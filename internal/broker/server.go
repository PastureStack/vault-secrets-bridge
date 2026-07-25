package broker

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const signatureHeader = "X-PastureStack-Host-Signature"

type hostKeyProvider interface {
	hostPublicKey(context.Context, string) (*rsa.PublicKey, error)
}

type server struct {
	config   Config
	platform hostKeyProvider
	vault    vaultAPI
	state    *stateStore
	nonces   *nonceCache
	logger   *log.Logger
	now      func() time.Time

	operationMu sync.Mutex
	issuerReady atomic.Bool
}

func newServer(config Config, platform hostKeyProvider, vault vaultAPI, state *stateStore, logger *log.Logger) (*server, error) {
	if platform == nil || vault == nil || state == nil {
		return nil, errors.New("Vault bridge dependencies are incomplete")
	}
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}
	result := &server{
		config:   config,
		platform: platform,
		vault:    vault,
		state:    state,
		nonces:   newNonceCache(config.NonceTTL, config.MaxRememberedNonce),
		logger:   logger,
		now: func() time.Time {
			current := time.Now()
			return current.UTC()
		},
	}
	result.issuerReady.Store(true)
	return result, nil
}

func (server *server) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	switch request.URL.Path {
	case "/healthz":
		server.handleHealth(response, request)
	case "/readyz":
		server.handleReady(response, request)
	case "/v1/leases":
		server.handleIssue(response, request)
	case "/v1/leases/revoke":
		server.handleRevoke(response, request)
	default:
		writeError(response, http.StatusNotFound)
	}
}

func (server *server) handleHealth(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		writeError(response, http.StatusMethodNotAllowed)
		return
	}
	writeJSON(response, http.StatusOK, map[string]any{"status": "healthy"})
}

func (server *server) handleReady(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		writeError(response, http.StatusMethodNotAllowed)
		return
	}
	ready := server.issuerReady.Load()
	if ready {
		ctx, cancel := context.WithTimeout(request.Context(), server.config.RequestTimeout)
		ready = server.vault.healthy(ctx)
		cancel()
	}
	status := http.StatusOK
	state := "ready"
	if !ready {
		status = http.StatusServiceUnavailable
		state = "not-ready"
	}
	writeJSON(response, status, map[string]any{
		"status": state, "lease_count": server.state.count(),
	})
}

func (server *server) handleIssue(response http.ResponseWriter, request *http.Request) {
	if !server.validRequestEnvelope(response, request) {
		return
	}
	body, ok := server.readRequest(response, request)
	if !ok {
		return
	}
	var input issueRequest
	if decodeStrict(body, &input) != nil || input.validate(server.config, server.now()) != nil {
		writeError(response, http.StatusBadRequest)
		return
	}
	publicKey, valid := server.verifyHostRequest(request.Context(), request, body, input.HostUUID, input.Nonce)
	if !valid {
		writeError(response, http.StatusUnauthorized)
		return
	}

	server.operationMu.Lock()
	defer server.operationMu.Unlock()
	key := leaseStateKey(input.HostUUID, input.VolumeName)
	if previous := server.state.accessor(key); previous != "" {
		if err := server.vault.revoke(request.Context(), previous); err != nil {
			writeError(response, http.StatusBadGateway)
			return
		}
	}
	token, accessor, err := server.vault.issue(request.Context(), input.Policies)
	if err != nil {
		writeError(response, http.StatusBadGateway)
		return
	}
	defer zeroBytes(token)
	record, err := encryptLeaseRecord(publicKey, input, token)
	if err != nil {
		_ = server.vault.revoke(context.Background(), accessor)
		writeError(response, http.StatusInternalServerError)
		return
	}
	if err := server.state.set(key, accessor); err != nil {
		_ = server.vault.revoke(context.Background(), accessor)
		writeError(response, http.StatusInternalServerError)
		return
	}
	writeJSON(response, http.StatusOK, issueResponse{Records: []encryptedRecord{record}})
}

func (server *server) handleRevoke(response http.ResponseWriter, request *http.Request) {
	if !server.validRequestEnvelope(response, request) {
		return
	}
	body, ok := server.readRequest(response, request)
	if !ok {
		return
	}
	var input revokeRequest
	if decodeStrict(body, &input) != nil || input.validate(server.config, server.now()) != nil {
		writeError(response, http.StatusBadRequest)
		return
	}
	if _, valid := server.verifyHostRequest(request.Context(), request, body, input.HostUUID, input.Nonce); !valid {
		writeError(response, http.StatusUnauthorized)
		return
	}

	server.operationMu.Lock()
	defer server.operationMu.Unlock()
	key := leaseStateKey(input.HostUUID, input.VolumeName)
	accessor := server.state.accessor(key)
	if accessor == "" {
		response.WriteHeader(http.StatusNoContent)
		return
	}
	if err := server.vault.revoke(request.Context(), accessor); err != nil {
		writeError(response, http.StatusBadGateway)
		return
	}
	if err := server.state.remove(key); err != nil {
		writeError(response, http.StatusInternalServerError)
		return
	}
	response.WriteHeader(http.StatusNoContent)
}

func (server *server) validRequestEnvelope(response http.ResponseWriter, request *http.Request) bool {
	if request.Method != http.MethodPost {
		writeError(response, http.StatusMethodNotAllowed)
		return false
	}
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" || request.URL.RawQuery != "" ||
		len(request.Header.Values(signatureHeader)) != 1 {
		writeError(response, http.StatusBadRequest)
		return false
	}
	return true
}

func (server *server) readRequest(response http.ResponseWriter, request *http.Request) ([]byte, bool) {
	reader := http.MaxBytesReader(response, request.Body, server.config.MaxRequestBytes)
	defer reader.Close()
	body, err := io.ReadAll(reader)
	if err != nil || len(body) == 0 {
		writeError(response, http.StatusBadRequest)
		return nil, false
	}
	return body, true
}

func (server *server) verifyHostRequest(ctx context.Context, request *http.Request, body []byte, hostUUID, nonce string) (*rsa.PublicKey, bool) {
	publicKey, err := server.platform.hostPublicKey(ctx, hostUUID)
	if err != nil {
		return nil, false
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(request.Header.Get(signatureHeader))
	if err != nil || len(signature) != publicKey.Size() {
		return nil, false
	}
	digest := sha256.Sum256(body)
	if rsa.VerifyPSS(publicKey, crypto.SHA256, digest[:], signature, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       crypto.SHA256,
	}) != nil {
		return nil, false
	}
	if !server.nonces.use(hostUUID, nonce, server.now()) {
		return nil, false
	}
	return publicKey, true
}

func (server *server) renewalLoop(ctx context.Context) {
	ticker := time.NewTicker(server.config.RenewInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			renewContext, cancel := context.WithTimeout(ctx, server.config.RequestTimeout)
			err := server.vault.renew(renewContext)
			cancel()
			server.issuerReady.Store(err == nil)
			if err != nil {
				server.logger.Print("Vault issuer renewal failed")
			}
		}
	}
}

func writeJSON(response http.ResponseWriter, status int, value any) {
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("Cache-Control", "no-store")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}

func writeError(response http.ResponseWriter, status int) {
	writeJSON(response, status, map[string]string{"error": "request rejected"})
}

func RunServe(args []string, stdout, stderr io.Writer, version string) int {
	config, err := ParseConfig(args, stderr)
	if err != nil {
		fmt.Fprintln(stderr, "invalid runtime configuration")
		return 2
	}
	platform, err := newPlatformClient(config)
	if err != nil {
		fmt.Fprintln(stderr, "invalid compatible control-plane configuration")
		return 1
	}
	vault, err := newVaultClient(config)
	if err != nil {
		fmt.Fprintln(stderr, "invalid Vault configuration")
		return 1
	}
	defer vault.close()
	config.VaultToken = ""
	state, err := loadStateStore(config.StatePath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	logger := log.New(stderr, "vault-secrets-bridge: ", log.LstdFlags|log.LUTC)
	handler, err := newServer(config, platform, vault, state, logger)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	initialContext, initialCancel := context.WithTimeout(context.Background(), config.RequestTimeout)
	healthy := vault.healthy(initialContext)
	renewError := vault.renew(initialContext)
	initialCancel()
	if !healthy || renewError != nil {
		fmt.Fprintln(stderr, "Vault issuer is not ready")
		return 1
	}

	listener, err := net.Listen("tcp", config.Listen)
	if err != nil {
		fmt.Fprintln(stderr, "unable to start Vault bridge listener")
		return 1
	}
	defer listener.Close()
	httpServer := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 3 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    8 << 10,
	}
	runContext, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go handler.renewalLoop(runContext)
	errorsChannel := make(chan error, 1)
	go func() { errorsChannel <- httpServer.Serve(listener) }()
	logger.Printf("ready version=%s", version)
	select {
	case serveError := <-errorsChannel:
		if serveError != nil && serveError != http.ErrServerClosed {
			fmt.Fprintln(stderr, "Vault bridge stopped unexpectedly")
			return 1
		}
	case <-runContext.Done():
	}
	shutdownContext, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	_ = httpServer.Shutdown(shutdownContext)
	fmt.Fprintln(stdout, "Vault bridge stopped")
	return 0
}
