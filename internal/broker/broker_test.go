package broker

import (
	"bytes"
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

type fakePlatform struct {
	key   *rsa.PublicKey
	hosts []string
	err   error
}

func (platform *fakePlatform) hostPublicKey(_ context.Context, hostUUID string) (*rsa.PublicKey, error) {
	platform.hosts = append(platform.hosts, hostUUID)
	return platform.key, platform.err
}

type fakeVault struct {
	mu       sync.Mutex
	token    []byte
	accessor string
	issued   [][]string
	revoked  []string
	renewed  int
	ready    bool
	err      error
}

func (vault *fakeVault) issue(_ context.Context, policies []string) ([]byte, string, error) {
	vault.mu.Lock()
	defer vault.mu.Unlock()
	vault.issued = append(vault.issued, append([]string(nil), policies...))
	return append([]byte(nil), vault.token...), vault.accessor, vault.err
}

func (vault *fakeVault) revoke(_ context.Context, accessor string) error {
	vault.mu.Lock()
	defer vault.mu.Unlock()
	vault.revoked = append(vault.revoked, accessor)
	return vault.err
}

func (vault *fakeVault) renew(context.Context) error {
	vault.mu.Lock()
	defer vault.mu.Unlock()
	vault.renewed++
	return vault.err
}

func (vault *fakeVault) healthy(context.Context) bool {
	return vault.ready
}

func (vault *fakeVault) close() {}

func TestServerIssuesEncryptedLeaseAndRevokesAfterUse(t *testing.T) {
	privateKey := testRSAKey(t)
	config := testBrokerConfig(t)
	state, err := loadStateStore(config.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	vault := &fakeVault{token: []byte("wrapped-token"), accessor: "accessor-1", ready: true}
	handler, err := newServer(config, &fakePlatform{key: &privateKey.PublicKey}, vault, state, nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 25, 8, 0, 0, 0, time.UTC)
	handler.now = func() time.Time { return now }

	issue := issueRequest{
		Version:    1,
		HostUUID:   "host-123",
		VolumeName: "vault-volume",
		Policies:   []string{"database", "default"},
		File:       "credentials/token",
		UID:        "1000",
		GID:        "1001",
		Mode:       "0400",
		Timestamp:  now.Format(time.RFC3339Nano),
		Nonce:      testNonce(1),
	}
	request := signedRequest(t, privateKey, "/v1/leases", issue)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("unexpected issue status: %d", response.Code)
	}
	var output issueResponse
	if decodeStrict(response.Body.Bytes(), &output) != nil || len(output.Records) != 1 {
		t.Fatal("issue response was invalid")
	}
	clearText := decryptTestRecord(t, privateKey, output.Records[0])
	if string(clearText) != "wrapped-token" ||
		output.Records[0].Name != "credentials/token" ||
		output.Records[0].UID != "1000" || output.Records[0].GID != "1001" ||
		output.Records[0].Mode != "0400" {
		t.Fatal("encrypted lease record contract was not preserved")
	}
	zeroBytes(clearText)
	if state.count() != 1 || len(vault.issued) != 1 {
		t.Fatal("issued lease state was not persisted")
	}

	replayResponse := httptest.NewRecorder()
	handler.ServeHTTP(replayResponse, signedRequest(t, privateKey, "/v1/leases", issue))
	if replayResponse.Code != http.StatusUnauthorized || len(vault.issued) != 1 {
		t.Fatal("signed request replay was not rejected")
	}

	revoke := revokeRequest{
		Version:    1,
		HostUUID:   "host-123",
		VolumeName: "vault-volume",
		Timestamp:  now.Format(time.RFC3339Nano),
		Nonce:      testNonce(2),
	}
	revokeResponse := httptest.NewRecorder()
	handler.ServeHTTP(revokeResponse, signedRequest(t, privateKey, "/v1/leases/revoke", revoke))
	if revokeResponse.Code != http.StatusNoContent ||
		len(vault.revoked) != 1 || vault.revoked[0] != "accessor-1" ||
		state.count() != 0 {
		t.Fatal("Vault lease was not revoked and removed")
	}
}

func TestServerReplacesExistingLeaseBeforeIssuingAnother(t *testing.T) {
	privateKey := testRSAKey(t)
	config := testBrokerConfig(t)
	state, _ := loadStateStore(config.StatePath)
	vault := &fakeVault{token: []byte("wrapped-token"), accessor: "accessor-new", ready: true}
	handler, _ := newServer(config, &fakePlatform{key: &privateKey.PublicKey}, vault, state, nil)
	now := time.Date(2026, 7, 25, 8, 0, 0, 0, time.UTC)
	handler.now = func() time.Time { return now }
	key := leaseStateKey("host-123", "vault-volume")
	if err := state.set(key, "accessor-old"); err != nil {
		t.Fatal(err)
	}
	input := issueRequest{
		Version: 1, HostUUID: "host-123", VolumeName: "vault-volume",
		Policies: []string{"default"}, File: "token", UID: "0", GID: "0", Mode: "0400",
		Timestamp: now.Format(time.RFC3339Nano), Nonce: testNonce(3),
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, signedRequest(t, privateKey, "/v1/leases", input))
	if response.Code != http.StatusOK || len(vault.revoked) != 1 ||
		vault.revoked[0] != "accessor-old" || len(vault.issued) != 1 ||
		state.accessor(key) != "accessor-new" {
		t.Fatal("existing lease was not replaced in the required order")
	}
}

func TestServerRejectsUnauthorizedPolicyAndInvalidSignature(t *testing.T) {
	privateKey := testRSAKey(t)
	otherKey := testRSAKey(t)
	config := testBrokerConfig(t)
	state, _ := loadStateStore(config.StatePath)
	vault := &fakeVault{token: []byte("wrapped-token"), accessor: "accessor", ready: true}
	platform := &fakePlatform{key: &privateKey.PublicKey}
	handler, _ := newServer(config, platform, vault, state, nil)
	now := time.Date(2026, 7, 25, 8, 0, 0, 0, time.UTC)
	handler.now = func() time.Time { return now }

	unauthorized := issueRequest{
		Version: 1, HostUUID: "host-123", VolumeName: "vault-volume",
		Policies: []string{"not-allowed"}, File: "token", UID: "0", GID: "0", Mode: "0400",
		Timestamp: now.Format(time.RFC3339Nano), Nonce: testNonce(4),
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, signedRequest(t, privateKey, "/v1/leases", unauthorized))
	if response.Code != http.StatusBadRequest || len(platform.hosts) != 0 || len(vault.issued) != 0 {
		t.Fatal("unauthorized policy reached a trusted dependency")
	}

	authorized := unauthorized
	authorized.Policies = []string{"default"}
	authorized.Nonce = testNonce(5)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, signedRequest(t, otherKey, "/v1/leases", authorized))
	if response.Code != http.StatusUnauthorized || len(vault.issued) != 0 {
		t.Fatal("invalid host signature was accepted")
	}
}

func TestPlatformClientRequiresOneActiveMatchingHost(t *testing.T) {
	privateKey := testRSAKey(t)
	publicPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(&privateKey.PublicKey),
	})
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		user, password, ok := request.BasicAuth()
		if !ok || user != "access" || password != "secret" ||
			request.URL.Path != "/v2-beta/hosts" || request.URL.Query().Get("uuid") != "host-123" {
			t.Error("platform request contract was not preserved")
		}
		_ = json.NewEncoder(response).Encode(map[string]any{"data": []any{
			map[string]any{
				"uuid": "host-123", "state": "active",
				"info": map[string]any{"hostKey": map[string]any{"data": string(publicPEM)}},
			},
		}})
	}))
	defer server.Close()
	config := testBrokerConfig(t)
	config.ControlPlaneURL = server.URL + "/v2-beta"
	client, err := newPlatformClient(config)
	if err != nil {
		t.Fatal(err)
	}
	key, err := client.hostPublicKey(context.Background(), "host-123")
	if err != nil || key.N.Cmp(privateKey.N) != 0 {
		t.Fatal("active host public key was not returned")
	}
}

func TestVaultClientUsesWrappedRoleTokenContract(t *testing.T) {
	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		paths = append(paths, request.URL.Path)
		if request.Header.Get("X-Vault-Token") != "issuer-token" {
			t.Error("Vault issuer token was not supplied")
		}
		switch request.URL.Path {
		case "/v1/auth/token/create/bridge-role":
			if request.Header.Get("X-Vault-Wrap-TTL") != "1m0s" {
				t.Error("Vault response wrapping was not requested")
			}
			_, _ = response.Write([]byte(`{"request_id":"id","wrap_info":{"token":"wrapped-token","accessor":"wrapping-accessor","wrapped_accessor":"child-accessor"}}`))
		case "/v1/auth/token/revoke-accessor":
			response.WriteHeader(http.StatusNoContent)
		case "/v1/auth/token/renew-self":
			_, _ = response.Write([]byte(`{"auth":{"renewable":true}}`))
		case "/v1/sys/health":
			_, _ = response.Write([]byte(`{"initialized":true,"sealed":false,"standby":false}`))
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()
	config := testBrokerConfig(t)
	config.VaultURL = server.URL
	client, err := newVaultClient(config)
	if err != nil {
		t.Fatal(err)
	}
	defer client.close()
	token, accessor, err := client.issue(context.Background(), []string{"default"})
	if err != nil || string(token) != "wrapped-token" || accessor != "child-accessor" {
		t.Fatal("Vault wrapped-token response was not accepted")
	}
	zeroBytes(token)
	if err := client.revoke(context.Background(), accessor); err != nil {
		t.Fatal(err)
	}
	if err := client.renew(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !client.healthy(context.Background()) || len(paths) != 4 {
		t.Fatal("Vault health or request lifecycle failed")
	}
}

func TestStateStorePersistsOnlyHashedKeysAndAccessors(t *testing.T) {
	config := testBrokerConfig(t)
	store, err := loadStateStore(config.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	key := leaseStateKey("host-123", "volume-123")
	if err := store.set(key, "accessor-123"); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(config.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(content, []byte("host-123")) || bytes.Contains(content, []byte("volume-123")) ||
		!bytes.Contains(content, []byte("accessor-123")) {
		t.Fatal("lease state exposed identifiers or lost the accessor")
	}
	info, _ := os.Stat(config.StatePath)
	if info.Mode().Perm() != 0o600 {
		t.Fatal("lease state file permissions are unsafe")
	}
	reloaded, err := loadStateStore(config.StatePath)
	if err != nil || reloaded.accessor(key) != "accessor-123" {
		t.Fatal("lease state did not survive reload")
	}
}

func testBrokerConfig(t *testing.T) Config {
	t.Helper()
	return Config{
		Listen:             "127.0.0.1:0",
		VaultURL:           "http://127.0.0.1:8200",
		VaultToken:         "issuer-token",
		VaultRole:          "bridge-role",
		AllowedPolicies:    map[string]struct{}{"database": {}, "default": {}},
		TokenTTL:           5 * time.Minute,
		WrapTTL:            time.Minute,
		RenewInterval:      5 * time.Minute,
		ControlPlaneURL:    "http://127.0.0.1:8080/v2-beta",
		AccessKey:          "access",
		SecretKey:          "secret",
		StatePath:          filepath.Join(t.TempDir(), "leases.json"),
		RequestTimeout:     2 * time.Second,
		MaxRequestBytes:    DefaultMaxRequestBytes,
		MaxResponseBytes:   DefaultMaxResponse,
		NonceTTL:           5 * time.Minute,
		MaxRememberedNonce: 1000,
	}
}

func testRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func testNonce(value byte) string {
	return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{value}, 24))
}

func signedRequest(t *testing.T, privateKey *rsa.PrivateKey, target string, value any) *http.Request {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(body)
	signature, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, digest[:], &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       crypto.SHA256,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, target, bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(signatureHeader, base64.StdEncoding.EncodeToString(signature))
	return request
}

func decryptTestRecord(t *testing.T, privateKey *rsa.PrivateKey, record encryptedRecord) []byte {
	t.Helper()
	rawEnvelope, err := base64.StdEncoding.Strict().DecodeString(record.RewrapText)
	if err != nil {
		t.Fatal(err)
	}
	var envelope encryptedEnvelope
	if decodeStrict(rawEnvelope, &envelope) != nil {
		t.Fatal("encrypted envelope was invalid")
	}
	encryptedKey, _ := base64.StdEncoding.Strict().DecodeString(envelope.EncryptedKey.EncryptedText)
	dataKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, encryptedKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer zeroBytes(dataKey)
	signature, _ := base64.StdEncoding.Strict().DecodeString(envelope.Signature)
	mac := hmac.New(sha256.New, dataKey)
	_, _ = mac.Write(signature[:12])
	_, _ = mac.Write([]byte(":"))
	_, _ = mac.Write([]byte(envelope.EncryptedText))
	if len(signature) != 45 || signature[12] != ':' || !hmac.Equal(signature[13:], mac.Sum(nil)) {
		t.Fatal("encrypted envelope signature was invalid")
	}
	var payload aesEnvelope
	if decodeStrict([]byte(envelope.EncryptedText), &payload) != nil {
		t.Fatal("encrypted payload was invalid")
	}
	block, _ := aes.NewCipher(dataKey)
	gcm, _ := cipher.NewGCM(block)
	encoded, err := gcm.Open(nil, payload.Nonce, payload.CipherText, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer zeroBytes(encoded)
	clearText := make([]byte, base64.StdEncoding.DecodedLen(len(encoded)))
	length, err := base64.StdEncoding.Strict().Decode(clearText, encoded)
	if err != nil {
		t.Fatal(err)
	}
	return clearText[:length]
}
