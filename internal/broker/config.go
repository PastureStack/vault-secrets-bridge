package broker

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	DefaultListen          = "0.0.0.0:8080"
	DefaultStatePath       = "/var/lib/pasturestack/vault-secrets-bridge/leases.json"
	DefaultMaxRequestBytes = int64(64 << 10)
	DefaultMaxResponse     = int64(2 << 20)
	DefaultMaxVaultToken   = int64(64 << 10)
)

type Config struct {
	Listen             string
	VaultURL           string
	VaultToken         string
	VaultTokenFile     string
	VaultRole          string
	AllowedPolicies    map[string]struct{}
	TokenTTL           time.Duration
	WrapTTL            time.Duration
	RenewInterval      time.Duration
	ControlPlaneURL    string
	AccessKey          string
	SecretKey          string
	StatePath          string
	RequestTimeout     time.Duration
	MaxRequestBytes    int64
	MaxResponseBytes   int64
	NonceTTL           time.Duration
	MaxRememberedNonce int
}

func ParseConfig(args []string, stderr io.Writer) (Config, error) {
	flags := flag.NewFlagSet("vault-secrets-bridge serve", flag.ContinueOnError)
	flags.SetOutput(stderr)
	config := Config{}
	var allowedPolicies string
	flags.StringVar(&config.Listen, "listen", envOr("PASTURESTACK_VAULT_BRIDGE_LISTEN", DefaultListen), "HTTP listen address")
	flags.StringVar(&config.VaultURL, "vault-url", firstEnv("VAULT_ADDR", "PASTURESTACK_VAULT_URL"), "Vault API URL")
	flags.StringVar(&config.VaultToken, "vault-token", firstEnv("VAULT_TOKEN", "PASTURESTACK_VAULT_ISSUER_TOKEN"), "Vault issuing token")
	flags.StringVar(&config.VaultTokenFile, "vault-token-file", envOr("PASTURESTACK_VAULT_ISSUER_TOKEN_FILE", ""), "file containing the Vault issuing token")
	flags.StringVar(&config.VaultRole, "vault-role", firstEnv("VAULT_ROLE", "PASTURESTACK_VAULT_ROLE"), "Vault token role")
	flags.StringVar(&allowedPolicies, "allowed-policies", envOr("PASTURESTACK_VAULT_ALLOWED_POLICIES", ""), "comma-separated Vault policy allowlist")
	flags.DurationVar(&config.TokenTTL, "token-ttl", durationEnv("PASTURESTACK_VAULT_TOKEN_TTL", 5*time.Minute), "issued child-token TTL")
	flags.DurationVar(&config.WrapTTL, "wrap-ttl", durationEnv("PASTURESTACK_VAULT_WRAP_TTL", time.Minute), "response-wrapping TTL")
	flags.DurationVar(&config.RenewInterval, "renew-interval", durationEnv("PASTURESTACK_VAULT_RENEW_INTERVAL", 5*time.Minute), "issuer-token renewal interval")
	flags.StringVar(&config.ControlPlaneURL, "control-plane-url", firstEnv(
		compatibilityControlPlaneURL(), "PASTURESTACK_CONTROL_PLANE_URL",
	), "compatible control-plane API URL")
	flags.StringVar(&config.AccessKey, "access-key", firstEnv(
		compatibilityEnvironmentAccessKey(), "PASTURESTACK_ACCESS_KEY", compatibilityAccessKey(),
	), "compatible control-plane access key")
	flags.StringVar(&config.SecretKey, "secret-key", firstEnv(
		compatibilityEnvironmentSecretKey(), "PASTURESTACK_SECRET_KEY", compatibilitySecretKey(),
	), "compatible control-plane secret key")
	flags.StringVar(&config.StatePath, "state-path", envOr("PASTURESTACK_VAULT_STATE_PATH", DefaultStatePath), "lease-accessor state file")
	flags.DurationVar(&config.RequestTimeout, "request-timeout", durationEnv("PASTURESTACK_VAULT_REQUEST_TIMEOUT", 10*time.Second), "upstream request timeout")
	flags.Int64Var(&config.MaxRequestBytes, "max-request-bytes", DefaultMaxRequestBytes, "maximum signed request body")
	flags.Int64Var(&config.MaxResponseBytes, "max-response-bytes", DefaultMaxResponse, "maximum upstream response body")
	flags.DurationVar(&config.NonceTTL, "nonce-ttl", 5*time.Minute, "signed-request replay window")
	flags.IntVar(&config.MaxRememberedNonce, "max-remembered-nonces", 10000, "maximum replay-cache entries")
	if err := flags.Parse(args); err != nil {
		return Config{}, err
	}
	if flags.NArg() != 0 {
		return Config{}, errors.New("unexpected positional arguments")
	}
	if config.VaultToken != "" && config.VaultTokenFile != "" {
		return Config{}, errors.New("Vault issuing token must use exactly one input")
	}
	if config.VaultTokenFile != "" {
		token, err := readSecretFile(config.VaultTokenFile, DefaultMaxVaultToken)
		if err != nil {
			return Config{}, errors.New("unable to read Vault issuing token file")
		}
		config.VaultToken = token
	}
	policies, err := parsePolicyAllowlist(allowedPolicies)
	if err != nil {
		return Config{}, err
	}
	config.AllowedPolicies = policies
	if err := config.Validate(); err != nil {
		return Config{}, err
	}
	return config, nil
}

func readSecretFile(path string, maximum int64) (string, error) {
	if maximum < 1 || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", errors.New("secret file path is invalid")
	}
	pathInfo, err := os.Lstat(path)
	if err != nil || !pathInfo.Mode().IsRegular() {
		return "", errors.New("secret file is invalid")
	}
	file, err := os.Open(path)
	if err != nil {
		return "", errors.New("secret file is unavailable")
	}
	defer file.Close()
	fileInfo, err := file.Stat()
	if err != nil || !fileInfo.Mode().IsRegular() {
		return "", errors.New("secret file is invalid")
	}
	value, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(value)) > maximum {
		return "", errors.New("secret file exceeds its limit")
	}
	return string(value), nil
}

func (config Config) Validate() error {
	if _, _, err := net.SplitHostPort(config.Listen); err != nil {
		return errors.New("invalid listen address")
	}
	if _, err := validateServiceURL(config.VaultURL); err != nil {
		return fmt.Errorf("invalid Vault URL: %w", err)
	}
	if _, err := validateServiceURL(config.ControlPlaneURL); err != nil {
		return fmt.Errorf("invalid compatible control-plane URL: %w", err)
	}
	if !validOpaqueSecret(config.VaultToken, 64<<10) {
		return errors.New("Vault issuing token is invalid")
	}
	if !validName(config.VaultRole, 128) {
		return errors.New("Vault role is invalid")
	}
	if len(config.AllowedPolicies) == 0 || len(config.AllowedPolicies) > 64 {
		return errors.New("Vault policy allowlist is invalid")
	}
	if !validOpaqueSecret(config.AccessKey, 4<<10) || !validOpaqueSecret(config.SecretKey, 4<<10) {
		return errors.New("compatible control-plane credentials are invalid")
	}
	if !filepath.IsAbs(config.StatePath) || filepath.Clean(config.StatePath) != config.StatePath {
		return errors.New("state path must be clean and absolute")
	}
	stateRoot := filepath.Clean("/var/lib/pasturestack")
	relative, err := filepath.Rel(stateRoot, config.StatePath)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return errors.New("state path is outside its required root")
	}
	if config.TokenTTL < time.Minute || config.TokenTTL > time.Hour ||
		config.WrapTTL < 30*time.Second || config.WrapTTL > 5*time.Minute ||
		config.WrapTTL > config.TokenTTL ||
		config.RenewInterval < time.Minute || config.RenewInterval > 30*time.Minute ||
		config.RequestTimeout < time.Second || config.RequestTimeout > time.Minute ||
		config.NonceTTL < time.Minute || config.NonceTTL > 10*time.Minute ||
		config.MaxRequestBytes < 1024 || config.MaxRequestBytes > 1<<20 ||
		config.MaxResponseBytes < 1024 || config.MaxResponseBytes > 8<<20 ||
		config.MaxRememberedNonce < 100 || config.MaxRememberedNonce > 100000 {
		return errors.New("runtime safety limit is invalid")
	}
	return nil
}

func parsePolicyAllowlist(raw string) (map[string]struct{}, error) {
	result := make(map[string]struct{})
	for _, item := range strings.Split(raw, ",") {
		policy := strings.TrimSpace(item)
		if policy == "" {
			continue
		}
		if !validName(policy, 64) {
			return nil, errors.New("Vault policy allowlist is invalid")
		}
		result[policy] = struct{}{}
	}
	if len(result) == 0 {
		return nil, errors.New("Vault policy allowlist is required")
	}
	return result, nil
}

func validateServiceURL(raw string) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("URL is invalid")
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return nil, errors.New("URL scheme is unsupported")
	}
	if parsed.Scheme == "http" && !privateHost(parsed.Hostname()) {
		return nil, errors.New("unencrypted URL must use a private address")
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/")
	return parsed, nil
}

func privateHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	if ip != nil {
		return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()
	}
	return validInternalHostname(host)
}

func validInternalHostname(host string) bool {
	if host == "" || len(host) > 63 || strings.Contains(host, ".") ||
		host[0] == '-' || host[len(host)-1] == '-' {
		return false
	}
	for _, character := range host {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '-' {
			continue
		}
		return false
	}
	return true
}

func validName(value string, maximum int) bool {
	if value == "" || value == "." || value == ".." || len(value) > maximum {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '.' || character == '_' || character == '-' {
			continue
		}
		return false
	}
	return true
}

func validOpaqueSecret(value string, maximum int) bool {
	if value == "" || len(value) > maximum {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func firstEnv(names ...string) string {
	for _, name := range names {
		if value := os.Getenv(name); value != "" {
			return value
		}
	}
	return ""
}

func durationEnv(name string, fallback time.Duration) time.Duration {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return 0
	}
	return parsed
}

func compatibilityControlPlaneURL() string {
	return strings.Join([]string{"CATTLE_", "URL"}, "")
}

func compatibilityAccessKey() string {
	return strings.Join([]string{"CATTLE_", "ACCESS_KEY"}, "")
}

func compatibilityEnvironmentAccessKey() string {
	return strings.Join([]string{"CATTLE_", "ENVIRONMENT_", "ACCESS_KEY"}, "")
}

func compatibilitySecretKey() string {
	return strings.Join([]string{"CATTLE_", "SECRET_KEY"}, "")
}

func compatibilityEnvironmentSecretKey() string {
	return strings.Join([]string{"CATTLE_", "ENVIRONMENT_", "SECRET_KEY"}, "")
}
