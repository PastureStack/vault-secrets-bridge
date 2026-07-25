package broker

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestParseConfigReadsVaultTokenFile(t *testing.T) {
	t.Setenv("VAULT_TOKEN", "")
	t.Setenv("PASTURESTACK_VAULT_ISSUER_TOKEN", "")
	t.Setenv("PASTURESTACK_VAULT_ISSUER_TOKEN_FILE", "")

	tokenPath := filepath.Join(t.TempDir(), "issuer-token")
	if err := os.WriteFile(tokenPath, []byte("vault-token-value"), 0o400); err != nil {
		t.Fatal(err)
	}
	config, err := ParseConfig([]string{
		"--vault-url", "http://127.0.0.1:8200",
		"--vault-token-file", tokenPath,
		"--vault-role", "pasturestack",
		"--allowed-policies", "default,application",
		"--control-plane-url", "http://127.0.0.1:8080",
		"--access-key", "access-key",
		"--secret-key", "secret-key",
	}, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if config.VaultToken != "vault-token-value" || config.VaultTokenFile != tokenPath {
		t.Fatal("Vault issuing token file was not loaded")
	}
}

func TestParseConfigRejectsMultipleVaultTokenInputs(t *testing.T) {
	t.Setenv("VAULT_TOKEN", "")
	t.Setenv("PASTURESTACK_VAULT_ISSUER_TOKEN", "")
	t.Setenv("PASTURESTACK_VAULT_ISSUER_TOKEN_FILE", "")

	tokenPath := filepath.Join(t.TempDir(), "issuer-token")
	if err := os.WriteFile(tokenPath, []byte("vault-token-value"), 0o400); err != nil {
		t.Fatal(err)
	}
	_, err := ParseConfig([]string{
		"--vault-url", "http://127.0.0.1:8200",
		"--vault-token", "inline-token",
		"--vault-token-file", tokenPath,
		"--vault-role", "pasturestack",
		"--allowed-policies", "default",
		"--control-plane-url", "http://127.0.0.1:8080",
		"--access-key", "access-key",
		"--secret-key", "secret-key",
	}, &bytes.Buffer{})
	if err == nil {
		t.Fatal("multiple Vault issuing token inputs were accepted")
	}
}

func TestReadSecretFileRejectsUnsafeInput(t *testing.T) {
	root := t.TempDir()
	tokenPath := filepath.Join(root, "issuer-token")
	if err := os.WriteFile(tokenPath, []byte("token\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	value, err := readSecretFile(tokenPath, DefaultMaxVaultToken)
	if err != nil || value != "token\n" {
		t.Fatal("regular secret file was not read exactly")
	}
	if _, err := readSecretFile("issuer-token", DefaultMaxVaultToken); err == nil {
		t.Fatal("relative secret file path was accepted")
	}
	if _, err := readSecretFile(root, DefaultMaxVaultToken); err == nil {
		t.Fatal("secret directory was accepted as a file")
	}
	oversizedPath := filepath.Join(root, "oversized-token")
	if err := os.WriteFile(oversizedPath, bytes.Repeat([]byte{'x'}, int(DefaultMaxVaultToken)+1), 0o400); err != nil {
		t.Fatal(err)
	}
	if _, err := readSecretFile(oversizedPath, DefaultMaxVaultToken); err == nil {
		t.Fatal("oversized secret file was accepted")
	}
}
