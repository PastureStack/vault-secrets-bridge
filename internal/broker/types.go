package broker

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"
)

type issueRequest struct {
	Version    int      `json:"version"`
	HostUUID   string   `json:"hostUuid"`
	VolumeName string   `json:"volumeName"`
	Policies   []string `json:"policies"`
	File       string   `json:"file"`
	UID        string   `json:"uid"`
	GID        string   `json:"gid"`
	Mode       string   `json:"mode"`
	Timestamp  string   `json:"timestamp"`
	Nonce      string   `json:"nonce"`
}

type revokeRequest struct {
	Version    int    `json:"version"`
	HostUUID   string `json:"hostUuid"`
	VolumeName string `json:"volumeName"`
	Timestamp  string `json:"timestamp"`
	Nonce      string `json:"nonce"`
}

type encryptedRecord struct {
	Name       string `json:"name"`
	UID        string `json:"uid"`
	GID        string `json:"gid"`
	Mode       string `json:"mode"`
	RewrapText string `json:"rewrapText"`
}

type issueResponse struct {
	Records []encryptedRecord `json:"records"`
}

type encryptedEnvelope struct {
	EncryptionAlgorithm string      `json:"encryptionAlgorithm"`
	EncryptedText       string      `json:"encryptedText"`
	HashAlgorithm       string      `json:"hashAlgorithm"`
	EncryptedKey        rsaEnvelope `json:"encryptedKey"`
	Signature           string      `json:"signature"`
}

type rsaEnvelope struct {
	EncryptionAlgorithm string `json:"encryptionAlgorithm"`
	EncryptedText       string `json:"encryptedText"`
	HashAlgorithm       string `json:"hashAlgorithm"`
}

type aesEnvelope struct {
	Nonce      []byte
	Algorithm  string
	CipherText []byte
}

func decodeStrict(data []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("multiple JSON documents are not allowed")
	}
	return nil
}

func (request issueRequest) validate(config Config, now time.Time) error {
	if request.Version != 1 || !validName(request.HostUUID, 128) ||
		!validName(request.VolumeName, 128) || !validRelativePath(request.File) ||
		!validOwnership(request.UID) || !validOwnership(request.GID) ||
		!validReadOnlyMode(request.Mode) {
		return errors.New("Vault lease request is invalid")
	}
	if err := validateFreshness(request.Timestamp, request.Nonce, config.NonceTTL, now); err != nil {
		return err
	}
	if len(request.Policies) == 0 || len(request.Policies) > 16 ||
		!sort.StringsAreSorted(request.Policies) {
		return errors.New("Vault policy request is invalid")
	}
	previous := ""
	for _, policy := range request.Policies {
		if !validName(policy, 64) || policy == previous {
			return errors.New("Vault policy request is invalid")
		}
		if _, allowed := config.AllowedPolicies[policy]; !allowed {
			return errors.New("Vault policy request is unauthorized")
		}
		previous = policy
	}
	return nil
}

func (request revokeRequest) validate(config Config, now time.Time) error {
	if request.Version != 1 || !validName(request.HostUUID, 128) ||
		!validName(request.VolumeName, 128) {
		return errors.New("Vault revoke request is invalid")
	}
	return validateFreshness(request.Timestamp, request.Nonce, config.NonceTTL, now)
}

func validateFreshness(timestamp, nonce string, window time.Duration, now time.Time) error {
	parsed, err := time.Parse(time.RFC3339Nano, timestamp)
	if err != nil {
		return errors.New("signed request timestamp is invalid")
	}
	delta := now.Sub(parsed)
	if delta < -window || delta > window {
		return errors.New("signed request timestamp is stale")
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(nonce)
	if err != nil || len(decoded) != 24 {
		return errors.New("signed request nonce is invalid")
	}
	return nil
}

func validRelativePath(value string) bool {
	if value == "" || len(value) > 240 || strings.Contains(value, "\\") ||
		path.IsAbs(value) || path.Clean(value) != value {
		return false
	}
	parts := strings.Split(value, "/")
	if len(parts) > 16 {
		return false
	}
	for _, part := range parts {
		if !validName(part, 64) || part == "." || part == ".." {
			return false
		}
	}
	return true
}

func validOwnership(value string) bool {
	if value == "" {
		return false
	}
	parsed, err := strconv.ParseInt(value, 10, 32)
	return err == nil && parsed >= 0
}

func validReadOnlyMode(value string) bool {
	return value == "0400" || value == "0440" || value == "0444"
}

func leaseStateKey(hostUUID, volumeName string) string {
	digest := sha256.Sum256([]byte(hostUUID + "\x00" + volumeName))
	return hex.EncodeToString(digest[:])
}
