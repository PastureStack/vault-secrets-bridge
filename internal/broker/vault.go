package broker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
)

type vaultAPI interface {
	issue(context.Context, []string) ([]byte, string, error)
	revoke(context.Context, string) error
	renew(context.Context) error
	healthy(context.Context) bool
	close()
}

type vaultClient struct {
	baseURL          *url.URL
	token            []byte
	role             string
	tokenTTL         string
	wrapTTL          string
	maxResponseBytes int64
	client           *http.Client
}

type vaultTokenCreateRequest struct {
	Policies  []string `json:"policies"`
	TTL       string   `json:"ttl"`
	Renewable bool     `json:"renewable"`
}

type vaultWrapInfo struct {
	Token           string `json:"token"`
	Accessor        string `json:"accessor"`
	WrappedAccessor string `json:"wrapped_accessor"`
}

type vaultIssueResponse struct {
	WrapInfo vaultWrapInfo `json:"wrap_info"`
}

type vaultHealthResponse struct {
	Initialized bool `json:"initialized"`
	Sealed      bool `json:"sealed"`
}

func newVaultClient(config Config) (*vaultClient, error) {
	baseURL, err := validateServiceURL(config.VaultURL)
	if err != nil {
		return nil, err
	}
	return &vaultClient{
		baseURL:          baseURL,
		token:            append([]byte(nil), config.VaultToken...),
		role:             config.VaultRole,
		tokenTTL:         config.TokenTTL.String(),
		wrapTTL:          config.WrapTTL.String(),
		maxResponseBytes: config.MaxResponseBytes,
		client:           secureHTTPClient(config.RequestTimeout, baseURL.Scheme == "http"),
	}, nil
}

func (client *vaultClient) issue(ctx context.Context, policies []string) ([]byte, string, error) {
	body, err := json.Marshal(vaultTokenCreateRequest{
		Policies:  append([]string(nil), policies...),
		TTL:       client.tokenTTL,
		Renewable: true,
	})
	if err != nil {
		return nil, "", errors.New("unable to encode Vault token request")
	}
	endpoint := client.endpoint("/v1/auth/token/create/" + url.PathEscape(client.role))
	responseBody, status, err := client.do(ctx, http.MethodPost, endpoint, body, client.wrapTTL)
	if err != nil {
		return nil, "", err
	}
	if status != http.StatusOK {
		return nil, "", errors.New("Vault token request was rejected")
	}
	var response vaultIssueResponse
	if json.Unmarshal(responseBody, &response) != nil ||
		!validOpaqueSecret(response.WrapInfo.Token, 64<<10) ||
		!validOpaqueSecret(response.WrapInfo.WrappedAccessor, 4096) {
		return nil, "", errors.New("Vault token response is invalid")
	}
	return []byte(response.WrapInfo.Token), response.WrapInfo.WrappedAccessor, nil
}

func (client *vaultClient) revoke(ctx context.Context, accessor string) error {
	if !validOpaqueSecret(accessor, 4096) {
		return errors.New("Vault lease accessor is invalid")
	}
	body, err := json.Marshal(map[string]string{"accessor": accessor})
	if err != nil {
		return errors.New("unable to encode Vault revoke request")
	}
	responseBody, status, err := client.do(ctx, http.MethodPost, client.endpoint("/v1/auth/token/revoke-accessor"), body, "")
	if err != nil {
		return err
	}
	if status == http.StatusOK || status == http.StatusNoContent {
		return nil
	}
	if status == http.StatusBadRequest {
		lower := bytes.ToLower(responseBody)
		if bytes.Contains(lower, []byte("invalid accessor")) || bytes.Contains(lower, []byte("lease not found")) {
			return nil
		}
	}
	return errors.New("Vault revoke request was rejected")
}

func (client *vaultClient) renew(ctx context.Context) error {
	responseBody, status, err := client.do(ctx, http.MethodPost, client.endpoint("/v1/auth/token/renew-self"), []byte(`{}`), "")
	if err != nil {
		return err
	}
	if status != http.StatusOK || len(responseBody) == 0 {
		return errors.New("Vault issuer renewal was rejected")
	}
	return nil
}

func (client *vaultClient) healthy(ctx context.Context) bool {
	endpoint := client.endpoint("/v1/sys/health")
	query := endpoint.Query()
	query.Set("standbyok", "true")
	query.Set("perfstandbyok", "true")
	endpoint.RawQuery = query.Encode()
	responseBody, status, err := client.do(ctx, http.MethodGet, endpoint, nil, "")
	if err != nil {
		return false
	}
	switch status {
	case http.StatusOK, 429, 472, 473:
	default:
		return false
	}
	var response vaultHealthResponse
	return json.Unmarshal(responseBody, &response) == nil && response.Initialized && !response.Sealed
}

func (client *vaultClient) close() {
	zeroBytes(client.token)
	client.token = nil
	client.client.CloseIdleConnections()
}

func (client *vaultClient) endpoint(suffix string) *url.URL {
	result := *client.baseURL
	result.Path = strings.TrimRight(result.Path, "/") + suffix
	result.RawPath = ""
	return &result
}

func (client *vaultClient) do(ctx context.Context, method string, endpoint *url.URL, body []byte, wrapTTL string) ([]byte, int, error) {
	request, err := http.NewRequestWithContext(ctx, method, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return nil, 0, errors.New("unable to create Vault API request")
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("X-Vault-Token", string(client.token))
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if wrapTTL != "" {
		request.Header.Set("X-Vault-Wrap-TTL", wrapTTL)
	}
	response, err := client.client.Do(request)
	if err != nil {
		return nil, 0, errors.New("Vault API request failed")
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, client.maxResponseBytes+1))
	if err != nil || int64(len(responseBody)) > client.maxResponseBytes {
		return nil, 0, errors.New("Vault API response exceeds its limit")
	}
	return responseBody, response.StatusCode, nil
}
