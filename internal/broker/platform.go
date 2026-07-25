package broker

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type platformClient struct {
	endpoint         *url.URL
	accessKey        string
	secretKey        string
	maxResponseBytes int64
	client           *http.Client
}

type platformHostCollection struct {
	Data []struct {
		UUID  string `json:"uuid"`
		State string `json:"state"`
		Info  struct {
			HostKey struct {
				Data string `json:"data"`
			} `json:"hostKey"`
		} `json:"info"`
	} `json:"data"`
}

func newPlatformClient(config Config) (*platformClient, error) {
	base, err := validateServiceURL(config.ControlPlaneURL)
	if err != nil {
		return nil, err
	}
	endpoint := *base
	endpoint.Path = strings.TrimRight(endpoint.Path, "/") + "/hosts"
	return &platformClient{
		endpoint:         &endpoint,
		accessKey:        config.AccessKey,
		secretKey:        config.SecretKey,
		maxResponseBytes: config.MaxResponseBytes,
		client:           secureHTTPClient(config.RequestTimeout, endpoint.Scheme == "http"),
	}, nil
}

func (client *platformClient) hostPublicKey(ctx context.Context, hostUUID string) (*rsa.PublicKey, error) {
	if !validName(hostUUID, 128) {
		return nil, errors.New("host identity is invalid")
	}
	endpoint := *client.endpoint
	query := endpoint.Query()
	query.Set("uuid", hostUUID)
	endpoint.RawQuery = query.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, errors.New("unable to create host identity request")
	}
	request.Header.Set("Accept", "application/json")
	request.SetBasicAuth(client.accessKey, client.secretKey)
	response, err := client.client.Do(request)
	if err != nil {
		return nil, errors.New("host identity request failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return nil, errors.New("host identity request was rejected")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, client.maxResponseBytes+1))
	if err != nil || int64(len(body)) > client.maxResponseBytes {
		return nil, errors.New("host identity response exceeds its limit")
	}
	var collection platformHostCollection
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(&collection); err != nil {
		return nil, errors.New("host identity response is invalid")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, errors.New("host identity response is invalid")
	}
	if len(collection.Data) != 1 || collection.Data[0].UUID != hostUUID ||
		collection.Data[0].State != "active" {
		return nil, errors.New("host identity response is ambiguous")
	}
	return parseHostPublicKey([]byte(collection.Data[0].Info.HostKey.Data))
}

func parseHostPublicKey(content []byte) (*rsa.PublicKey, error) {
	block, remainder := pem.Decode(content)
	if block == nil || len(bytes.TrimSpace(remainder)) != 0 {
		return nil, errors.New("host public key is invalid")
	}
	var key *rsa.PublicKey
	if parsed, err := x509.ParsePKCS1PublicKey(block.Bytes); err == nil {
		key = parsed
	} else if parsed, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
		key, _ = parsed.(*rsa.PublicKey)
	} else if certificate, err := x509.ParseCertificate(block.Bytes); err == nil {
		key, _ = certificate.PublicKey.(*rsa.PublicKey)
	}
	if key == nil || key.N.BitLen() < 2048 || key.N.BitLen() > 8192 {
		return nil, errors.New("host public key is invalid")
	}
	return key, nil
}

func secureHTTPClient(timeout time.Duration, privateOnly bool) *http.Client {
	dialer := &net.Dialer{
		Timeout:   5 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	dialContext := dialer.DialContext
	if privateOnly {
		dialContext = privateDialContext(dialer)
	}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext:           dialContext,
			TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          8,
			MaxIdleConnsPerHost:   4,
			IdleConnTimeout:       30 * time.Second,
			TLSHandshakeTimeout:   5 * time.Second,
			ResponseHeaderTimeout: timeout,
		},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errors.New("redirect was rejected")
		},
	}
}

func privateDialContext(dialer *net.Dialer) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, errors.New("upstream address is invalid")
		}
		addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil || len(addresses) == 0 {
			return nil, errors.New("upstream address could not be resolved")
		}
		for _, address := range addresses {
			ip := address.IP
			if !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() {
				continue
			}
			connection, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			if dialErr == nil {
				return connection, nil
			}
		}
		return nil, errors.New("unencrypted upstream resolved outside the private network")
	}
}
