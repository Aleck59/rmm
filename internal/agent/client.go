package agent

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Aleck59/rmm/internal/protocol"
)

// APIError is a non-2xx response from the server.
type APIError struct {
	Status     int
	Code       string
	Title      string
	RetryAfter time.Duration
}

func (e *APIError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("server returned %d %s: %s", e.Status, e.Code, e.Title)
	}
	return fmt.Sprintf("server returned %d", e.Status)
}

// Client talks to the agent API. It only ever initiates outbound requests;
// the agent opens no listening ports.
type Client struct {
	base      *url.URL
	hc        *http.Client
	userAgent string
}

// NewClient builds a client that trusts only the configured CA (when set)
// and, optionally, pinned server keys.
func NewClient(cfg Config, userAgent string) (*Client, error) {
	u, err := url.Parse(cfg.ServerURL)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("invalid server_url %q", cfg.ServerURL)
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !cfg.AllowInsecure {
			return nil, errors.New("server_url uses plain http; set allow_insecure: true for development only")
		}
	default:
		return nil, fmt.Errorf("unsupported server_url scheme %q", u.Scheme)
	}

	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = nil // direct by default; "system" opts into proxy settings
	if cfg.Proxy == "system" {
		tr.Proxy = http.ProxyFromEnvironment
	}
	tr.IdleConnTimeout = 120 * time.Second
	tr.ResponseHeaderTimeout = 30 * time.Second
	if u.Scheme == "https" {
		tlsCfg, err := tlsConfig(cfg, u.Hostname())
		if err != nil {
			return nil, err
		}
		tr.TLSClientConfig = tlsCfg
	}
	return &Client{
		base:      u,
		hc:        &http.Client{Transport: tr, Timeout: 60 * time.Second},
		userAgent: userAgent,
	}, nil
}

func tlsConfig(cfg Config, serverName string) (*tls.Config, error) {
	t := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: serverName}
	if cfg.CAFile != "" {
		pem, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read ca_file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("ca_file: no certificates found")
		}
		// Only the configured CA: the Windows 7 store is outdated and a local
		// store is easier to tamper with.
		t.RootCAs = pool
	}
	if len(cfg.PinSHA256) > 0 {
		var pins [][]byte
		for _, p := range cfg.PinSHA256 {
			b, err := base64.StdEncoding.DecodeString(p)
			if err != nil || len(b) != sha256.Size {
				return nil, fmt.Errorf("pin_sha256 %q is not base64 SHA-256", p)
			}
			pins = append(pins, b)
		}
		t.VerifyConnection = func(cs tls.ConnectionState) error {
			for _, chain := range cs.VerifiedChains {
				for _, cert := range chain {
					sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
					for _, pin := range pins {
						if bytes.Equal(sum[:], pin) {
							return nil
						}
					}
				}
			}
			return errors.New("server key does not match pin_sha256")
		}
	}
	return t, nil
}

// Enroll registers the agent using an enrollment token.
func (c *Client) Enroll(ctx context.Context, enrollToken string, req protocol.EnrollRequest) (protocol.EnrollResponse, error) {
	var out protocol.EnrollResponse
	err := c.do(ctx, http.MethodPost, "/enroll", enrollToken, req, false, &out)
	return out, err
}

// PostMetrics sends one metrics batch (gzip-compressed).
func (c *Client) PostMetrics(ctx context.Context, token string, b protocol.MetricsBatch) (protocol.MetricsResponse, error) {
	var out protocol.MetricsResponse
	err := c.do(ctx, http.MethodPost, "/metrics", token, b, true, &out)
	return out, err
}

// GetConfig fetches the collection configuration.
func (c *Client) GetConfig(ctx context.Context, token string) (protocol.AgentConfig, error) {
	var out protocol.AgentConfig
	err := c.do(ctx, http.MethodGet, "/config", token, nil, false, &out)
	return out, err
}

// RotateToken exchanges the current device token for a new one.
func (c *Client) RotateToken(ctx context.Context, token string) (protocol.TokenRotateResponse, error) {
	var out protocol.TokenRotateResponse
	err := c.do(ctx, http.MethodPost, "/token/rotate", token, nil, false, &out)
	return out, err
}

func (c *Client) do(ctx context.Context, method, path, token string, in any, gz bool, out any) error {
	var body io.Reader
	var encoded []byte
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return err
		}
		encoded = raw
		if gz {
			var buf bytes.Buffer
			zw := gzip.NewWriter(&buf)
			if _, err := zw.Write(raw); err != nil {
				return err
			}
			if err := zw.Close(); err != nil {
				return err
			}
			encoded = buf.Bytes()
		}
		body = bytes.NewReader(encoded)
	}
	endpoint := c.base.JoinPath(protocol.APIVersionPath, path)
	req, err := http.NewRequestWithContext(ctx, method, endpoint.String(), body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Accept", "application/json")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
		if gz {
			req.Header.Set("Content-Encoding", "gzip")
		}
	}

	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		apiErr := &APIError{Status: resp.StatusCode}
		var p protocol.Problem
		if json.Unmarshal(data, &p) == nil {
			apiErr.Code, apiErr.Title = p.Code, p.Title
		}
		if s := resp.Header.Get("Retry-After"); s != "" {
			if secs, err := strconv.Atoi(strings.TrimSpace(s)); err == nil {
				apiErr.RetryAfter = time.Duration(secs) * time.Second
			}
		}
		return apiErr
	}
	if out != nil && len(data) > 0 {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
	}
	return nil
}
