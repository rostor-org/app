package core

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// Timeout bounds every core call. The credprov gives up at 10 s (contract §2),
// so the agent must answer before that with a rendered agent.core_unreachable.
const Timeout = 8 * time.Second

// Client talks to core over mTLS with the enrolled device certificate and
// pins the core CA from enrollment (contract §1.2/§1.3).
type Client struct {
	BaseURL      string
	Resource     Resource
	AgentVersion string
	http         *http.Client
}

// ErrUnreachable wraps any transport-level failure so the broker can map it to
// agent.core_unreachable without inspecting error strings.
var ErrUnreachable = errors.New("core unreachable")

// NewClient loads the device key pair and CA from the given paths.
func NewClient(baseURL, certPath, keyPath, caPath string, res Resource, agentVersion string) (*Client, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("load device certificate: %w", err)
	}
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("read ca.crt: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("ca.crt contains no certificates")
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			RootCAs:      pool, // pin: only the core CA, never the system store
			MinVersion:   tls.VersionTLS12,
		},
		TLSHandshakeTimeout:   Timeout,
		ResponseHeaderTimeout: Timeout,
		Proxy:                 nil, // LogonUI-time traffic must not depend on a user proxy
	}
	return &Client{
		BaseURL:      strings.TrimRight(baseURL, "/"),
		Resource:     res,
		AgentVersion: agentVersion,
		http:         &http.Client{Transport: tr, Timeout: Timeout},
	}, nil
}

// Verify implements Verifier via POST /v1/verify.
func (c *Client) Verify(ctx context.Context, req VerifyRequest) (*VerifyResponse, error) {
	if req.Resource.ID == "" {
		req.Resource = c.Resource
	}
	var out VerifyResponse
	status, err := c.postJSON(ctx, "/v1/verify", req, &out)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		// Core answers 200 for any well-formed request; anything else is an
		// infrastructure problem the person cannot fix from the lock screen.
		return nil, fmt.Errorf("%w: verify returned HTTP %d", ErrUnreachable, status)
	}
	if out.Decision != "ALLOW" && out.Decision != "DENY" {
		return nil, fmt.Errorf("%w: verify returned decision %q", ErrUnreachable, out.Decision)
	}
	return &out, nil
}

// Posture implements §1.3; failures are logged by the caller, never fatal.
func (c *Client) Posture(ctx context.Context, osVersion string) error {
	body := map[string]string{"agent_version": c.AgentVersion, "os_version": osVersion}
	status, err := c.postJSON(ctx, "/v1/devices/self/posture", body, nil)
	if err != nil {
		return err
	}
	if status != http.StatusNoContent && status != http.StatusOK {
		return fmt.Errorf("posture returned HTTP %d", status)
	}
	return nil
}

func (c *Client) postJSON(ctx context.Context, path string, in, out any) (int, error) {
	b, err := json.Marshal(in)
	if err != nil {
		return 0, err
	}
	ctx, cancel := context.WithTimeout(ctx, Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+path, bytes.NewReader(b))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "rostor-agent/"+c.AgentVersion)
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, fmt.Errorf("%w: %v", ErrUnreachable, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return 0, fmt.Errorf("%w: %v", ErrUnreachable, err)
	}
	if out != nil && len(data) > 0 && resp.StatusCode < 300 {
		if err := json.Unmarshal(data, out); err != nil {
			return resp.StatusCode, fmt.Errorf("%w: bad JSON from core: %v", ErrUnreachable, err)
		}
	}
	return resp.StatusCode, nil
}
