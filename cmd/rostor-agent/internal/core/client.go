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
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// Timeout bounds every core call. The credprov gives up at 10 s (contract §2),
// so the agent must answer before that with a rendered agent.core_unreachable.
const Timeout = 8 * time.Second

// Client talks to core over mTLS with the enrolled device certificate and
// pins the core CA bundle from enrollment (contract §1.2/§1.3). The key pair
// and bundle are read from files so that trust updates and certificate
// renewal (console-api.md "Certificates and trust") can swap them on disk and
// call Reload without restarting the service.
type Client struct {
	BaseURL      string
	Resource     Resource
	AgentVersion string

	certPath, keyPath, caPath string

	mu   sync.RWMutex
	http *http.Client
	leaf *x509.Certificate
}

// ErrUnreachable wraps any transport-level failure so the broker can map it to
// agent.core_unreachable without inspecting error strings.
var ErrUnreachable = errors.New("core unreachable")

// ErrTLS additionally marks a transport failure that happened in the TLS
// handshake itself: the server's certificate is not signed by a pinned CA, or
// core rejected the device certificate. Both are what a CA rotation looks
// like from a device that has not applied the new bundle yet, so the caller
// re-fetches trust and retries once. Errors carrying ErrTLS always carry
// ErrUnreachable too.
var ErrTLS = errors.New("tls failure")

// NewClient loads the device key pair and CA bundle from the given paths.
func NewClient(baseURL, certPath, keyPath, caPath string, res Resource, agentVersion string) (*Client, error) {
	c := &Client{
		BaseURL:      strings.TrimRight(baseURL, "/"),
		Resource:     res,
		AgentVersion: agentVersion,
		certPath:     certPath,
		keyPath:      keyPath,
		caPath:       caPath,
	}
	if err := c.Reload(); err != nil {
		return nil, err
	}
	return c, nil
}

// Reload re-reads device.crt, device.key and ca.crt and swaps the transport.
// On any error the previous transport stays in use, so a half-written file
// never takes the logon path down.
func (c *Client) Reload() error {
	cert, err := tls.LoadX509KeyPair(c.certPath, c.keyPath)
	if err != nil {
		return fmt.Errorf("load device certificate: %w", err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return fmt.Errorf("parse device certificate: %w", err)
	}
	caPEM, err := os.ReadFile(c.caPath)
	if err != nil {
		return fmt.Errorf("read ca.crt: %w", err)
	}
	// AppendCertsFromPEM walks every CERTIFICATE block in the file, so a
	// bundle of several CAs (enrollment and trust both return all active
	// ones concatenated) is pinned as a whole.
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return errors.New("ca.crt contains no certificates")
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			RootCAs:      pool, // pin: only the core CAs, never the system store
			MinVersion:   tls.VersionTLS12,
		},
		TLSHandshakeTimeout:   Timeout,
		ResponseHeaderTimeout: Timeout,
		Proxy:                 nil, // LogonUI-time traffic must not depend on a user proxy
	}
	c.mu.Lock()
	old := c.http
	c.http = &http.Client{Transport: tr, Timeout: Timeout}
	c.leaf = leaf
	c.mu.Unlock()
	if old != nil {
		old.CloseIdleConnections()
	}
	return nil
}

// Certificate returns the device certificate currently presented to core.
func (c *Client) Certificate() *x509.Certificate {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.leaf
}

// Files returns the paths the client loads from.
func (c *Client) Files() (certPath, keyPath, caPath string) {
	return c.certPath, c.keyPath, c.caPath
}

// Verify implements Verifier via POST /v1/verify.
func (c *Client) Verify(ctx context.Context, req VerifyRequest) (*VerifyResponse, error) {
	if req.Resource.ID == "" {
		req.Resource = c.Resource
	}
	var out VerifyResponse
	status, err := c.doJSON(ctx, http.MethodPost, "/v1/verify", req, &out)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		// Core answers 200 for any well-formed request; anything else is an
		// infrastructure problem the person cannot fix from the lock screen.
		return nil, fmt.Errorf("%w: verify returned HTTP %d", ErrUnreachable, status)
	}
	if out.Decision != DecisionAllow && out.Decision != DecisionDeny && out.Decision != DecisionContinue {
		return nil, fmt.Errorf("%w: verify returned decision %q", ErrUnreachable, out.Decision)
	}
	return &out, nil
}

// Posture implements §1.3; failures are logged by the caller, never fatal.
func (c *Client) Posture(ctx context.Context, osVersion string) error {
	body := map[string]string{"agent_version": c.AgentVersion, "os_version": osVersion}
	status, err := c.doJSON(ctx, http.MethodPost, "/v1/devices/self/posture", body, nil)
	if err != nil {
		return err
	}
	if status != http.StatusNoContent && status != http.StatusOK {
		return fmt.Errorf("posture returned HTTP %d", status)
	}
	return nil
}

// Trust implements GET /v1/devices/self/trust.
func (c *Client) Trust(ctx context.Context) (*TrustResponse, error) {
	var out TrustResponse
	status, err := c.doJSON(ctx, http.MethodGet, "/v1/devices/self/trust", nil, &out)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("%w: trust returned HTTP %d", ErrUnreachable, status)
	}
	if out.Version == "" || len(out.CAPEMs) == 0 {
		return nil, fmt.Errorf("%w: trust response missing version or ca_pems", ErrUnreachable)
	}
	return &out, nil
}

// Policy implements GET /v1/devices/self/policy (§1.5). The caller keeps
// the last good answer; a failure here never changes what the lock screen
// shows.
func (c *Client) Policy(ctx context.Context) (*PolicyResponse, error) {
	var out PolicyResponse
	status, err := c.doJSON(ctx, http.MethodGet, "/v1/devices/self/policy", nil, &out)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("%w: policy returned HTTP %d", ErrUnreachable, status)
	}
	if out.Login.DefaultMethod == "" {
		return nil, fmt.Errorf("%w: policy response missing login.default_method", ErrUnreachable)
	}
	return &out, nil
}

// Renew implements POST /v1/devices/self/renew.
func (c *Client) Renew(ctx context.Context, csrPEM string) (*RenewResponse, error) {
	var out RenewResponse
	status, err := c.doJSON(ctx, http.MethodPost, "/v1/devices/self/renew", map[string]string{"csr_pem": csrPEM}, &out)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK && status != http.StatusCreated {
		return nil, fmt.Errorf("renew returned HTTP %d", status)
	}
	if out.CertificatePEM == "" {
		return nil, errors.New("renew response missing certificate_pem")
	}
	return &out, nil
}

// Scripts implements GET /v1/devices/self/scripts (§1.4). The list comes
// back in core's position order; callers still sort, since order is what
// the contract promises and a re-sort is cheaper than trusting it.
func (c *Client) Scripts(ctx context.Context) ([]Script, error) {
	var out struct {
		Scripts []Script `json:"scripts"`
	}
	status, err := c.doJSON(ctx, http.MethodGet, "/v1/devices/self/scripts", nil, &out)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("%w: scripts returned HTTP %d", ErrUnreachable, status)
	}
	return out.Scripts, nil
}

// ReportRun implements POST /v1/devices/self/scripts/{id}/runs (§1.4).
func (c *Client) ReportRun(ctx context.Context, id string, run ScriptRun) error {
	status, err := c.doJSON(ctx, http.MethodPost, "/v1/devices/self/scripts/"+url.PathEscape(id)+"/runs", run, nil)
	if err != nil {
		return err
	}
	if status != http.StatusCreated {
		return fmt.Errorf("report run returned HTTP %d", status)
	}
	return nil
}

func (c *Client) doJSON(ctx context.Context, method, path string, in, out any) (int, error) {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return 0, err
		}
		body = bytes.NewReader(b)
	}
	ctx, cancel := context.WithTimeout(ctx, Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, body)
	if err != nil {
		return 0, err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "rostor-agent/"+c.AgentVersion)
	c.mu.RLock()
	hc := c.http
	c.mu.RUnlock()
	resp, err := hc.Do(req)
	if err != nil {
		if isTLSError(err) {
			return 0, fmt.Errorf("%w: %w: %v", ErrUnreachable, ErrTLS, err)
		}
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

// isTLSError recognises the handshake failures a CA rotation produces:
// our pool no longer trusts the server (a verification error on our side)
// or the server no longer trusts us (an alert such as "bad certificate",
// "unknown certificate authority" or "certificate required"). crypto/tls
// delivers a peer alert as an unexported type inside a *net.OpError whose
// Op is "remote error"; that Op is used by nothing else, so it is matched
// structurally rather than by message text.
func isTLSError(err error) bool {
	var verify *tls.CertificateVerificationError
	var alert tls.AlertError
	var unknownCA x509.UnknownAuthorityError
	var invalid x509.CertificateInvalidError
	var header tls.RecordHeaderError
	var op *net.OpError
	return errors.As(err, &verify) || errors.As(err, &alert) ||
		errors.As(err, &unknownCA) || errors.As(err, &invalid) || errors.As(err, &header) ||
		(errors.As(err, &op) && op.Op == "remote error")
}
