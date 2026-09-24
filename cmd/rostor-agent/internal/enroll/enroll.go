// Package enroll performs one-time device enrollment (contract §1.1) and
// writes the resulting files (§4). The private key is generated here and
// never leaves the machine; only the CSR travels.
package enroll

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"rostor.org/app/cmd/rostor-agent/internal/core"
)

// Config is the persisted agent.json (contract §4). Resource is an addition:
// the enrollment response names the workstation resource and the agent must
// send exactly that ID back in Verify even if the hostname later changes.
type Config struct {
	CoreURL  string        `json:"core_url"`
	DeviceID string        `json:"device_id"`
	Resource core.Resource `json:"resource"`
	// TrustVersion is the version of the CA bundle last written to ca.crt
	// (GET /v1/devices/self/trust). Empty until the first trust check.
	TrustVersion string `json:"trust_version,omitempty"`
}

// Posture is the §1.1 posture block.
type Posture struct {
	OS        string `json:"os"`
	OSVersion string `json:"os_version"`
	Hostname  string `json:"hostname"`
}

type request struct {
	EnrollmentToken string  `json:"enrollment_token"`
	CSRPEM          string  `json:"csr_pem"`
	Posture         Posture `json:"posture"`
}

type response struct {
	DeviceID       string        `json:"device_id"`
	CertificatePEM string        `json:"certificate_pem"`
	CAPEM          string        `json:"ca_pem"`
	Resource       core.Resource `json:"resource"`
}

// Files is where Run writes its outputs.
type Files struct {
	AgentJSON, DeviceKey, DeviceCert, CACert string
}

// Options controls the enrollment call.
type Options struct {
	CoreURL string
	Token   string
	Posture Posture
	// CAFile pins the core CA for the enrollment call itself when the
	// operator has it out of band. Empty means the system trust store.
	CAFile string
	// Insecure skips server verification for the enrollment call only. The
	// returned ca_pem is pinned for everything afterwards. PoC convenience.
	Insecure bool
	Files    Files
	// SecureKey applies the §4 ACL to device.key after writing; nil on
	// non-Windows.
	SecureKey func(path string) error
}

// Run enrolls and writes files. It refuses to overwrite an existing
// enrollment so a stray re-run cannot orphan the device principal core knows.
func Run(ctx context.Context, o Options) (*Config, error) {
	if o.CoreURL == "" || o.Token == "" {
		return nil, errors.New("enroll: core URL and token are required")
	}
	if _, err := os.Stat(o.Files.AgentJSON); err == nil {
		return nil, fmt.Errorf("enroll: %s already exists; remove it to re-enroll", o.Files.AgentJSON)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	csrPEM, err := CSR(key, o.Posture.Hostname)
	if err != nil {
		return nil, err
	}

	client, err := httpClient(o)
	if err != nil {
		return nil, err
	}
	body, _ := json.Marshal(request{EnrollmentToken: o.Token, CSRPEM: csrPEM, Posture: o.Posture})
	ctx, cancel := context.WithTimeout(ctx, core.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(o.CoreURL, "/")+"/v1/devices/enroll", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("enroll: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("enroll: core returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	var out response
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("enroll: bad response: %w", err)
	}
	if out.DeviceID == "" || out.CertificatePEM == "" || out.CAPEM == "" {
		return nil, errors.New("enroll: response missing device_id, certificate_pem or ca_pem")
	}
	if out.Resource.ID == "" {
		out.Resource = core.Resource{Type: "workstation", ID: o.Posture.Hostname}
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	// Sanity-check the pair before persisting anything.
	if _, err := tls.X509KeyPair([]byte(out.CertificatePEM), keyPEM); err != nil {
		return nil, fmt.Errorf("enroll: issued certificate does not match key: %w", err)
	}

	cfg := &Config{CoreURL: o.CoreURL, DeviceID: out.DeviceID, Resource: out.Resource}
	if err := os.MkdirAll(filepath.Dir(o.Files.AgentJSON), 0o755); err != nil {
		return nil, err
	}
	if err := os.WriteFile(o.Files.DeviceKey, keyPEM, 0o600); err != nil {
		return nil, err
	}
	if o.SecureKey != nil {
		if err := o.SecureKey(o.Files.DeviceKey); err != nil {
			return nil, fmt.Errorf("enroll: secure device.key: %w", err)
		}
	}
	if err := os.WriteFile(o.Files.DeviceCert, []byte(out.CertificatePEM), 0o644); err != nil {
		return nil, err
	}
	if err := os.WriteFile(o.Files.CACert, []byte(out.CAPEM), 0o644); err != nil {
		return nil, err
	}
	cfgJSON, _ := json.MarshalIndent(cfg, "", "  ")
	if err := os.WriteFile(o.Files.AgentJSON, cfgJSON, 0o644); err != nil {
		return nil, err
	}
	return cfg, nil
}

// CSR builds a PEM certificate request with CN = hostname.
func CSR(key *ecdsa.PrivateKey, hostname string) (string, error) {
	tmpl := &x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: hostname, OrganizationalUnit: []string{"Rostor Devices"}},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})), nil
}

// LoadConfig reads agent.json.
func LoadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("agent.json: %w", err)
	}
	if c.CoreURL == "" {
		return nil, errors.New("agent.json: core_url is empty")
	}
	return &c, nil
}

func httpClient(o Options) (*http.Client, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if o.CAFile != "" {
		pemBytes, err := os.ReadFile(o.CAFile)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemBytes) {
			return nil, fmt.Errorf("%s: no certificates", o.CAFile)
		}
		tlsCfg.RootCAs = pool
	}
	if o.Insecure {
		tlsCfg.InsecureSkipVerify = true
	}
	return &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsCfg, Proxy: nil}}, nil
}

// SaveConfig rewrites agent.json atomically (write path.new, rename).
func SaveConfig(path string, c *Config) error {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".new"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
