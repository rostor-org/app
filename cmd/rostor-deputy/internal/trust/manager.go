package trust

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"rostor.org/app/cmd/rostor-deputy/internal/core"
	"rostor.org/app/cmd/rostor-deputy/internal/enroll"
)

// Prober is the one call made with a staged pair before it replaces the
// live one. *core.Client satisfies it.
type Prober interface {
	Trust(ctx context.Context) (*core.TrustResponse, error)
}

// Manager applies trust bundles and renews the device certificate. It also
// implements core.Verifier: a Verify that fails in the TLS handshake triggers
// a trust check and one retry, which is how a device catches up after a CA
// rotation it slept through.
type Manager struct {
	Client *core.Client
	Files  Files
	// Config is deputy.json; Manager owns trust_version in it.
	Config *enroll.Config
	// SecureKey applies the §4 ACL to a staged key; nil on non-Windows.
	SecureKey func(path string) error
	Logger    *log.Logger
	// Now is the clock for the expiry decision; nil means time.Now.
	Now func() time.Time
	// NewProber builds a client from a staged pair; nil means core.NewClient
	// with the live bundle. Tests replace it.
	NewProber func(certPath, keyPath, caPath string) (Prober, error)

	mu sync.Mutex
}

// Verify implements core.Verifier with the TLS-failure recovery described
// on Manager.
func (m *Manager) Verify(ctx context.Context, req core.VerifyRequest) (*core.VerifyResponse, error) {
	resp, err := m.Client.Verify(ctx, req)
	if err == nil || !errors.Is(err, core.ErrTLS) {
		return resp, err
	}
	m.logf("verify failed in TLS handshake (%v); refreshing trust", err)
	// Reload first: a bundle already corrected on disk (trust update by a
	// concurrent CLI run, or by hand) must take effect before the fetch.
	if rerr := m.Client.Reload(); rerr != nil {
		m.logf("reload before trust refresh: %v", rerr)
	}
	if cerr := m.Check(ctx); cerr != nil {
		m.logf("trust check after TLS failure: %v", cerr)
		return nil, err
	}
	return m.Client.Verify(ctx, req)
}

// Start proves a staged pair a crash left behind, then runs one Check.
// Errors are returned for the log; the deputy keeps running on whatever pair
// it has. Recover must already have run before the live client was built
// (it may complete a half-done rename that the client would fail to load).
func (m *Manager) Start(ctx context.Context) error {
	m.mu.Lock()
	staged, err := Recover(m.Files)
	if err != nil {
		m.mu.Unlock()
		return err
	}
	if staged {
		m.logf("staged certificate pair found; proving it before use")
		if err := m.proveAndCommit(ctx); err != nil {
			m.logf("staged pair discarded: %v", err)
		}
	}
	m.mu.Unlock()
	return m.Check(ctx)
}

// Check is the heartbeat step: fetch trust, apply a changed bundle, renew
// when core says so or the local certificate warrants it.
func (m *Manager) Check(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.syncWithDisk()
	resp, err := m.Client.Trust(ctx)
	if err != nil {
		return fmt.Errorf("trust: %w", err)
	}
	if err := m.applyBundle(resp.Version, resp.CAPEMs); err != nil {
		return err
	}
	need, why := resp.Renew, "core asked"
	if !need {
		bundle, _ := ParseBundle(Concat(resp.CAPEMs))
		need, why = NeedsRenewal(m.Client.Certificate(), bundle, m.now())
	}
	if !need {
		return nil
	}
	m.logf("renewing certificate: %s", why)
	return m.renewLocked(ctx)
}

// Renew forces a renewal regardless of expiry (`rostor-deputy renew --now`).
func (m *Manager) Renew(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.syncWithDisk()
	return m.renewLocked(ctx)
}

// renewLocked performs one renewal. Order matters: the reply's bundle is
// pinned first (so the probe trusts a server that already moved CA), the
// new pair is staged and proven with a GET trust, and only then renamed
// over the old one. Any failure before the commit leaves the old pair in
// place; core keeps accepting it for 24 h after issuing the new one.
func (m *Manager) renewLocked(ctx context.Context) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	cn := ""
	if leaf := m.Client.Certificate(); leaf != nil {
		cn = leaf.Subject.CommonName
	}
	if cn == "" {
		cn, _ = os.Hostname()
	}
	csr, err := enroll.CSR(key, cn)
	if err != nil {
		return err
	}
	resp, err := m.Client.Renew(ctx, csr)
	if err != nil {
		return fmt.Errorf("renew: %w", err)
	}
	if len(resp.CAPEMs) > 0 {
		if err := m.applyBundle(resp.TrustVersion, resp.CAPEMs); err != nil {
			return err
		}
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := StagePair(m.Files, keyPEM, []byte(resp.CertificatePEM), m.SecureKey); err != nil {
		return fmt.Errorf("stage renewed pair: %w", err)
	}
	return m.proveAndCommit(ctx)
}

// proveAndCommit makes one call with the staged pair, then swaps it in and
// reloads the live client. On failure the staged pair is removed.
func (m *Manager) proveAndCommit(ctx context.Context) error {
	certNew, keyNew := StagedPaths(m.Files)
	prober, err := m.newProber(certNew, keyNew, m.Files.CACert)
	if err != nil {
		DiscardStaged(m.Files)
		return fmt.Errorf("load staged pair: %w", err)
	}
	if _, err := prober.Trust(ctx); err != nil {
		DiscardStaged(m.Files)
		return fmt.Errorf("staged pair rejected by core: %w", err)
	}
	if err := CommitPair(m.Files); err != nil {
		DiscardStaged(m.Files)
		return err
	}
	if err := m.Client.Reload(); err != nil {
		return fmt.Errorf("reload after renewal: %w", err)
	}
	leaf := m.Client.Certificate()
	m.logf("certificate renewed, expires %s", leaf.NotAfter.UTC().Format(time.RFC3339))
	return nil
}

// applyBundle replaces ca.crt when the bundle changed and records the
// version. The file content is compared too, so a version recorded before a
// failed write does not mask a stale file.
func (m *Manager) applyBundle(version string, pems []string) error {
	if len(pems) == 0 {
		return nil
	}
	newBundle, err := ParseBundle(Concat(pems))
	if err != nil {
		return fmt.Errorf("trust bundle: %w", err)
	}
	current, _ := LoadBundle(m.Files)
	if version == m.Config.TrustVersion && SameBundle(current, newBundle) {
		return nil
	}
	if !SameBundle(current, newBundle) {
		if err := WriteAtomic(m.Files.CACert, Concat(pems), 0o644); err != nil {
			return fmt.Errorf("write ca.crt: %w", err)
		}
		if err := m.Client.Reload(); err != nil {
			return fmt.Errorf("reload after bundle update: %w", err)
		}
	}
	m.Config.TrustVersion = version
	if err := enroll.SaveConfig(m.Files.DeputyJSON, m.Config); err != nil {
		return fmt.Errorf("save trust_version: %w", err)
	}
	m.logf("trust bundle version %s pinned (%d CA%s)", version, len(newBundle), plural(len(newBundle)))
	return nil
}

// syncWithDisk reloads the client when device.crt on disk is not the
// certificate in memory, e.g. after `rostor-deputy renew --now` ran beside
// the service.
func (m *Manager) syncWithDisk() {
	onDisk, err := LoadLeaf(m.Files)
	if err != nil {
		return
	}
	if leaf := m.Client.Certificate(); leaf != nil && leaf.SerialNumber.Cmp(onDisk.SerialNumber) == 0 {
		return
	}
	if err := m.Client.Reload(); err != nil {
		m.logf("reload changed device.crt: %v", err)
		return
	}
	m.logf("picked up renewed certificate from disk")
}

func (m *Manager) newProber(certPath, keyPath, caPath string) (Prober, error) {
	if m.NewProber != nil {
		return m.NewProber(certPath, keyPath, caPath)
	}
	return core.NewClient(m.Client.BaseURL, certPath, keyPath, caPath, m.Client.Resource, m.Client.AgentVersion)
}

func (m *Manager) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

func (m *Manager) logf(format string, args ...any) {
	if m.Logger != nil {
		m.Logger.Printf(format, args...)
	}
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
