package trust

import (
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
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"rostor.org/app/cmd/rostor-deputy/internal/core"
	"rostor.org/app/cmd/rostor-deputy/internal/enroll"
)

// ---- a tiny CA ---------------------------------------------------------------

type testCA struct {
	key  *ecdsa.PrivateKey
	cert *x509.Certificate
	pem  string
}

var serial int64 = 100

func newCA(t *testing.T, name string) *testCA {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial++
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &testCA{key: key, cert: cert, pem: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}
}

// issue signs a leaf for pub with the given lifetime; server=true adds the
// loopback SAN so httptest's URL verifies.
func (ca *testCA) issue(t *testing.T, pub any, cn string, ttl time.Duration, server bool) (*x509.Certificate, string) {
	t.Helper()
	serial++
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(ttl),
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	if server {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		tmpl.IPAddresses = []net.IP{net.IPv4(127, 0, 0, 1)}
	} else {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, pub, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return cert, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func keyPEM(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func tempFiles(t *testing.T) Files {
	dir := t.TempDir()
	return Files{
		DeputyJSON: filepath.Join(dir, "deputy.json"), DeviceKey: filepath.Join(dir, "device.key"),
		DeviceCert: filepath.Join(dir, "device.crt"), CACert: filepath.Join(dir, "ca.crt"),
	}
}

func mustWrite(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func exists(path string) bool { _, err := os.Stat(path); return err == nil }

// ---- pure logic ----------------------------------------------------------------

func TestConcatParseSameBundle(t *testing.T) {
	a, b := newCA(t, "A"), newCA(t, "B")
	// Trailing newline or not, the bundle round-trips to the same set.
	data := Concat([]string{strings.TrimSpace(a.pem), b.pem, ""})
	certs, err := ParseBundle(data)
	if err != nil || len(certs) != 2 {
		t.Fatalf("parsed %d certs, err %v", len(certs), err)
	}
	if certs[0].Subject.CommonName != "A" || certs[1].Subject.CommonName != "B" {
		t.Fatalf("order lost: %v", certs)
	}
	if !SameBundle(certs, []*x509.Certificate{b.cert, a.cert}) {
		t.Fatal("SameBundle should ignore order")
	}
	if SameBundle(certs, []*x509.Certificate{a.cert}) {
		t.Fatal("SameBundle should notice a missing CA")
	}
	if _, err := ParseBundle([]byte("not pem")); err == nil {
		t.Fatal("empty bundle should be an error")
	}
	// The mTLS pool loads every certificate from the concatenation.
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) || len(pool.Subjects()) != 2 { //nolint:staticcheck // Subjects is fine for a count
		t.Fatal("pool did not take both CAs")
	}
}

func TestNeedsRenewal(t *testing.T) {
	old, newer := newCA(t, "old"), newCA(t, "new")
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Now()
	fresh, _ := old.issue(t, &key.PublicKey, "WS", 90*24*time.Hour, false)
	soon, _ := old.issue(t, &key.PublicKey, "WS", 10*24*time.Hour, false)

	cases := []struct {
		name   string
		leaf   *x509.Certificate
		bundle []*x509.Certificate
		want   bool
		why    string
	}{
		{"fresh, issuer newest", fresh, []*x509.Certificate{old.cert}, false, ""},
		{"expires within 30 days", soon, []*x509.Certificate{old.cert}, true, "expires"},
		{"issuer no longer newest", fresh, []*x509.Certificate{newer.cert, old.cert}, true, "no longer the newest"},
		{"issuer not in bundle", fresh, []*x509.Certificate{newer.cert}, true, "not in the trust bundle"},
		{"no bundle known", fresh, nil, false, ""},
		{"no certificate", nil, []*x509.Certificate{old.cert}, false, ""},
	}
	for _, c := range cases {
		got, why := NeedsRenewal(c.leaf, c.bundle, now)
		if got != c.want || !strings.Contains(why, c.why) {
			t.Errorf("%s: got %v %q, want %v containing %q", c.name, got, why, c.want, c.why)
		}
	}
	// Exactly at the threshold counts as due (core uses the same "<").
	edge, _ := old.issue(t, &key.PublicKey, "WS", RenewWithin-time.Minute, false)
	if got, _ := NeedsRenewal(edge, []*x509.Certificate{old.cert}, now); !got {
		t.Error("just under 30 days should renew")
	}
}

func TestWriteAtomic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ca.crt")
	mustWrite(t, path, []byte("old"))
	if err := WriteAtomic(path, []byte("new"), 0o644); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(path); string(b) != "new" {
		t.Fatalf("got %q", b)
	}
	if exists(path + ".new") {
		t.Fatal("temp file left behind")
	}
}

func TestStageCommitAndRecover(t *testing.T) {
	ca := newCA(t, "CA")
	k1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	k2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, c1 := ca.issue(t, &k1.PublicKey, "WS", time.Hour, false)
	_, c2 := ca.issue(t, &k2.PublicKey, "WS", time.Hour, false)
	p1, p2 := keyPEM(t, k1), keyPEM(t, k2)

	live := func(f Files, wantKey []byte, wantCert string) {
		t.Helper()
		k, _ := os.ReadFile(f.DeviceKey)
		c, _ := os.ReadFile(f.DeviceCert)
		if string(k) != string(wantKey) || string(c) != wantCert {
			t.Fatalf("live pair is not the expected one")
		}
		if exists(f.DeviceKey+".new") || exists(f.DeviceCert+".new") {
			t.Fatal("staged files left behind")
		}
	}

	t.Run("stage rejects a mismatched pair and leaves nothing", func(t *testing.T) {
		f := tempFiles(t)
		mustWrite(t, f.DeviceKey, p1)
		mustWrite(t, f.DeviceCert, []byte(c1))
		if err := StagePair(f, p2, []byte(c1), nil); err == nil {
			t.Fatal("mismatched pair accepted")
		}
		live(f, p1, c1)
	})

	t.Run("stage then commit swaps both, ACL hook sees the staged key", func(t *testing.T) {
		f := tempFiles(t)
		mustWrite(t, f.DeviceKey, p1)
		mustWrite(t, f.DeviceCert, []byte(c1))
		secured := ""
		if err := StagePair(f, p2, []byte(c2), func(p string) error { secured = p; return nil }); err != nil {
			t.Fatal(err)
		}
		if secured != f.DeviceKey+".new" {
			t.Fatalf("SecureKey called with %q", secured)
		}
		if !HasStagedPair(f) {
			t.Fatal("staged pair not detected")
		}
		live0, _ := os.ReadFile(f.DeviceKey)
		if string(live0) != string(p1) {
			t.Fatal("staging touched the live key")
		}
		if err := CommitPair(f); err != nil {
			t.Fatal(err)
		}
		live(f, p2, c2)
	})

	t.Run("discard keeps the live pair", func(t *testing.T) {
		f := tempFiles(t)
		mustWrite(t, f.DeviceKey, p1)
		mustWrite(t, f.DeviceCert, []byte(c1))
		if err := StagePair(f, p2, []byte(c2), nil); err != nil {
			t.Fatal(err)
		}
		DiscardStaged(f)
		live(f, p1, c1)
		if err := CommitPair(f); err == nil {
			t.Fatal("commit without a staged pair should fail")
		}
	})

	t.Run("recover finishes a commit interrupted between the two renames", func(t *testing.T) {
		f := tempFiles(t)
		mustWrite(t, f.DeviceKey, p2) // key already renamed
		mustWrite(t, f.DeviceCert, []byte(c1))
		mustWrite(t, f.DeviceCert+".new", []byte(c2))
		staged, err := Recover(f)
		if err != nil || staged {
			t.Fatalf("staged=%v err=%v", staged, err)
		}
		live(f, p2, c2)
	})

	t.Run("recover drops a stale cert.new that does not match the live key", func(t *testing.T) {
		f := tempFiles(t)
		mustWrite(t, f.DeviceKey, p1)
		mustWrite(t, f.DeviceCert, []byte(c1))
		mustWrite(t, f.DeviceCert+".new", []byte(c2))
		if staged, err := Recover(f); err != nil || staged {
			t.Fatalf("staged=%v err=%v", staged, err)
		}
		live(f, p1, c1)
	})

	t.Run("recover drops a lone key.new", func(t *testing.T) {
		f := tempFiles(t)
		mustWrite(t, f.DeviceKey, p1)
		mustWrite(t, f.DeviceCert, []byte(c1))
		mustWrite(t, f.DeviceKey+".new", p2)
		if staged, err := Recover(f); err != nil || staged {
			t.Fatalf("staged=%v err=%v", staged, err)
		}
		live(f, p1, c1)
	})

	t.Run("recover leaves a complete staged pair for probing", func(t *testing.T) {
		f := tempFiles(t)
		mustWrite(t, f.DeviceKey, p1)
		mustWrite(t, f.DeviceCert, []byte(c1))
		mustWrite(t, f.DeviceKey+".new", p2)
		mustWrite(t, f.DeviceCert+".new", []byte(c2))
		if staged, err := Recover(f); err != nil || !staged {
			t.Fatalf("staged=%v err=%v", staged, err)
		}
		if !HasStagedPair(f) {
			t.Fatal("staged pair removed")
		}
	})

	t.Run("recover drops a mismatched staged pair", func(t *testing.T) {
		f := tempFiles(t)
		mustWrite(t, f.DeviceKey, p1)
		mustWrite(t, f.DeviceCert, []byte(c1))
		mustWrite(t, f.DeviceKey+".new", p2)
		mustWrite(t, f.DeviceCert+".new", []byte(c1))
		if staged, err := Recover(f); err != nil || staged {
			t.Fatalf("staged=%v err=%v", staged, err)
		}
		live(f, p1, c1)
	})
}

func TestInspectReport(t *testing.T) {
	ca := newCA(t, "Rostor CA")
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, c := ca.issue(t, &k.PublicKey, "WS-1", 90*24*time.Hour, false)
	f := tempFiles(t)
	mustWrite(t, f.DeviceKey, keyPEM(t, k))
	mustWrite(t, f.DeviceCert, []byte(c))
	mustWrite(t, f.CACert, []byte(ca.pem))
	if err := enroll.SaveConfig(f.DeputyJSON, &enroll.Config{CoreURL: "https://x", TrustVersion: "abc"}); err != nil {
		t.Fatal(err)
	}
	r := Inspect(f)
	if len(r.Errors) != 0 || r.TrustVersion != "abc" || len(r.CAs) != 1 || r.Device == nil || r.DeviceIssuer == nil {
		t.Fatalf("report %+v", r)
	}
	var sb strings.Builder
	r.Write(&sb, time.Now())
	out := sb.String()
	for _, want := range []string{"trust version:  abc", Fingerprint(ca.cert)[:16], "device cert:    WS-1", "renewal due:  no"} {
		if !strings.Contains(out, want) {
			t.Errorf("report missing %q:\n%s", want, out)
		}
	}
}

// ---- fake core with a rotatable CA -----------------------------------------------

type fakeCore struct {
	t  *testing.T
	mu sync.Mutex
	// cas is the active set, newest first; version derives from it.
	cas     []*testCA
	renewed int
	// rejectRenewedProbe issues a certificate from a CA the server itself
	// does not accept, to exercise the "staged pair rejected" path.
	issueFrom *testCA
	srv       *httptest.Server
}

func newFakeCore(t *testing.T, first *testCA) *fakeCore {
	fc := &fakeCore{t: t, cas: []*testCA{first}}
	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, serverPEM := first.issue(t, &serverKey.PublicKey, "core", time.Hour, true)
	serverCert, err := tls.X509KeyPair([]byte(serverPEM), keyPEM(t, serverKey))
	if err != nil {
		t.Fatal(err)
	}
	fc.srv = httptest.NewUnstartedServer(http.HandlerFunc(fc.handle))
	fc.srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			return &tls.Config{Certificates: []tls.Certificate{serverCert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: fc.clientPool()}, nil
		},
	}
	fc.srv.StartTLS()
	t.Cleanup(fc.srv.Close)
	return fc
}

func (fc *fakeCore) clientPool() *x509.CertPool {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	pool := x509.NewCertPool()
	for _, ca := range fc.cas {
		pool.AddCert(ca.cert)
	}
	return pool
}

func (fc *fakeCore) rotate(ca *testCA) {
	fc.mu.Lock()
	fc.cas = append([]*testCA{ca}, fc.cas...)
	fc.mu.Unlock()
}

func (fc *fakeCore) bundle() (string, []string) {
	var pems []string
	for _, ca := range fc.cas {
		pems = append(pems, ca.pem)
	}
	return "v" + fc.cas[0].cert.SerialNumber.String(), pems
}

func (fc *fakeCore) handle(w http.ResponseWriter, r *http.Request) {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	peer := r.TLS.PeerCertificates[0]
	version, pems := fc.bundle()
	switch r.URL.Path {
	case "/v1/verify":
		_ = json.NewEncoder(w).Encode(map[string]any{"decision": "DENY", "reason": []map[string]any{{"code": "auth.failed"}}})
	case "/v1/devices/self/trust":
		renew := peer.CheckSignatureFrom(fc.cas[0].cert) != nil
		_ = json.NewEncoder(w).Encode(map[string]any{"version": version, "ca_pems": pems, "renew": renew, "cert_not_after": peer.NotAfter})
	case "/v1/devices/self/renew":
		var req struct {
			CSRPEM string `json:"csr_pem"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		block, _ := pem.Decode([]byte(req.CSRPEM))
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil || csr.CheckSignature() != nil {
			http.Error(w, "bad csr", 400)
			return
		}
		issuer := fc.cas[0]
		if fc.issueFrom != nil {
			issuer = fc.issueFrom
		}
		leaf, certPEM := issuer.issue(fc.t, csr.PublicKey, csr.Subject.CommonName, 90*24*time.Hour, false)
		fc.renewed++
		_ = json.NewEncoder(w).Encode(map[string]any{"certificate_pem": certPEM, "not_after": leaf.NotAfter, "ca_pems": pems, "trust_version": version})
	default:
		http.NotFound(w, r)
	}
}

// enrolled writes the §4 files for a device holding a certificate from ca.
func enrolled(t *testing.T, fc *fakeCore, ca *testCA, ttl time.Duration) (Files, *enroll.Config) {
	t.Helper()
	f := tempFiles(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, certPEM := ca.issue(t, &key.PublicKey, "WS-1", ttl, false)
	mustWrite(t, f.DeviceKey, keyPEM(t, key))
	mustWrite(t, f.DeviceCert, []byte(certPEM))
	_, pems := fc.bundle()
	mustWrite(t, f.CACert, Concat(pems))
	cfg := &enroll.Config{CoreURL: fc.srv.URL, DeviceID: "dev_1", Resource: core.Resource{Type: "workstation", ID: "WS-1"}}
	if err := enroll.SaveConfig(f.DeputyJSON, cfg); err != nil {
		t.Fatal(err)
	}
	return f, cfg
}

func newManager(t *testing.T, f Files, cfg *enroll.Config) *Manager {
	t.Helper()
	client, err := core.NewClient(cfg.CoreURL, f.DeviceCert, f.DeviceKey, f.CACert, cfg.Resource, "test")
	if err != nil {
		t.Fatal(err)
	}
	return &Manager{Client: client, Files: f, Config: cfg}
}

func TestManagerRotationRenewsThroughStagedPair(t *testing.T) {
	ca1 := newCA(t, "CA1")
	fc := newFakeCore(t, ca1)
	f, cfg := enrolled(t, fc, ca1, 90*24*time.Hour)
	m := newManager(t, f, cfg)
	ctx := context.Background()

	// Steady state: the version is recorded, nothing else changes.
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	saved, _ := enroll.LoadConfig(f.DeputyJSON)
	if saved.TrustVersion == "" || fc.renewed != 0 {
		t.Fatalf("after start: version %q renewed %d", saved.TrustVersion, fc.renewed)
	}
	serial1 := m.Client.Certificate().SerialNumber

	// Rotate: a new CA appears; core says renew.
	ca2 := newCA(t, "CA2")
	fc.rotate(ca2)
	if err := m.Check(ctx); err != nil {
		t.Fatal(err)
	}
	cas, err := LoadBundle(f)
	if err != nil || len(cas) != 2 || cas[0].Subject.CommonName != "CA2" {
		t.Fatalf("ca.crt after rotation: %d CAs, err %v", len(cas), err)
	}
	saved, _ = enroll.LoadConfig(f.DeputyJSON)
	if saved.TrustVersion != "v"+ca2.cert.SerialNumber.String() {
		t.Fatalf("trust_version %q", saved.TrustVersion)
	}
	if fc.renewed != 1 {
		t.Fatalf("renewed %d times", fc.renewed)
	}
	leaf, _ := LoadLeaf(f)
	if leaf.CheckSignatureFrom(ca2.cert) != nil {
		t.Fatal("device.crt not issued by CA2")
	}
	if m.Client.Certificate().SerialNumber.Cmp(serial1) == 0 {
		t.Fatal("client still presents the old certificate")
	}
	if exists(f.DeviceKey+".new") || exists(f.DeviceCert+".new") {
		t.Fatal("staged files left behind")
	}
	// The live pair is loadable and accepted by core.
	if _, err := tls.LoadX509KeyPair(f.DeviceCert, f.DeviceKey); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Client.Trust(ctx); err != nil {
		t.Fatal(err)
	}
	// Nothing further to do on the next tick.
	if err := m.Check(ctx); err != nil || fc.renewed != 1 {
		t.Fatalf("second check: err %v renewed %d", err, fc.renewed)
	}
}

func TestManagerRenewsOnLocalExpiry(t *testing.T) {
	ca1 := newCA(t, "CA1")
	fc := newFakeCore(t, ca1)
	f, cfg := enrolled(t, fc, ca1, 20*24*time.Hour) // core's fake says renew=false; the local rule fires
	m := newManager(t, f, cfg)
	if err := m.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fc.renewed != 1 {
		t.Fatalf("renewed %d", fc.renewed)
	}
	if time.Until(m.Client.Certificate().NotAfter) < 80*24*time.Hour {
		t.Fatal("client did not pick up the renewed certificate")
	}
}

func TestManagerKeepsOldPairWhenProbeFails(t *testing.T) {
	ca1 := newCA(t, "CA1")
	fc := newFakeCore(t, ca1)
	f, cfg := enrolled(t, fc, ca1, 90*24*time.Hour)
	oldKey, _ := os.ReadFile(f.DeviceKey)
	oldCert, _ := os.ReadFile(f.DeviceCert)
	m := newManager(t, f, cfg)

	// Core issues from a CA it does not itself accept: the staged pair
	// cannot prove itself and must be thrown away.
	fc.issueFrom = newCA(t, "rogue")
	err := m.Renew(context.Background())
	if err == nil || !strings.Contains(err.Error(), "rejected") {
		t.Fatalf("expected probe rejection, got %v", err)
	}
	k, _ := os.ReadFile(f.DeviceKey)
	c, _ := os.ReadFile(f.DeviceCert)
	if string(k) != string(oldKey) || string(c) != string(oldCert) {
		t.Fatal("old pair was replaced")
	}
	if exists(f.DeviceKey+".new") || exists(f.DeviceCert+".new") {
		t.Fatal("staged files left behind")
	}
	// The old pair still works.
	if _, err := m.Client.Trust(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestManagerStartProvesLeftoverStagedPair(t *testing.T) {
	ca1 := newCA(t, "CA1")
	fc := newFakeCore(t, ca1)
	f, cfg := enrolled(t, fc, ca1, 90*24*time.Hour)
	// A previous run renewed, staged, and died before committing.
	k2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf2, c2 := ca1.issue(t, &k2.PublicKey, "WS-1", 90*24*time.Hour, false)
	mustWrite(t, f.DeviceKey+".new", keyPEM(t, k2))
	mustWrite(t, f.DeviceCert+".new", []byte(c2))

	m := newManager(t, f, cfg)
	if err := m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if m.Client.Certificate().SerialNumber.Cmp(leaf2.SerialNumber) != 0 {
		t.Fatal("staged pair was not committed")
	}
	if exists(f.DeviceKey + ".new") {
		t.Fatal("staged key left behind")
	}
}

func TestVerifyRecoversFromTLSFailure(t *testing.T) {
	ca1 := newCA(t, "CA1")
	fc := newFakeCore(t, ca1)
	f, cfg := enrolled(t, fc, ca1, 90*24*time.Hour)
	// The client was built while ca.crt pinned a CA that does not sign the
	// server; the file has since been corrected on disk (as a trust update
	// or an operator would). The first Verify fails in the handshake, the
	// recovery reloads and refreshes trust, the retry goes through.
	good, _ := os.ReadFile(f.CACert)
	mustWrite(t, f.CACert, []byte(newCA(t, "stale").pem))
	m := newManager(t, f, cfg)
	mustWrite(t, f.CACert, good)

	req := core.VerifyRequest{Credential: core.Credential{Type: "password", Identifier: "x", Secret: "y"}, Action: "logon"}
	if _, err := m.Client.Verify(context.Background(), req); !errors.Is(err, core.ErrTLS) || !errors.Is(err, core.ErrUnreachable) {
		t.Fatalf("expected a TLS failure carrying ErrUnreachable, got %v", err)
	}
	resp, err := m.Verify(context.Background(), req)
	if err != nil || resp.Decision != core.DecisionDeny {
		t.Fatalf("recovered verify: %v %+v", err, resp)
	}
}

func TestClientRejectsServerFromUnpinnedCA(t *testing.T) {
	ca1 := newCA(t, "CA1")
	fc := newFakeCore(t, ca1)
	f, cfg := enrolled(t, fc, ca1, 90*24*time.Hour)
	m := newManager(t, f, cfg)
	// Server rejects our certificate: also a TLS failure, not a plain
	// unreachable, so the broker path can distinguish it.
	fc.mu.Lock()
	fc.cas = []*testCA{newCA(t, "other")}
	fc.mu.Unlock()
	m.Client.Reload() // drop the kept-alive connection so a new handshake happens
	_, err := m.Client.Trust(context.Background())
	if !errors.Is(err, core.ErrTLS) {
		t.Fatalf("expected ErrTLS, got %v", err)
	}
}
