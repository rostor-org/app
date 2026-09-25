package update

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"rostor.org/app/cmd/rostor-deputy/internal/core"
)

// ---- a tiny CA that signs bundles the way core does ---------------------------

type testCA struct {
	key *ecdsa.PrivateKey
	pem []byte
}

func newCA(t *testing.T, name string) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &testCA{key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// sign fills Signature exactly as the contract describes, over info.SHA256.
func (ca *testCA) sign(t *testing.T, info Info) Info {
	t.Helper()
	digest := sha256.Sum256(SignedMessage(info.Version, info.SHA256))
	sig, err := ecdsa.SignASN1(rand.Reader, ca.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	info.Signature = base64.StdEncoding.EncodeToString(sig)
	info.Signer = "cak_test"
	return info
}

// bundle builds a zip with the given entries (name → content) and the Info
// core would announce for it, signed by ca.
func bundle(t *testing.T, ca *testCA, version string, entries map[string]string) ([]byte, Info) {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range entries {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(w, body); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(buf.Bytes())
	info := Info{Version: version, SHA256: hex.EncodeToString(sum[:]), Size: int64(buf.Len())}
	return buf.Bytes(), ca.sign(t, info)
}

func goodEntries() map[string]string {
	return map[string]string{
		"rostor-deputy.exe":  "MZ new deputy",
		"RostorCredProv.dll": "MZ new dll",
		"install.ps1":        "Write-Host 'installing'\r\n",
		"uninstall.ps1":      "Write-Host 'removing'\r\n",
		"README.txt":         "hi\n",
	}
}

// ---- Verify --------------------------------------------------------------------

func TestVerify(t *testing.T) {
	ca, other := newCA(t, "CA"), newCA(t, "other")
	_, info := bundle(t, ca, "v0.14.0", goodEntries())
	if err := Verify(info, info.SHA256, ca.pem); err != nil {
		t.Fatalf("good signature: %v", err)
	}
	// Any CA in the bundle may be the signer (rotation window).
	if err := Verify(info, info.SHA256, append(append([]byte{}, other.pem...), ca.pem...)); err != nil {
		t.Fatalf("bundle with two CAs: %v", err)
	}
	// The digest verified is the caller's (what it computed over the
	// file), so a file that differs from what core signed is refused even
	// if the announced sha256 field still matches the signature.
	if err := Verify(info, strings.Repeat("0", 64), ca.pem); !errors.Is(err, ErrSignature) {
		t.Errorf("different file digest: want ErrSignature, got %v", err)
	}
	tamper := func(name string, f func(*Info)) {
		t.Helper()
		x := info
		f(&x)
		if err := Verify(x, x.SHA256, ca.pem); !errors.Is(err, ErrSignature) {
			t.Errorf("%s: want ErrSignature, got %v", name, err)
		}
	}
	tamper("version changed", func(x *Info) { x.Version = "v0.15.0" })
	tamper("sha changed", func(x *Info) { x.SHA256 = strings.Repeat("a", 64) })
	tamper("empty signature", func(x *Info) { x.Signature = "" })
	tamper("not base64", func(x *Info) { x.Signature = "***" })
	tamper("garbage DER", func(x *Info) { x.Signature = base64.StdEncoding.EncodeToString([]byte("nope")) })

	if err := Verify(info, info.SHA256, other.pem); !errors.Is(err, ErrSignature) {
		t.Errorf("wrong CA: want ErrSignature, got %v", err)
	}
	if err := Verify(info, info.SHA256, nil); !errors.Is(err, ErrNoCA) {
		t.Errorf("no bundle: want ErrNoCA, got %v", err)
	}
	// Size and signer are not signed: the digest already pins the bytes.
	x := info
	x.Size, x.Signer = 1, "cak_other"
	if err := Verify(x, x.SHA256, ca.pem); err != nil {
		t.Errorf("size/signer are informational: %v", err)
	}
}

func TestSignedMessage(t *testing.T) {
	if got := string(SignedMessage("v0.14.0", "abc")); got != "bundle\nv0.14.0\nabc" {
		t.Fatalf("got %q", got)
	}
}

// ---- Pending -------------------------------------------------------------------

func TestPendingRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "updates", "pending.json")
	if p, err := LoadPending(path); err != nil || p != nil {
		t.Fatalf("missing file: want nil, nil; got %v, %v", p, err)
	}
	want := Pending{Version: "v0.14.0", StartedAt: time.Date(2026, 9, 25, 10, 0, 0, 0, time.UTC), FromVersion: "v0.13.0"}
	if err := SavePending(path, want); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path + ".tmp"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("temp file left behind: %v", err)
	}
	b, _ := os.ReadFile(path)
	for _, key := range []string{`"version"`, `"started_at"`, `"from_version"`} {
		if !strings.Contains(string(b), key) {
			t.Errorf("pending.json lacks %s: %s", key, b)
		}
	}
	got, err := LoadPending(path)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || *got != want {
		t.Fatalf("round trip: got %+v, want %+v", got, want)
	}
	if err := RemovePending(path); err != nil {
		t.Fatal(err)
	}
	if err := RemovePending(path); err != nil {
		t.Fatalf("second remove must be a no-op: %v", err)
	}
	if p, err := LoadPending(path); err != nil || p != nil {
		t.Fatalf("after remove: got %v, %v", p, err)
	}
	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPending(path); err == nil {
		t.Fatal("corrupt pending.json must be an error, not nothing pending")
	}
}

// ---- fakes ---------------------------------------------------------------------

type fakeClient struct {
	mu        sync.Mutex
	info      *Info
	zip       []byte
	updateErr error
	bundleErr error
	reportErr error
	reports   []Run
	downloads int
}

func (c *fakeClient) Update(_ context.Context) (*core.UpdateResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.updateErr != nil {
		return nil, c.updateErr
	}
	if c.info == nil {
		return &core.UpdateResponse{}, nil
	}
	i := *c.info
	return &core.UpdateResponse{Update: &i}, nil
}

func (c *fakeClient) UpdateBundle(_ context.Context, w io.Writer) (int64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.downloads++
	if c.bundleErr != nil {
		return 0, c.bundleErr
	}
	n, err := w.Write(c.zip)
	return int64(n), err
}

func (c *fakeClient) ReportUpdate(_ context.Context, run core.UpdateRun) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.reportErr != nil {
		return c.reportErr
	}
	c.reports = append(c.reports, run)
	return nil
}

type fakeInstaller struct {
	mu    sync.Mutex
	dirs  []string
	err   error
	after func(dir string) // runs before returning, e.g. to fake the installer's log
}

func (f *fakeInstaller) start(_ context.Context, dir string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.dirs = append(f.dirs, dir)
	if f.after != nil {
		f.after(dir)
	}
	return f.err
}

func (f *fakeInstaller) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.dirs)
}

func newCoordinator(t *testing.T, ca *testCA, client *fakeClient, inst *fakeInstaller, running string) (*Coordinator, *bytes.Buffer) {
	t.Helper()
	root := t.TempDir()
	caFile := filepath.Join(root, "ca.crt")
	if err := os.WriteFile(caFile, ca.pem, 0o600); err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	return &Coordinator{
		Client: client, CAFile: caFile, Version: running, Logger: log.New(&logs, "", 0),
		Installer: inst.start, Dir: filepath.Join(root, "updates"),
		Now: func() time.Time { return time.Date(2026, 9, 25, 10, 0, 0, 0, time.UTC) },
	}, &logs
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// ---- Check ---------------------------------------------------------------------

func TestCheckHappyPath(t *testing.T) {
	ca := newCA(t, "CA")
	zipBytes, info := bundle(t, ca, "v0.14.0", goodEntries())
	client := &fakeClient{info: &info, zip: zipBytes}
	inst := &fakeInstaller{}
	c, logs := newCoordinator(t, ca, client, inst, "v0.13.0")

	if err := c.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(c.Dir, "v0.14.0")
	if inst.calls() != 1 || inst.dirs[0] != dir {
		t.Fatalf("installer calls: %v", inst.dirs)
	}
	for _, name := range []string{BundleName, "install.ps1", "rostor-deputy.exe", "RostorCredProv.dll", AttemptedMark} {
		if !exists(filepath.Join(dir, name)) {
			t.Errorf("%s missing after Check", name)
		}
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "install.ps1")); string(b) != goodEntries()["install.ps1"] {
		t.Errorf("install.ps1 content: %q", b)
	}
	p, err := LoadPending(filepath.Join(c.Dir, "pending.json"))
	if err != nil || p == nil {
		t.Fatalf("pending.json: %v, %v", p, err)
	}
	if p.Version != "v0.14.0" || p.FromVersion != "v0.13.0" || p.StartedAt != c.Now() {
		t.Fatalf("pending: %+v", *p)
	}
	for _, want := range []string{"offered", "verified and unpacked", "starting installer", "installer started"} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("log lacks %q:\n%s", want, logs.String())
		}
	}

	// The same version is never installed twice by this deputy, even
	// after pending.json is gone, and the bundle is not downloaded again.
	if err := RemovePending(filepath.Join(c.Dir, "pending.json")); err != nil {
		t.Fatal(err)
	}
	if err := c.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	if inst.calls() != 1 {
		t.Fatalf("second Check reinstalled: %d calls", inst.calls())
	}
	if client.downloads != 1 {
		t.Fatalf("second Check downloaded again: %d", client.downloads)
	}
	if !strings.Contains(logs.String(), "already attempted") {
		t.Errorf("log lacks the skip:\n%s", logs.String())
	}
	if exists(filepath.Join(c.Dir, "pending.json")) {
		t.Fatal("second Check must not rewrite pending.json")
	}
}

func TestCheckNothingToDo(t *testing.T) {
	ca := newCA(t, "CA")
	inst := &fakeInstaller{}
	client := &fakeClient{}
	c, _ := newCoordinator(t, ca, client, inst, "v0.13.0")
	if err := c.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	if inst.calls() != 0 || client.downloads != 0 || exists(c.Dir) {
		t.Fatal("nil update must touch nothing")
	}
	// A fetch failure is returned for the heartbeat to log.
	client.updateErr = errors.New("boom")
	if err := c.Check(context.Background()); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("want fetch error, got %v", err)
	}
	// Already on the wanted version: nothing to install.
	_, info := bundle(t, ca, "v0.13.0", goodEntries())
	client.updateErr, client.info = nil, &info
	if err := c.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	if inst.calls() != 0 || client.downloads != 0 {
		t.Fatal("same version must not be reinstalled")
	}
}

func TestCheckBusySkips(t *testing.T) {
	ca := newCA(t, "CA")
	zipBytes, info := bundle(t, ca, "v0.14.0", goodEntries())
	client := &fakeClient{info: &info, zip: zipBytes}
	inst := &fakeInstaller{}
	c, logs := newCoordinator(t, ca, client, inst, "v0.13.0")
	busy := true
	c.Busy = func() bool { return busy }

	if err := c.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	if inst.calls() != 0 || client.downloads != 0 {
		t.Fatal("busy: must neither download nor install")
	}
	if exists(filepath.Join(c.Dir, "pending.json")) || exists(filepath.Join(c.Dir, "v0.14.0", AttemptedMark)) {
		t.Fatal("busy: must leave no state")
	}
	if !strings.Contains(logs.String(), "deferred") {
		t.Errorf("log lacks the deferral:\n%s", logs.String())
	}
	// Next heartbeat, nobody signing in: it goes ahead.
	busy = false
	if err := c.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	if inst.calls() != 1 {
		t.Fatalf("after busy cleared: %d installer calls", inst.calls())
	}
}

func TestCheckBusyAfterDownloadSkips(t *testing.T) {
	ca := newCA(t, "CA")
	zipBytes, info := bundle(t, ca, "v0.14.0", goodEntries())
	client := &fakeClient{info: &info, zip: zipBytes}
	inst := &fakeInstaller{}
	c, _ := newCoordinator(t, ca, client, inst, "v0.13.0")
	// Idle at the first check, a logon arrives during the download.
	n := 0
	c.Busy = func() bool { n++; return n > 1 }
	if err := c.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	if client.downloads != 1 || inst.calls() != 0 {
		t.Fatalf("downloads %d installs %d", client.downloads, inst.calls())
	}
	if exists(filepath.Join(c.Dir, "pending.json")) || exists(filepath.Join(c.Dir, "v0.14.0", AttemptedMark)) {
		t.Fatal("deferred after download: must not commit")
	}
}

func TestCheckRefusals(t *testing.T) {
	ca, rogue := newCA(t, "CA"), newCA(t, "rogue")
	zipBytes, good := bundle(t, ca, "v0.14.0", goodEntries())
	traversal := map[string]string{"install.ps1": "x", "../evil.ps1": "x"}
	travZip, travInfo := bundle(t, ca, "v0.14.0", traversal)
	absolute := map[string]string{"install.ps1": "x", "/etc/evil": "x"}
	absZip, absInfo := bundle(t, ca, "v0.14.0", absolute)
	noScript := map[string]string{"rostor-deputy.exe": "x"}
	nsZip, nsInfo := bundle(t, ca, "v0.14.0", noScript)

	cases := []struct {
		name string
		info Info
		zip  []byte
		want string
	}{
		{"size mismatch", func() Info { i := good; i.Size++; return i }(), zipBytes, "size is"},
		{"sha mismatch", func() Info { i := good; i.SHA256 = strings.Repeat("a", 64); return i }(), zipBytes, "sha256 is"},
		{"bad signature", func() Info { i := good; i.Signature = base64.StdEncoding.EncodeToString([]byte("nope")); return i }(), zipBytes, "signature"},
		{"wrong CA", rogue.sign(t, good), zipBytes, "signature"},
		{"tampered zip", good, append(append([]byte{}, zipBytes[:len(zipBytes)-1]...), zipBytes[len(zipBytes)-1]^1), "sha256 is"},
		{"version is a path", func() Info { i := good; i.Version = "../x"; return i }(), zipBytes, "not a usable name"},
		{"zip with ../", travInfo, travZip, "escapes"},
		{"zip with absolute path", absInfo, absZip, "unsafe path"},
		{"zip without install.ps1", nsInfo, nsZip, "has no install.ps1"},
		{"download fails", good, nil, "download"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client := &fakeClient{info: &tc.info, zip: tc.zip}
			if tc.zip == nil {
				client.bundleErr = errors.New("connection reset")
			}
			inst := &fakeInstaller{}
			c, logs := newCoordinator(t, ca, client, inst, "v0.13.0")
			if err := c.Check(context.Background()); err != nil {
				t.Fatalf("refusals are logged, not returned: %v", err)
			}
			if inst.calls() != 0 {
				t.Fatal("installer must not be called")
			}
			if exists(filepath.Join(c.Dir, "pending.json")) {
				t.Fatal("pending.json must not be written")
			}
			if exists(filepath.Join(c.Dir, tc.info.Version, AttemptedMark)) {
				t.Fatal("attempted marker must not be written")
			}
			if !strings.Contains(logs.String(), "refused") || !strings.Contains(logs.String(), tc.want) {
				t.Errorf("log lacks refusal %q:\n%s", tc.want, logs.String())
			}
			// Nothing escaped the bundle directory.
			if exists(filepath.Join(c.Dir, "evil.ps1")) || exists(filepath.Join(filepath.Dir(c.Dir), "evil.ps1")) {
				t.Fatal("traversal entry was written")
			}
		})
	}
}

func TestCheckInstallerFailsToStart(t *testing.T) {
	ca := newCA(t, "CA")
	zipBytes, info := bundle(t, ca, "v0.14.0", goodEntries())
	client := &fakeClient{info: &info, zip: zipBytes}
	inst := &fakeInstaller{err: errors.New("powershell.exe not found")}
	c, _ := newCoordinator(t, ca, client, inst, "v0.13.0")
	if err := c.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Reported as failed right away by this deputy, and not retried.
	if len(client.reports) != 1 || client.reports[0].Status != core.RunFailed || client.reports[0].Version != "v0.14.0" ||
		client.reports[0].FromVersion != "v0.13.0" || !strings.Contains(client.reports[0].OutputTail, "powershell.exe not found") {
		t.Fatalf("reports: %+v", client.reports)
	}
	if exists(filepath.Join(c.Dir, "pending.json")) {
		t.Fatal("pending.json must be removed after the failure report")
	}
	if !exists(filepath.Join(c.Dir, "v0.14.0", AttemptedMark)) {
		t.Fatal("attempted marker must stay")
	}
	if err := c.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	if inst.calls() != 1 {
		t.Fatalf("retried after a failed start: %d calls", inst.calls())
	}
}

// ---- ReportPending -------------------------------------------------------------

func writePending(t *testing.T, c *Coordinator, version, from string) {
	t.Helper()
	if err := SavePending(filepath.Join(c.Dir, "pending.json"), Pending{Version: version, StartedAt: c.Now(), FromVersion: from}); err != nil {
		t.Fatal(err)
	}
}

func TestReportPendingOK(t *testing.T) {
	ca := newCA(t, "CA")
	client := &fakeClient{}
	c, logs := newCoordinator(t, ca, client, &fakeInstaller{}, "v0.14.0")
	writePending(t, c, "v0.14.0", "v0.13.0")
	logDir := filepath.Join(c.Dir, "v0.14.0")
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// A log longer than the tail: only its end is reported.
	big := strings.Repeat("x", TailBytes) + "service RostorDeputy is Running\n"
	if err := os.WriteFile(filepath.Join(logDir, InstallLog), []byte(big), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := c.ReportPending(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(client.reports) != 1 {
		t.Fatalf("reports: %+v", client.reports)
	}
	r := client.reports[0]
	if r.Version != "v0.14.0" || r.Status != core.RunOK || r.FromVersion != "v0.13.0" {
		t.Fatalf("report: %+v", r)
	}
	if len(r.OutputTail) != TailBytes || !strings.HasSuffix(r.OutputTail, "is Running\n") {
		t.Fatalf("tail: len %d, end %q", len(r.OutputTail), r.OutputTail[len(r.OutputTail)-20:])
	}
	if exists(filepath.Join(c.Dir, "pending.json")) {
		t.Fatal("pending.json must be removed after a successful report")
	}
	if !strings.Contains(logs.String(), "reported ok") {
		t.Errorf("log:\n%s", logs.String())
	}
	// A second call has nothing to report.
	if err := c.ReportPending(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(client.reports) != 1 {
		t.Fatal("reported twice")
	}
}

func TestReportPendingFailed(t *testing.T) {
	ca := newCA(t, "CA")
	client := &fakeClient{}
	// The old deputy came back up: it is v0.13.0 and pending says v0.14.0.
	c, _ := newCoordinator(t, ca, client, &fakeInstaller{}, "v0.13.0")
	writePending(t, c, "v0.14.0", "v0.13.0")
	// No install.log at all: the tail is simply empty.
	if err := c.ReportPending(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(client.reports) != 1 || client.reports[0].Status != core.RunFailed || client.reports[0].OutputTail != "" {
		t.Fatalf("reports: %+v", client.reports)
	}
	if exists(filepath.Join(c.Dir, "pending.json")) {
		t.Fatal("pending.json must be removed after the report")
	}
}

func TestReportPendingKeptWhenReportFails(t *testing.T) {
	ca := newCA(t, "CA")
	client := &fakeClient{reportErr: errors.New("core unreachable")}
	c, _ := newCoordinator(t, ca, client, &fakeInstaller{}, "v0.14.0")
	writePending(t, c, "v0.14.0", "v0.13.0")
	if err := c.ReportPending(context.Background()); err == nil {
		t.Fatal("a rejected report must be returned so the heartbeat logs it")
	}
	if !exists(filepath.Join(c.Dir, "pending.json")) {
		t.Fatal("pending.json must be kept for the next start")
	}
	// Core is back: the retry reports and clears.
	client.reportErr = nil
	if err := c.ReportPending(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(client.reports) != 1 || exists(filepath.Join(c.Dir, "pending.json")) {
		t.Fatalf("retry: reports %+v", client.reports)
	}
}

func TestReportPendingCleansOldBundles(t *testing.T) {
	ca := newCA(t, "CA")
	client := &fakeClient{}
	c, _ := newCoordinator(t, ca, client, &fakeInstaller{}, "v0.14.0")
	writePending(t, c, "v0.14.0", "v0.13.0")
	mk := func(version string) {
		dir := filepath.Join(c.Dir, version)
		for _, name := range []string{BundleName, "install.ps1", "rostor-deputy.exe", InstallLog, AttemptedMark} {
			if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	mk("v0.12.0")
	mk("v0.13.0")
	mk("v0.14.0")
	if err := c.ReportPending(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, old := range []string{"v0.12.0", "v0.13.0"} {
		dir := filepath.Join(c.Dir, old)
		for _, gone := range []string{BundleName, "install.ps1", "rostor-deputy.exe", "sub"} {
			if exists(filepath.Join(dir, gone)) {
				t.Errorf("%s/%s should have been removed", old, gone)
			}
		}
		for _, kept := range []string{InstallLog, AttemptedMark} {
			if !exists(filepath.Join(dir, kept)) {
				t.Errorf("%s/%s should have been kept", old, kept)
			}
		}
	}
	// The running (and just-pending) version keeps everything.
	for _, name := range []string{BundleName, "install.ps1", InstallLog, AttemptedMark} {
		if !exists(filepath.Join(c.Dir, "v0.14.0", name)) {
			t.Errorf("v0.14.0/%s should have been kept", name)
		}
	}
	// pending.json is not a version directory and is untouched by cleanup;
	// it was removed by the report itself.
	if exists(filepath.Join(c.Dir, "pending.json")) {
		t.Fatal("pending.json still present")
	}
}

// ---- extract -------------------------------------------------------------------

func TestSafeTarget(t *testing.T) {
	root := filepath.Join(t.TempDir(), "v1")
	ok := []string{"install.ps1", "sub/file.txt", "./a", "sub/", "a/./b"}
	for _, name := range ok {
		if _, err := safeTarget(root, name); err != nil {
			t.Errorf("%q: %v", name, err)
		}
	}
	bad := []string{"", "..", "../x", "a/../../x", "/abs", `C:\x`, `a\b`, "a/b/../../../c"}
	for _, name := range bad {
		if got, err := safeTarget(root, name); err == nil {
			t.Errorf("%q accepted as %s", name, got)
		}
	}
}

func TestReadTail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "install.log")
	if readTail(path, 10) != "" {
		t.Fatal("missing file must read as empty")
	}
	if err := os.WriteFile(path, []byte("0123456789abcdef"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := readTail(path, 6); got != "abcdef" {
		t.Fatalf("tail: %q", got)
	}
	if got := readTail(path, 100); got != "0123456789abcdef" {
		t.Fatalf("whole file: %q", got)
	}
}
