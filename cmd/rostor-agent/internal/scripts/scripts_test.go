package scripts

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
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

	"rostor.org/app/cmd/rostor-agent/internal/core"
)

// ---- a tiny CA that signs scripts the way core does ---------------------------

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

// sign fills Signature exactly as the contract describes.
func (ca *testCA) sign(t *testing.T, s Script) Script {
	t.Helper()
	digest := sha256.Sum256(SignedMessage(s.ID, s.Version, s.Body))
	sig, err := ecdsa.SignASN1(rand.Reader, ca.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	s.Signature = base64.StdEncoding.EncodeToString(sig)
	s.Signer = "cak_test"
	return s
}

func script(id string, version, position int, mode, body string) Script {
	return Script{ID: id, Name: "Script " + id, Language: "powershell", Version: version, Position: position, Mode: mode, Body: body}
}

// ---- Verify --------------------------------------------------------------------

func TestVerify(t *testing.T) {
	ca, other := newCA(t, "CA"), newCA(t, "other")
	s := ca.sign(t, script("scr_1", 3, 10, "immediate", "Write-Host 'héllo'\r\n"))
	if err := Verify(s, ca.pem); err != nil {
		t.Fatalf("good signature: %v", err)
	}
	// Any CA in the bundle may be the signer (rotation window).
	if err := Verify(s, append(append([]byte{}, other.pem...), ca.pem...)); err != nil {
		t.Fatalf("bundle with two CAs: %v", err)
	}

	tamper := func(name string, f func(*Script)) {
		t.Helper()
		x := s
		f(&x)
		if err := Verify(x, ca.pem); !errors.Is(err, ErrSignature) {
			t.Errorf("%s: want ErrSignature, got %v", name, err)
		}
	}
	tamper("body changed", func(x *Script) { x.Body += "Remove-Item C:\\ -Recurse\r\n" })
	tamper("version changed", func(x *Script) { x.Version++ })
	tamper("id changed", func(x *Script) { x.ID = "scr_2" })
	tamper("empty signature", func(x *Script) { x.Signature = "" })
	tamper("not base64", func(x *Script) { x.Signature = "***" })
	tamper("garbage DER", func(x *Script) { x.Signature = base64.StdEncoding.EncodeToString([]byte("nope")) })

	if err := Verify(s, other.pem); !errors.Is(err, ErrSignature) {
		t.Errorf("wrong CA: want ErrSignature, got %v", err)
	}
	if err := Verify(s, nil); !errors.Is(err, ErrNoCA) {
		t.Errorf("no bundle: want ErrNoCA, got %v", err)
	}
	if err := Verify(s, []byte("not pem")); !errors.Is(err, ErrNoCA) {
		t.Errorf("bad bundle: want ErrNoCA, got %v", err)
	}
	// Name and position are not signed: the admin may reorder or rename
	// without the core re-signing every body.
	x := s
	x.Name, x.Position = "renamed", 99
	if err := Verify(x, ca.pem); err != nil {
		t.Errorf("rename/reorder must still verify: %v", err)
	}
}

func TestSignedMessage(t *testing.T) {
	if got := string(SignedMessage("scr_1", 12, "body")); got != "scr_1\n12\nbody" {
		t.Fatalf("got %q", got)
	}
}

// ---- Plan ----------------------------------------------------------------------

func TestPlanOrderAndOncePerVersion(t *testing.T) {
	st := &State{entries: map[string]Entry{"b": {ImmediateVersionRan: 2}, "d": {ImmediateVersionRan: 5}}}
	list := []Script{
		script("c", 1, 30, "immediate", ""),
		script("a", 1, 10, "immediate", ""),
		script("b", 3, 20, "immediate", ""), // newer than what ran
		script("d", 5, 5, "immediate", ""),  // already ran at this version
		script("e", 1, 10, "immediate", ""), // same position as a: id breaks the tie
		script("z", 1, 1, "signin", ""),     // wrong mode
		script("a", 1, 10, "immediate", ""), // duplicate entry
	}
	got := ids(Plan(list, st))
	if strings.Join(got, ",") != "a,e,b,c" {
		t.Fatalf("plan order: %v", got)
	}
	// Older version than recorded (core rolled back) is not rerun either.
	st.entries["b"] = Entry{ImmediateVersionRan: 4}
	if got := ids(Plan(list, st)); strings.Join(got, ",") != "a,e,c" {
		t.Fatalf("after rollback: %v", got)
	}
}

func TestPlanSignin(t *testing.T) {
	list := []Script{
		script("y", 1, 20, "signin", ""),
		script("x", 1, 10, "immediate", ""),
		script("w", 1, 10, "signin", ""),
		script("w", 1, 10, "signin", ""),
		script("v", 1, 10, "signin", ""),
	}
	if got := ids(PlanSignin(list)); strings.Join(got, ",") != "v,w,y" {
		t.Fatalf("signin order: %v", got)
	}
	if got := PlanSignin(nil); len(got) != 0 {
		t.Fatalf("empty: %v", got)
	}
}

func ids(list []Script) []string {
	var out []string
	for _, s := range list {
		out = append(out, s.ID)
	}
	return out
}

// ---- State ---------------------------------------------------------------------

func TestStateRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "scripts.json")
	st, err := LoadState(path)
	if err != nil {
		t.Fatal(err)
	}
	if e := st.Get("scr_1"); e.ImmediateVersionRan != 0 || !e.LastSigninAt.IsZero() {
		t.Fatalf("fresh state: %+v", e)
	}
	when := time.Date(2026, 9, 25, 10, 0, 0, 0, time.UTC)
	if err := st.MarkImmediate("scr_1", 3); err != nil {
		t.Fatal(err)
	}
	if err := st.MarkSignin("scr_2", when); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path + ".tmp"); err == nil {
		t.Fatal("temp file left behind")
	}
	b, _ := os.ReadFile(path)
	if !strings.Contains(string(b), `"immediate_version_ran": 3`) || !strings.Contains(string(b), `"last_signin_at": "2026-09-25T10:00:00Z"`) {
		t.Fatalf("file:\n%s", b)
	}
	// A script that only ever ran as immediate has no sign-in stamp on disk.
	if strings.Count(string(b), "last_signin_at") != 1 {
		t.Fatalf("zero stamps should be omitted:\n%s", b)
	}

	again, err := LoadState(path)
	if err != nil {
		t.Fatal(err)
	}
	if e := again.Get("scr_1"); e.ImmediateVersionRan != 3 {
		t.Fatalf("scr_1: %+v", e)
	}
	if e := again.Get("scr_2"); !e.LastSigninAt.Equal(when) || e.ImmediateVersionRan != 0 {
		t.Fatalf("scr_2: %+v", e)
	}
}

func TestStateErrors(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "scripts.json")
	if err := os.WriteFile(bad, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadState(bad); err == nil {
		t.Fatal("corrupt file must not load as empty state")
	}
	empty := filepath.Join(dir, "empty.json")
	if err := os.WriteFile(empty, []byte("  \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if st, err := LoadState(empty); err != nil || st.Get("x").ImmediateVersionRan != 0 {
		t.Fatalf("blank file should be empty state: %v", err)
	}
	// Unreadable (a directory in place of the file).
	if _, err := LoadState(dir); err == nil {
		t.Fatal("directory should fail to load")
	}
	// Unsaveable: the parent is a file, so MkdirAll fails.
	st := &State{path: filepath.Join(bad, "x", "scripts.json"), entries: map[string]Entry{}}
	if err := st.MarkImmediate("a", 1); err == nil {
		t.Fatal("save under a file should fail")
	}
}

// ---- Runner --------------------------------------------------------------------

// fakeExec records what it was given and behaves per its fields.
type fakeExec struct {
	mu       sync.Mutex
	paths    []string
	contents [][]byte
	envs     [][]string
	output   string
	exit     int
	startErr error
	block    bool // wait for ctx to end, as a hung script would
}

func (f *fakeExec) run(ctx context.Context, path string, env []string, out io.Writer) (int, error) {
	f.mu.Lock()
	b, _ := os.ReadFile(path)
	f.paths = append(f.paths, path)
	f.contents = append(f.contents, b)
	f.envs = append(f.envs, env)
	f.mu.Unlock()
	if f.startErr != nil {
		return -1, f.startErr
	}
	io.WriteString(out, f.output)
	if f.block {
		<-ctx.Done()
		return -1, ctx.Err()
	}
	return f.exit, nil
}

func newRunner(t *testing.T, f *fakeExec) *Runner {
	t.Helper()
	return &Runner{Exec: f.run, Dir: filepath.Join(t.TempDir(), "stage"), Environ: func() []string { return []string{"PATH=/bin", "rostor_user=stale"} }}
}

func TestRunnerOK(t *testing.T) {
	f := &fakeExec{output: "hello\n"}
	r := newRunner(t, f)
	s := script("scr_1", 2, 1, "signin", "Write-Host 'hi'")
	rep := r.Run(context.Background(), s, map[string]string{"ROSTOR_USER": "dan"})
	if rep.Status != core.RunOK || rep.ExitCode != 0 || rep.OutputTail != "hello\n" || rep.Version != 2 || rep.Mode != "signin" {
		t.Fatalf("report: %+v", rep)
	}
	if rep.StartedAt.IsZero() || rep.FinishedAt.Before(rep.StartedAt) {
		t.Fatalf("timestamps: %+v", rep)
	}
	if len(f.paths) != 1 || !strings.HasSuffix(f.paths[0], ".ps1") || !strings.HasPrefix(f.paths[0], r.Dir) {
		t.Fatalf("staged path: %v", f.paths)
	}
	if want := append([]byte("\xEF\xBB\xBF"), "Write-Host 'hi'"...); !bytes.Equal(f.contents[0], want) {
		t.Fatalf("staged content %q", f.contents[0])
	}
	if _, err := os.Stat(f.paths[0]); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("staged file not removed")
	}
	// Environment: base kept, same-name (case-insensitive) base entry
	// replaced, extras appended.
	if got := strings.Join(f.envs[0], " "); got != "PATH=/bin ROSTOR_USER=dan" {
		t.Fatalf("env: %q", got)
	}
}

func TestRunnerFailedExit(t *testing.T) {
	f := &fakeExec{output: "boom", exit: 7}
	rep := newRunner(t, f).Run(context.Background(), script("s", 1, 1, "immediate", ""), nil)
	if rep.Status != core.RunFailed || rep.ExitCode != 7 || rep.OutputTail != "boom" {
		t.Fatalf("report: %+v", rep)
	}
}

func TestRunnerStartError(t *testing.T) {
	f := &fakeExec{startErr: errors.New("could not start powershell: file not found")}
	rep := newRunner(t, f).Run(context.Background(), script("s", 1, 1, "immediate", ""), nil)
	if rep.Status != core.RunError || rep.ExitCode != -1 || !strings.Contains(rep.OutputTail, "not found") {
		t.Fatalf("report: %+v", rep)
	}
	if _, err := os.Stat(f.paths[0]); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("staged file not removed after start failure")
	}
}

func TestRunnerTimeout(t *testing.T) {
	f := &fakeExec{output: "partial", block: true}
	r := newRunner(t, f)
	r.Timeout = 30 * time.Millisecond
	rep := r.Run(context.Background(), script("s", 1, 1, "immediate", ""), nil)
	if rep.Status != core.RunTimeout || rep.ExitCode != -1 || rep.OutputTail != "partial" {
		t.Fatalf("report: %+v", rep)
	}
	if rep.FinishedAt.Sub(rep.StartedAt) < 30*time.Millisecond {
		t.Fatalf("finished too early: %+v", rep)
	}
}

func TestRunnerCancelledIsTimeout(t *testing.T) {
	f := &fakeExec{block: true}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(10 * time.Millisecond); cancel() }()
	rep := newRunner(t, f).Run(ctx, script("s", 1, 1, "immediate", ""), nil)
	if rep.Status != core.RunTimeout || rep.ExitCode != -1 {
		t.Fatalf("report: %+v", rep)
	}
}

func TestRunnerOutputTail(t *testing.T) {
	big := strings.Repeat("0123456789", 1000) // 10,000 bytes
	f := &fakeExec{output: big}
	rep := newRunner(t, f).Run(context.Background(), script("s", 1, 1, "immediate", ""), nil)
	if len(rep.OutputTail) != TailBytes || rep.OutputTail != big[len(big)-TailBytes:] {
		t.Fatalf("tail len %d, wrong content", len(rep.OutputTail))
	}
}

func TestTailWriterChunks(t *testing.T) {
	w := &tailWriter{max: 8}
	for _, chunk := range []string{"abc", "def", "ghi", "j"} {
		w.Write([]byte(chunk))
	}
	if w.String() != "cdefghij" {
		t.Fatalf("got %q", w.String())
	}
	w.Write([]byte("0123456789ABCDEF"))
	if w.String() != "89ABCDEF" {
		t.Fatalf("got %q", w.String())
	}
}

func TestRunnerStageFailure(t *testing.T) {
	f := &fakeExec{}
	r := newRunner(t, f)
	// A file where the staging directory should be.
	r.Dir = filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(r.Dir, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	rep := r.Run(context.Background(), script("s", 1, 1, "immediate", ""), nil)
	if rep.Status != core.RunError || rep.ExitCode != -1 || !strings.HasPrefix(rep.OutputTail, "stage:") {
		t.Fatalf("report: %+v", rep)
	}
	if len(f.paths) != 0 {
		t.Fatal("executor must not run without a staged file")
	}
}

func TestRunnerDefaultExecutorOffWindows(t *testing.T) {
	r := &Runner{Dir: t.TempDir()}
	rep := r.Run(context.Background(), script("s", 1, 1, "immediate", ""), nil)
	// On Windows the real executor would try to start powershell; the
	// stub elsewhere reports a start error. Either way the report is
	// well-formed.
	if rep.Status != core.RunError && rep.Status != core.RunOK && rep.Status != core.RunFailed {
		t.Fatalf("report: %+v", rep)
	}
}

// ---- Coordinator -----------------------------------------------------------------

type fakeClient struct {
	mu        sync.Mutex
	scripts   []Script
	fetchErr  error
	reports   []report
	fetches   int
	reportErr error
}

type report struct {
	id  string
	run Run
}

func (c *fakeClient) Scripts(_ context.Context) ([]core.Script, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.fetches++
	return append([]Script{}, c.scripts...), c.fetchErr
}

func (c *fakeClient) ReportRun(_ context.Context, id string, run core.ScriptRun) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reports = append(c.reports, report{id, run})
	return c.reportErr
}

func (c *fakeClient) reported() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []string
	for _, r := range c.reports {
		out = append(out, r.id+":"+r.run.Mode+":"+r.run.Status)
	}
	return out
}

func newCoordinator(t *testing.T, ca *testCA, client *fakeClient, f *fakeExec) (*Coordinator, *bytes.Buffer) {
	t.Helper()
	dir := t.TempDir()
	caFile := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(caFile, ca.pem, 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := LoadState(filepath.Join(dir, "scripts.json"))
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	return &Coordinator{
		Client: client, CAFile: caFile, State: st, Runner: newRunner(t, f),
		Logger: log.New(&logs, "", 0),
	}, &logs
}

func TestCoordinatorRunDue(t *testing.T) {
	ca, rogue := newCA(t, "CA"), newCA(t, "rogue")
	tampered := ca.sign(t, script("scr_bad", 1, 0, "immediate", "good"))
	tampered.Body = "evil"
	client := &fakeClient{scripts: []Script{
		ca.sign(t, script("scr_c", 2, 30, "immediate", "c")),
		ca.sign(t, script("scr_a", 1, 10, "immediate", "a")),
		tampered,
		rogue.sign(t, script("scr_rogue", 1, 0, "immediate", "rogue")),
		ca.sign(t, script("scr_s", 1, 5, "signin", "s")),
		ca.sign(t, script("scr_b", 4, 20, "immediate", "b")),
	}}
	f := &fakeExec{output: "done"}
	coord, logs := newCoordinator(t, ca, client, f)

	if err := coord.RunDue(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := client.reported(); strings.Join(got, " ") != "scr_a:immediate:ok scr_b:immediate:ok scr_c:immediate:ok" {
		t.Fatalf("reports: %v", got)
	}
	// Bodies ran in position order; the tampered, rogue and sign-in ones
	// never touched the runner.
	var bodies []string
	for _, c := range f.contents {
		bodies = append(bodies, string(bytes.TrimPrefix(c, []byte("\xEF\xBB\xBF"))))
	}
	if strings.Join(bodies, ",") != "a,b,c" {
		t.Fatalf("ran bodies %v", bodies)
	}
	for _, id := range []string{"scr_bad", "scr_rogue"} {
		if !strings.Contains(logs.String(), id+" ") || !strings.Contains(logs.String(), "refused") {
			t.Fatalf("expected refusal of %s in log:\n%s", id, logs.String())
		}
	}
	if e := coord.State.Get("scr_b"); e.ImmediateVersionRan != 4 {
		t.Fatalf("state scr_b: %+v", e)
	}
	if r := client.reports[0].run; r.PrincipalID != "" || r.Version != 1 || r.OutputTail != "done" || r.ExitCode != 0 {
		t.Fatalf("report shape: %+v", r)
	}

	// Second heartbeat: nothing new, nothing runs.
	if err := coord.RunDue(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(client.reports) != 3 || len(f.paths) != 3 {
		t.Fatalf("second pass reran: %d reports, %d runs", len(client.reports), len(f.paths))
	}

	// A new version of scr_a runs again; a script whose run fails is still
	// marked as run at that version.
	client.scripts[1] = ca.sign(t, script("scr_a", 2, 10, "immediate", "a2"))
	f.exit = 3
	if err := coord.RunDue(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := client.reported()[3:]; strings.Join(got, " ") != "scr_a:immediate:failed" {
		t.Fatalf("third pass: %v", got)
	}
	if e := coord.State.Get("scr_a"); e.ImmediateVersionRan != 2 {
		t.Fatalf("failed run must still count: %+v", e)
	}
	if err := coord.RunDue(context.Background()); err != nil || len(client.reports) != 4 {
		t.Fatalf("fourth pass: %v, %d reports", err, len(client.reports))
	}
}

func TestCoordinatorRunSignin(t *testing.T) {
	ca := newCA(t, "CA")
	client := &fakeClient{scripts: []Script{
		ca.sign(t, script("scr_i", 1, 1, "immediate", "i")),
		ca.sign(t, script("scr_2", 1, 20, "signin", "two")),
		ca.sign(t, script("scr_1", 1, 10, "signin", "one")),
	}}
	f := &fakeExec{}
	coord, _ := newCoordinator(t, ca, client, f)
	when := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	coord.Now = func() time.Time { return when }

	for i := 0; i < 2; i++ {
		if err := coord.RunSignin(context.Background(), "dan", "usr_1", "dan"); err != nil {
			t.Fatal(err)
		}
	}
	if got := client.reported(); strings.Join(got, " ") != "scr_1:signin:ok scr_2:signin:ok scr_1:signin:ok scr_2:signin:ok" {
		t.Fatalf("reports: %v", got)
	}
	if r := client.reports[0].run; r.PrincipalID != "usr_1" || r.Mode != "signin" {
		t.Fatalf("report shape: %+v", r)
	}
	env := strings.Join(f.envs[0], " ")
	for _, want := range []string{"ROSTOR_USER=dan", "ROSTOR_PRINCIPAL=usr_1", "ROSTOR_LOCAL_ACCOUNT=dan"} {
		if !strings.Contains(env, want) {
			t.Fatalf("env missing %s: %q", want, env)
		}
	}
	if e := coord.State.Get("scr_1"); !e.LastSigninAt.Equal(when) || e.ImmediateVersionRan != 0 {
		t.Fatalf("state: %+v", e)
	}
	if e := coord.State.Get("scr_i"); e.ImmediateVersionRan != 0 {
		t.Fatal("sign-in must not run immediates")
	}
}

func TestCoordinatorErrors(t *testing.T) {
	ca := newCA(t, "CA")
	f := &fakeExec{}

	// Fetch failure: nothing runs, error returned.
	client := &fakeClient{fetchErr: core.ErrUnreachable}
	coord, _ := newCoordinator(t, ca, client, f)
	if err := coord.RunDue(context.Background()); !errors.Is(err, core.ErrUnreachable) {
		t.Fatalf("fetch error: %v", err)
	}
	if err := coord.RunSignin(context.Background(), "d", "u", "d"); !errors.Is(err, core.ErrUnreachable) {
		t.Fatalf("fetch error at signin: %v", err)
	}

	// Missing bundle: refuse everything, do not even fetch.
	client = &fakeClient{scripts: []Script{ca.sign(t, script("s", 1, 1, "immediate", ""))}}
	coord, _ = newCoordinator(t, ca, client, f)
	os.Remove(coord.CAFile)
	if err := coord.RunDue(context.Background()); err == nil || client.fetches != 0 || len(f.paths) != 0 {
		t.Fatalf("missing bundle: err %v, fetches %d, runs %d", err, client.fetches, len(f.paths))
	}

	// Report failure is logged, the run still counts, the next script still runs.
	client = &fakeClient{reportErr: errors.New("HTTP 500"), scripts: []Script{
		ca.sign(t, script("s1", 1, 1, "immediate", "")),
		ca.sign(t, script("s2", 1, 2, "immediate", "")),
	}}
	coord, logs := newCoordinator(t, ca, client, f)
	if err := coord.RunDue(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(client.reports) != 2 || coord.State.Get("s2").ImmediateVersionRan != 1 || !strings.Contains(logs.String(), "report run: HTTP 500") {
		t.Fatalf("report failure handling: %d reports, log:\n%s", len(client.reports), logs.String())
	}

	// Unsupported language is skipped (logged), not run.
	other := ca.sign(t, Script{ID: "py", Name: "py", Language: "python", Version: 1, Position: 1, Mode: "immediate", Body: "print()"})
	client = &fakeClient{scripts: []Script{other}}
	coord, logs = newCoordinator(t, ca, client, f)
	before := len(f.paths)
	if err := coord.RunDue(context.Background()); err != nil || len(f.paths) != before || !strings.Contains(logs.String(), "not supported") {
		t.Fatalf("language skip: err %v, log:\n%s", err, logs.String())
	}

	// A cancelled context stops between scripts.
	client = &fakeClient{scripts: []Script{
		ca.sign(t, script("s1", 1, 1, "immediate", "")),
		ca.sign(t, script("s2", 1, 2, "immediate", "")),
	}}
	blocking := &fakeExec{block: true}
	coord, _ = newCoordinator(t, ca, client, blocking)
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(20 * time.Millisecond); cancel() }()
	if err := coord.RunDue(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel: %v", err)
	}
	if len(blocking.paths) != 1 || len(client.reports) != 1 || client.reports[0].run.Status != core.RunTimeout {
		t.Fatalf("cancel: %d runs, reports %v", len(blocking.paths), client.reported())
	}
}

// Sign-in and heartbeat runs never overlap: the second caller waits.
func TestCoordinatorSerialises(t *testing.T) {
	ca := newCA(t, "CA")
	client := &fakeClient{scripts: []Script{
		ca.sign(t, script("i", 1, 1, "immediate", "")),
		ca.sign(t, script("s", 1, 1, "signin", "")),
	}}
	f := &fakeExec{}
	var running, maxRunning int
	var mu sync.Mutex
	f2 := &fakeExec{}
	exec := func(ctx context.Context, path string, env []string, out io.Writer) (int, error) {
		mu.Lock()
		running++
		if running > maxRunning {
			maxRunning = running
		}
		mu.Unlock()
		time.Sleep(15 * time.Millisecond)
		mu.Lock()
		running--
		mu.Unlock()
		return f2.run(ctx, path, env, out)
	}
	coord, _ := newCoordinator(t, ca, client, f)
	coord.Runner.Exec = exec
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(2)
		go func() { defer wg.Done(); _ = coord.RunDue(context.Background()) }()
		go func() { defer wg.Done(); _ = coord.RunSignin(context.Background(), "d", "u", "d") }()
	}
	wg.Wait()
	if maxRunning != 1 {
		t.Fatalf("scripts overlapped: max %d", maxRunning)
	}
	// One immediate in total, three sign-in runs.
	if got := client.reported(); len(got) != 4 {
		t.Fatalf("reports: %v", got)
	}
}

var _ Client = core.Mock{}
