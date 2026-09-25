package api_test

// End-to-end acceptance test for the Windows logon slice: the shape of spec
// scenario B.2 with a password in place of a badge. Runs against a real
// Postgres (ROSTOR_TEST_DATABASE_URL), in its own tenant.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"rostor.org/app/internal/api"
	"rostor.org/app/internal/audit"
	"rostor.org/app/internal/auth"
	"rostor.org/app/internal/authz"
	"rostor.org/app/internal/catalog"
	"rostor.org/app/internal/crypto"
	"rostor.org/app/internal/db"
	"rostor.org/app/internal/devices"
	"rostor.org/app/internal/directory"
	"rostor.org/app/internal/ids"
	"rostor.org/app/internal/pki"
)

type harness struct {
	t        *testing.T
	ctx      context.Context
	db       *db.Pool
	srv      *api.Server
	ts       *httptest.Server
	tenantID string
	admin    string // bearer
	ca       *pki.CA
}

func newHarness(t *testing.T) *harness {
	url := os.Getenv("ROSTOR_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("ROSTOR_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := db.Open(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 32)
	rand.Read(key)
	prov, _ := crypto.NewDefault(key)
	eng, _ := authz.New()
	cat, _ := catalog.Load()
	h := &harness{t: t, ctx: ctx, db: pool, tenantID: ids.New("tnt")}
	dev := &devices.Service{Provider: prov}
	authSvc := auth.NewService(prov, &auth.PasswordMethod{Provider: prov})
	sys := directory.Actor{Kind: "system", ID: "test", CorrelationID: ids.New("corr")}
	err = pool.Tx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO tenants (id, name) VALUES ($1,$2)`, h.tenantID, "test-"+h.tenantID); err != nil {
			return err
		}
		h.ca, err = dev.EnsureCA(ctx, tx, h.tenantID, "test")
		if err != nil {
			return err
		}
		must := func(err error) {
			if err != nil {
				t.Fatal(err)
			}
		}
		must(directory.EnsureBuiltins(ctx, tx, h.tenantID, eng))
		admin, err := directory.CreatePrincipal(ctx, tx, h.tenantID, sys, directory.Principal{Kind: "service", Username: "admin"})
		must(err)
		_, err = directory.CreateGrant(ctx, tx, h.tenantID, sys, directory.Grant{SubjectKind: "principal", SubjectID: admin.ID, Role: "admin", ResourceType: "directory", ResourceID: "root"}, eng)
		must(err)
		h.admin, err = authSvc.MintAPIToken(ctx, tx, h.tenantID, sys, admin.ID, "test", 0)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	wa := &auth.WebAuthnMethod{}
	authSvc = auth.NewService(prov, &auth.PasswordMethod{Provider: prov}, &auth.BadgeMethod{Provider: prov}, wa)
	h.srv = &api.Server{DB: pool, Auth: authSvc, Authz: eng, Devices: dev, Catalog: cat, CA: h.ca, TenantID: h.tenantID,
		Log: slog.New(slog.NewTextHandler(testLog(), nil)), Events: api.NewBroadcaster(), Started: time.Now(), Version: "test"}
	wa.Settings = h.srv.RelyingParty
	certPEM, keyPEM, err := h.ca.IssueServer([]string{"127.0.0.1"}, 3600e9)
	if err != nil {
		t.Fatal(err)
	}
	tlsCfg, err := h.srv.TLSConfig(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	h.ts = httptest.NewUnstartedServer(h.srv.Handler())
	h.ts.TLS = tlsCfg
	h.ts.StartTLS()
	t.Cleanup(func() { h.ts.Close(); pool.Close() })
	return h
}

func (h *harness) client(cert *tls.Certificate) *http.Client {
	pool := x509.NewCertPool()
	pool.AddCert(h.ca.Cert)
	cfg := &tls.Config{RootCAs: pool}
	if cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}}
}

func (h *harness) call(c *http.Client, method, path, bearer string, body any) (int, map[string]any) {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, h.ts.URL+path, rd)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := c.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	out := map[string]any{}
	raw, _ := io.ReadAll(resp.Body)
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &out)
	}
	return resp.StatusCode, out
}

func (h *harness) adminCall(method, path string, body any) map[string]any {
	st, out := h.call(h.client(nil), method, path, h.admin, body)
	if st >= 300 {
		h.t.Fatalf("%s %s: %d %v", method, path, st, out)
	}
	return out
}

func csr(t *testing.T) (*ecdsa.PrivateKey, string) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "ignored"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return key, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

func TestWindowsLogonSlice(t *testing.T) {
	h := newHarness(t)

	// Admin sets up a member with a password, a group, and a group grant on
	// the parent of all workstations.
	h.adminCall("POST", "/v1/admin/users", map[string]any{"username": "dana", "display_name": map[string]string{"en": "Dana"}})
	h.adminCall("POST", "/v1/admin/users/dana/bindings", map[string]any{"method": "password", "fields": map[string]string{"password": "hunter2hunter2"}})
	h.adminCall("POST", "/v1/admin/groups", map[string]any{"name": "members"})
	h.adminCall("POST", "/v1/admin/groups/members/members", map[string]any{"member_kind": "principal", "member": "dana"})
	h.adminCall("POST", "/v1/admin/grants", map[string]any{"subject_kind": "group", "subject": "members", "role": "user", "resource_type": "workstations", "resource_id": "all"})
	tok := h.adminCall("POST", "/v1/admin/enrollment-tokens", map[string]any{"resource_type": "workstation"})["enrollment_token"].(string)

	// Device enrolls with a CSR; gets a client certificate.
	key, csrPEM := csr(t)
	st, out := h.call(h.client(nil), "POST", "/v1/devices/enroll", "", map[string]any{"enrollment_token": tok, "csr_pem": csrPEM,
		"posture": map[string]any{"os": "windows", "hostname": "WS-TEST"}})
	if st != 201 {
		t.Fatalf("enroll: %d %v", st, out)
	}
	certBlock, _ := pem.Decode([]byte(out["certificate_pem"].(string)))
	keyDER, _ := x509.MarshalECPrivateKey(key)
	cert, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBlock.Bytes}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	if err != nil {
		t.Fatal(err)
	}
	// Token is single-use.
	if st, _ := h.call(h.client(nil), "POST", "/v1/devices/enroll", "", map[string]any{"enrollment_token": tok, "csr_pem": csrPEM,
		"posture": map[string]any{"hostname": "WS-TEST"}}); st != 401 {
		t.Fatalf("token reuse should be 401, got %d", st)
	}

	dev := h.client(&cert)
	verify := func(identifier, secret string) map[string]any {
		st, out := h.call(dev, "POST", "/v1/verify", "", map[string]any{
			"credential": map[string]string{"type": "password", "identifier": identifier, "secret": secret},
			"action":     "logon", "resource": map[string]string{"type": "workstation", "id": "WS-TEST"}})
		if st != 200 {
			t.Fatalf("verify: %d %v", st, out)
		}
		return out
	}
	code := func(out map[string]any) string {
		return out["reason"].([]any)[0].(map[string]any)["code"].(string)
	}

	// No client cert → unauthorized.
	if st, _ := h.call(h.client(nil), "POST", "/v1/verify", "", map[string]any{"credential": map[string]string{"type": "password"}}); st != 401 {
		t.Fatalf("verify without cert should be 401, got %d", st)
	}
	// Right password → ALLOW with session and AL1.
	out = verify("dana", "hunter2hunter2")
	if out["decision"] != "ALLOW" || out["assurance"] != "AL1" || out["session"] == nil {
		t.Fatalf("expected ALLOW: %v", out)
	}
	if out["principal"].(map[string]any)["username"] != "dana" {
		t.Fatalf("principal: %v", out["principal"])
	}
	// Wrong password and unknown user → same code.
	if c := code(verify("dana", "nope")); c != "auth.failed" {
		t.Fatalf("wrong password: %s", c)
	}
	if c := code(verify("nobody", "nope")); c != "auth.failed" {
		t.Fatalf("unknown user: %s", c)
	}
	// Suspension beats everything (§3.2).
	h.adminCall("POST", "/v1/admin/users/dana/state", map[string]any{"state": "suspended"})
	if c := code(verify("dana", "hunter2hunter2")); c != "principal.suspended" {
		t.Fatalf("suspended: %s", c)
	}
	h.adminCall("POST", "/v1/admin/users/dana/state", map[string]any{"state": "active"})
	// Removing group membership → grant.none.
	h.adminCall("DELETE", "/v1/admin/groups/members/members", map[string]any{"member_kind": "principal", "member": "dana"})
	if c := code(verify("dana", "hunter2hunter2")); c != "grant.none" {
		t.Fatalf("no grant: %s", c)
	}
	h.adminCall("POST", "/v1/admin/groups/members/members", map[string]any{"member_kind": "principal", "member": "dana"})
	// Cross-method lockout after 5 failures.
	for i := 0; i < 5; i++ {
		verify("dana", "wrong")
	}
	if c := code(verify("dana", "hunter2hunter2")); c != "auth.locked" {
		t.Fatalf("lockout: %s", c)
	}
	// A device may not verify against a resource it is not bound to.
	st, out = h.call(dev, "POST", "/v1/verify", "", map[string]any{
		"credential": map[string]string{"type": "password", "identifier": "dana", "secret": "x"},
		"action":     "logon", "resource": map[string]string{"type": "workstation", "id": "OTHER"}})
	if st != 200 || code(out) != "request.forbidden" {
		t.Fatalf("unbound resource: %d %v", st, out)
	}
	// Why explains the derivation.
	why := h.adminCall("GET", "/v1/admin/why?principal=dana&action=logon&resource_type=workstation&resource_id=WS-TEST", nil)
	if why["decision"] != "ALLOW" || len(why["candidates"].([]any)) != 1 {
		t.Fatalf("why: %v", why)
	}
	// Why for a suspended person still has a constant shape (empty lists, not null).
	h.adminCall("POST", "/v1/admin/users/dana/state", map[string]any{"state": "suspended"})
	whyS := h.adminCall("GET", "/v1/admin/why?principal=dana&action=logon&resource_type=workstation&resource_id=WS-TEST", nil)
	if c, ok := whyS["candidates"].([]any); !ok || len(c) != 0 || whyS["groups"] == nil {
		t.Fatalf("why (suspended) shape: %v", whyS)
	}
	h.adminCall("POST", "/v1/admin/users/dana/state", map[string]any{"state": "active"})
	// Audit chain intact and every emitted code renderable.
	if bad, err := audit.VerifyChain(h.ctx, h.db, h.tenantID); err != nil || bad != 0 {
		t.Fatalf("audit chain: bad=%d err=%v", bad, err)
	}
	for _, c := range []string{"auth.failed", "auth.locked", "principal.suspended", "grant.none", "request.forbidden", "grant.matched"} {
		if !h.srv.Catalog.Has(c) {
			t.Fatalf("catalog missing %s", c)
		}
	}
}

func TestConsoleSessionAndReads(t *testing.T) {
	h := newHarness(t)
	h.adminCall("POST", "/v1/admin/users", map[string]any{"username": "dan", "display_name": map[string]string{"en": "Dan"}})
	h.adminCall("POST", "/v1/admin/users/dan/bindings", map[string]any{"method": "password", "fields": map[string]string{"password": "hunter2hunter2"}})
	h.adminCall("POST", "/v1/admin/grants", map[string]any{"subject_kind": "principal", "subject": "dan", "role": "admin", "resource_type": "directory", "resource_id": "root"})

	c := h.client(nil)
	jar := map[string]string{}
	do := func(method, path string, body any, csrf bool) (int, map[string]any, []*http.Cookie) {
		var rd io.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			rd = bytes.NewReader(b)
		}
		req, _ := http.NewRequest(method, h.ts.URL+path, rd)
		if v, ok := jar["rostor_session"]; ok {
			req.AddCookie(&http.Cookie{Name: "rostor_session", Value: v})
		}
		if csrf {
			req.Header.Set("X-Requested-With", "rostor-console")
		}
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		out := map[string]any{}
		raw, _ := io.ReadAll(resp.Body)
		if len(raw) > 0 && raw[0] == '{' {
			_ = json.Unmarshal(raw, &out)
		}
		for _, ck := range resp.Cookies() {
			jar[ck.Name] = ck.Value
		}
		return resp.StatusCode, out, resp.Cookies()
	}
	// No session → 401.
	if st, _, _ := do("GET", "/v1/auth/session", nil, false); st != 401 {
		t.Fatalf("session without cookie: %d", st)
	}
	// Wrong password → 200 with auth.failed, no cookie.
	if _, out, cks := do("POST", "/v1/auth/login", map[string]any{"identifier": "dan", "fields": map[string]string{"password": "nope"}}, false); out["code"] != "auth.failed" || len(cks) != 0 {
		t.Fatalf("bad login: %v %v", out, cks)
	}
	// Right password → session cookie and permissions.
	st, out, cks := do("POST", "/v1/auth/login", map[string]any{"identifier": "dan", "fields": map[string]string{"password": "hunter2hunter2"}}, false)
	if st != 200 || len(cks) == 0 || out["assurance"] != "AL1" {
		t.Fatalf("login: %d %v %v", st, out, cks)
	}
	if perms, _ := out["permissions"].([]any); len(perms) != 1 || perms[0] != "*" {
		t.Fatalf("permissions: %v", out["permissions"])
	}
	// Cookie-authenticated reads work.
	if st, out, _ := do("GET", "/v1/admin/users", nil, false); st != 200 || out["total"].(float64) < 1 {
		t.Fatalf("list users: %d %v", st, out)
	}
	for _, p := range []string{"/v1/admin/summary", "/v1/admin/groups", "/v1/admin/grants", "/v1/admin/devices", "/v1/admin/audit", "/v1/admin/system", "/v1/admin/plugins", "/v1/admin/users/dan", "/v1/catalog", "/v1/brand"} {
		if st, _, _ := do("GET", p, nil, false); st != 200 {
			t.Fatalf("%s: %d", p, st)
		}
	}
	// Cookie mutation without the CSRF marker → 403; with it → ok.
	if st, _, _ := do("POST", "/v1/admin/groups", map[string]any{"name": "csrf"}, false); st != 403 {
		t.Fatalf("csrf missing should be 403, got %d", st)
	}
	if st, _, _ := do("POST", "/v1/admin/groups", map[string]any{"name": "csrf"}, true); st != 201 {
		t.Fatalf("csrf present should be 201, got %d", st)
	}
	// Logout revokes.
	do("POST", "/v1/auth/logout", nil, true)
	if st, _, _ := do("GET", "/v1/auth/session", nil, false); st != 401 {
		t.Fatalf("after logout: %d", st)
	}
	// Suspended people cannot open a session even with the right secret.
	h.adminCall("POST", "/v1/admin/users/dan/state", map[string]any{"state": "suspended"})
	if _, out, _ := do("POST", "/v1/auth/login", map[string]any{"identifier": "dan", "fields": map[string]string{"password": "hunter2hunter2"}}, false); out["code"] != "principal.suspended" {
		t.Fatalf("suspended login: %v", out)
	}
}

func TestEventStream(t *testing.T) {
	h := newHarness(t)
	ctx, cancel := context.WithCancel(h.ctx)
	defer cancel()
	go h.srv.Listen(ctx)
	time.Sleep(300 * time.Millisecond) // let LISTEN attach

	req, _ := http.NewRequestWithContext(ctx, "GET", h.ts.URL+"/v1/events/stream", nil)
	req.Header.Set("Authorization", "Bearer "+h.admin)
	resp, err := h.client(nil).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		t.Fatalf("stream: %d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	got := make(chan string, 16)
	data := make(chan string, 16)
	go func() {
		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
			if line := sc.Text(); strings.HasPrefix(line, "event: ") {
				got <- strings.TrimPrefix(line, "event: ")
			} else if strings.HasPrefix(line, "data: ") {
				data <- strings.TrimPrefix(line, "data: ")
			}
		}
	}()
	// The stream opens with `ready` carrying the serving build, so a tab left
	// open learns about an update from the reconnect alone.
	select {
	case e := <-got:
		if e != "ready" {
			t.Fatalf("first frame should be ready, got %q", e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no ready frame")
	}
	var readyBody map[string]string
	if err := json.Unmarshal([]byte(<-data), &readyBody); err != nil || readyBody["version"] != h.srv.Version {
		t.Fatalf("ready payload: %v (%v)", readyBody, err)
	}
	h.adminCall("POST", "/v1/admin/groups", map[string]any{"name": "live"})
	deadline := time.After(5 * time.Second)
	seen := map[string]bool{}
	for !(seen["group.created"] && seen["audit.appended"]) {
		select {
		case e := <-got:
			seen[e] = true
		case <-deadline:
			t.Fatalf("did not receive live events; saw %v", seen)
		}
	}
}

func TestBadgeCredential(t *testing.T) {
	h := newHarness(t)
	h.adminCall("POST", "/v1/admin/users", map[string]any{"username": "dana", "display_name": map[string]string{"en": "Dana"}})
	h.adminCall("POST", "/v1/admin/groups", map[string]any{"name": "members"})
	h.adminCall("POST", "/v1/admin/groups/members/members", map[string]any{"member_kind": "principal", "member": "dana"})
	h.adminCall("POST", "/v1/admin/grants", map[string]any{"subject_kind": "group", "subject": "members", "role": "user", "resource_type": "workstations", "resource_id": "all"})
	// Register a badge with a PIN from its full UID; the printed and Wiegand forms derive from it.
	h.adminCall("POST", "/v1/admin/users/dana/bindings", map[string]any{"method": "badge", "fields": map[string]string{"uid": "0A00 4A 1F 7E", "pin": "2468"}})
	// The same card cannot be registered to someone else.
	h.adminCall("POST", "/v1/admin/users", map[string]any{"username": "sam"})
	if st, out := h.call(h.client(nil), "POST", "/v1/admin/users/sam/bindings", h.admin, map[string]any{"method": "badge", "fields": map[string]string{"uid": "0a004a1f7e"}}); st != 409 {
		t.Fatalf("duplicate badge should be 409: %d %v", st, out)
	}

	// Device enrols.
	tok := h.adminCall("POST", "/v1/admin/enrollment-tokens", map[string]any{"resource_type": "workstation"})["enrollment_token"].(string)
	key, csrPEM := csr(t)
	st, out := h.call(h.client(nil), "POST", "/v1/devices/enroll", "", map[string]any{"enrollment_token": tok, "csr_pem": csrPEM, "posture": map[string]any{"hostname": "WS-BADGE"}})
	if st != 201 {
		t.Fatalf("enroll: %d %v", st, out)
	}
	certBlock, _ := pem.Decode([]byte(out["certificate_pem"].(string)))
	keyDER, _ := x509.MarshalECPrivateKey(key)
	cert, _ := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBlock.Bytes}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	dev := h.client(&cert)
	verify := func(cred map[string]string) map[string]any {
		_, out := h.call(dev, "POST", "/v1/verify", "", map[string]any{"credential": cred, "action": "logon", "resource": map[string]string{"type": "workstation", "id": "WS-BADGE"}})
		return out
	}
	code := func(out map[string]any) string { return out["reason"].([]any)[0].(map[string]any)["code"].(string) }
	// Tap alone on a PIN-protected badge: CONTINUE, asking for the PIN.
	if out := verify(map[string]string{"type": "badge", "uid": "0a004a1f7e"}); out["decision"] != "CONTINUE" || code(out) != "auth.continue" {
		t.Fatalf("tap without pin: %v", out)
	}
	// Tap by the Wiegand-26 form (a door-style reader) with the PIN → ALLOW at AL2.
	if out := verify(map[string]string{"type": "badge", "facility": "74", "card": "8062", "pin": "2468"}); out["decision"] != "ALLOW" || out["assurance"] != "AL2" {
		t.Fatalf("wiegand + pin: %v", out)
	}
	// Printed number form, wrong PIN → auth.failed.
	if out := verify(map[string]string{"type": "badge", "number": "4857726", "pin": "0000"}); code(out) != "auth.failed" {
		t.Fatalf("wrong pin: %v", out)
	}
	// Unknown card → auth.failed, same as wrong PIN.
	if out := verify(map[string]string{"type": "badge", "uid": "deadbeef00", "pin": "2468"}); code(out) != "auth.failed" {
		t.Fatalf("unknown card: %v", out)
	}
	// Console sign-in by badge needs no identifier.
	st, out = h.call(h.client(nil), "POST", "/v1/auth/login", "", map[string]any{"method": "badge", "fields": map[string]string{"uid": "0a004a1f7e", "pin": "2468"}})
	if st != 200 || out["assurance"] != "AL2" {
		t.Fatalf("badge login: %d %v", st, out)
	}
}

func jsonReq(method, url string, body any) (*http.Request, error) {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, url, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	return req, nil
}

// testLog sends server logs to stderr when ROSTOR_TEST_LOG=1.
func testLog() io.Writer {
	if os.Getenv("ROSTOR_TEST_LOG") == "1" {
		return os.Stderr
	}
	return io.Discard
}

func TestSelfServiceCredentials(t *testing.T) {
	h := newHarness(t)
	h.adminCall("POST", "/v1/admin/users", map[string]any{"username": "dana"})
	h.adminCall("POST", "/v1/admin/users/dana/bindings", map[string]any{"method": "password", "fields": map[string]string{"password": "hunter2hunter2"}})
	h.adminCall("POST", "/v1/admin/users", map[string]any{"username": "sam"})
	c := h.client(nil)
	jar := map[string]string{}
	do := func(method, path string, body any) (int, map[string]any) {
		req, _ := jsonReq(method, h.ts.URL+path, body)
		if v, ok := jar["rostor_session"]; ok {
			req.AddCookie(&http.Cookie{Name: "rostor_session", Value: v})
		}
		req.Header.Set("X-Requested-With", "rostor-console")
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		for _, ck := range resp.Cookies() {
			jar[ck.Name] = ck.Value
		}
		out := map[string]any{}
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}
	do("POST", "/v1/auth/login", map[string]any{"identifier": "dana", "fields": map[string]string{"password": "hunter2hunter2"}})
	// dana holds no admin role at all...
	if st, _ := do("GET", "/v1/admin/users", nil); st != 403 {
		t.Fatalf("non-admin list should be 403, got %d", st)
	}
	// ...but may read her own record and register her own badge.
	if st, _ := do("GET", "/v1/admin/users/dana", nil); st != 200 {
		t.Fatalf("own record: %d", st)
	}
	st, b := do("POST", "/v1/admin/users/dana/bindings", map[string]any{"method": "badge", "fields": map[string]string{"number": "4857726", "pin": "1357"}})
	if st != 201 {
		t.Fatalf("own badge: %d %v", st, b)
	}
	// Not someone else's.
	if st, _ := do("POST", "/v1/admin/users/sam/bindings", map[string]any{"method": "badge", "fields": map[string]string{"number": "1111111"}}); st != 403 {
		t.Fatalf("other's badge should be 403, got %d", st)
	}
	if st, _ := do("GET", "/v1/admin/users/sam", nil); st != 403 {
		t.Fatalf("other's record should be 403, got %d", st)
	}
	// Her last method cannot be removed by herself (badge + password exist now, so
	// removing the badge is fine; then the password is the last one).
	if st, out := do("DELETE", "/v1/admin/users/dana/bindings/"+b["id"].(string), nil); st != 204 {
		t.Fatalf("own revoke (not last): %d %v", st, out)
	}
	var pwID string
	_ = h.db.QueryRow(h.ctx, `SELECT id FROM authenticator_bindings WHERE tenant_id=$1 AND method='password' AND state='active' AND principal_id=(SELECT id FROM principals WHERE tenant_id=$1 AND username='dana')`, h.tenantID).Scan(&pwID)
	if st, out := do("DELETE", "/v1/admin/users/dana/bindings/"+pwID, nil); st != 400 || out["code"] != "binding.last_method" {
		t.Fatalf("last method should be refused: %d %v", st, out)
	}
	// An admin may still remove it (offboarding).
	if st, out := h.call(h.client(nil), "DELETE", "/v1/admin/users/dana/bindings/"+pwID, h.admin, nil); st != 204 {
		t.Fatalf("admin revoke of last method: %d %v", st, out)
	}
	// Re-register a badge so the remaining assertions still hold.
	st, b = do("POST", "/v1/admin/users/dana/bindings", map[string]any{"method": "badge", "fields": map[string]string{"number": "4857727", "pin": "1357"}})
	if st != 201 {
		t.Fatalf("re-register: %d %v", st, b)
	}
	// Revoking her own badge works; revoking through another person's path does not.
	if st, _ := do("DELETE", "/v1/admin/users/sam/bindings/"+b["id"].(string), nil); st == 204 {
		t.Fatal("revoke via another person's path succeeded")
	}
	// It is now her only method again, so she cannot remove it herself.
	if st, out := do("DELETE", "/v1/admin/users/dana/bindings/"+b["id"].(string), nil); st != 400 || out["code"] != "binding.last_method" {
		t.Fatalf("own revoke of last method should be refused: %d %v", st, out)
	}
}

func TestFirstAdminSetupAndSelfService(t *testing.T) {
	h := newHarness(t)
	c := h.client(nil)
	jar := map[string]string{}
	do := func(method, path string, body any) (int, map[string]any) {
		req, _ := jsonReq(method, h.ts.URL+path, body)
		if v, ok := jar["rostor_session"]; ok {
			req.AddCookie(&http.Cookie{Name: "rostor_session", Value: v})
		}
		req.Header.Set("X-Requested-With", "rostor-console")
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		for _, ck := range resp.Cookies() {
			jar[ck.Name] = ck.Value
		}
		out := map[string]any{}
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}
	// A fresh install needs its first administrator.
	if _, out := do("GET", "/v1/auth/setup", nil); out["needed"] != true {
		t.Fatalf("setup should be needed: %v", out)
	}
	if st, out := do("POST", "/v1/auth/setup", map[string]any{"bootstrap_token": "rst_wrong", "username": "dan", "password": "hunter2hunter2"}); st != 401 {
		t.Fatalf("bad token: %d %v", st, out)
	}
	st, out := do("POST", "/v1/auth/setup", map[string]any{"bootstrap_token": h.admin, "username": "dan", "display_name": "Dan", "password": "hunter2hunter2"})
	if st != 201 || jar["rostor_session"] == "" {
		t.Fatalf("setup: %d %v", st, out)
	}
	if perms, _ := out["permissions"].([]any); len(perms) != 1 || perms[0] != "*" {
		t.Fatalf("first admin should have all permissions via directory-admins: %v", out["permissions"])
	}
	if _, out := do("GET", "/v1/auth/setup", nil); out["needed"] != false {
		t.Fatalf("setup should be done: %v", out)
	}
	if st, out := do("POST", "/v1/auth/setup", map[string]any{"bootstrap_token": h.admin, "username": "eve", "password": "hunter2hunter2"}); st != 400 || out["code"] != "setup.already_done" {
		t.Fatalf("second setup should be refused: %d %v", st, out)
	}
	// Why shows the group path, not a direct grant.
	why := h.adminCall("GET", "/v1/admin/why?principal=dan&action=users.write&resource_type=directory&resource_id=root", nil)
	if why["decision"] != "ALLOW" || !strings.Contains(fmt.Sprint(why["reason"]), "group:") {
		t.Fatalf("admin via group: %v", why)
	}

	// Self-service: change own password needs the current one.
	if st, out := do("POST", "/v1/admin/users/dan/password", map[string]any{"current": "wrong", "new": "newpassword123"}); st == 204 {
		t.Fatalf("wrong current password accepted: %v", out)
	}
	if st, _ := do("POST", "/v1/admin/users/dan/password", map[string]any{"current": "hunter2hunter2", "new": "newpassword123"}); st != 204 {
		t.Fatalf("change password: %d", st)
	}
	do("POST", "/v1/auth/logout", nil)
	delete(jar, "rostor_session")
	if _, out := do("POST", "/v1/auth/login", map[string]any{"identifier": "dan", "fields": map[string]string{"password": "hunter2hunter2"}}); out["code"] != "auth.failed" {
		t.Fatalf("old password should fail: %v", out)
	}
	if st, out := do("POST", "/v1/auth/login", map[string]any{"identifier": "dan", "fields": map[string]string{"password": "newpassword123"}}); st != 200 || out["assurance"] != "AL1" {
		t.Fatalf("new password: %d %v", st, out)
	}
	// Set a PIN on own badge, then it is required.
	st, b := do("POST", "/v1/admin/users/dan/bindings", map[string]any{"method": "badge", "fields": map[string]string{"number": "1234567"}})
	if st != 201 {
		t.Fatalf("badge: %d %v", st, b)
	}
	if st, _ := do("POST", "/v1/admin/users/dan/bindings/"+b["id"].(string)+"/pin", map[string]any{"pin": "9876"}); st != 204 {
		t.Fatalf("set pin: %d", st)
	}
	do("POST", "/v1/auth/logout", nil)
	delete(jar, "rostor_session")
	if _, out := do("POST", "/v1/auth/login", map[string]any{"method": "badge", "fields": map[string]string{"number": "1234567"}}); out["code"] != "auth.continue" {
		t.Fatalf("badge without pin should ask for it: %v", out)
	}
	if st, out := do("POST", "/v1/auth/login", map[string]any{"method": "badge", "fields": map[string]string{"number": "1234567", "pin": "9876"}}); st != 200 || out["assurance"] != "AL2" {
		t.Fatalf("badge with new pin: %d %v", st, out)
	}
}

// EnsureBuiltins must be safe to run on every start, including on a tenant
// that already has everything (the v0.3.0 crash: a failed INSERT aborted
// the start-up transaction).
func TestBuiltinsIdempotentOnExistingTenant(t *testing.T) {
	h := newHarness(t) // harness already ran EnsureBuiltins once
	eng, _ := authz.New()
	for i := 0; i < 2; i++ {
		if err := h.db.Tx(h.ctx, func(tx pgx.Tx) error {
			// The same transaction also does other work afterwards, as serve does.
			if err := directory.EnsureBuiltins(h.ctx, tx, h.tenantID, eng); err != nil {
				return err
			}
			var n int
			return tx.QueryRow(h.ctx, `SELECT count(*) FROM groups WHERE tenant_id=$1 AND name=$2`, h.tenantID, directory.AdminsGroup).Scan(&n)
		}); err != nil {
			t.Fatalf("run %d: %v", i+1, err)
		}
	}
	var grants int
	_ = h.db.QueryRow(h.ctx, `SELECT count(*) FROM grants WHERE tenant_id=$1 AND role='admin' AND subject_kind='group' AND revoked_at IS NULL`, h.tenantID).Scan(&grants)
	if grants != 1 {
		t.Fatalf("expected exactly one admins grant, got %d", grants)
	}
	// Migrations are idempotent too.
	if applied, err := h.db.Migrate(h.ctx); err != nil || len(applied) != 0 {
		t.Fatalf("second migrate: applied=%v err=%v", applied, err)
	}
}

// The catalog must never be served from a stale cache across versions.
func TestCatalogRevalidates(t *testing.T) {
	h := newHarness(t)
	req, _ := http.NewRequest("GET", h.ts.URL+"/v1/catalog?locale=en", nil)
	resp, err := h.client(nil).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	etag := resp.Header.Get("ETag")
	if etag == "" || resp.Header.Get("Cache-Control") != "no-cache" {
		t.Fatalf("catalog caching headers: etag=%q cc=%q", etag, resp.Header.Get("Cache-Control"))
	}
	req.Header.Set("If-None-Match", etag)
	resp, err = h.client(nil).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 304 {
		t.Fatalf("expected 304 with matching ETag, got %d", resp.StatusCode)
	}
}

// Certificate renewal and CA rotation (SPEC-cert-renewal): a device enrolls,
// the CA rotates, the device learns the new bundle, renews from the new CA,
// keeps working on the old certificate during the grace window, the old CA
// can be retired only once nothing depends on it, and the old certificate
// then stops working.
func TestCertificateRenewalAndRotation(t *testing.T) {
	h := newHarness(t)
	tok := h.adminCall("POST", "/v1/admin/enrollment-tokens", map[string]any{"resource_type": "workstation"})["enrollment_token"].(string)
	key1, csr1 := csr(t)
	st, out := h.call(h.client(nil), "POST", "/v1/devices/enroll", "", map[string]any{"enrollment_token": tok, "csr_pem": csr1, "posture": map[string]any{"hostname": "WS-ROT"}})
	if st != 201 {
		t.Fatalf("enroll: %d %v", st, out)
	}
	mkCert := func(key *ecdsa.PrivateKey, certPEM string) tls.Certificate {
		block, _ := pem.Decode([]byte(certPEM))
		der, _ := x509.MarshalECPrivateKey(key)
		c, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: block.Bytes}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	cert1 := mkCert(key1, out["certificate_pem"].(string))
	dev1 := h.client(&cert1)
	trust := func(c *http.Client) map[string]any {
		st, out := h.call(c, "GET", "/v1/devices/self/trust", "", nil)
		if st != 200 {
			t.Fatalf("trust: %d %v", st, out)
		}
		return out
	}
	if tr := trust(dev1); len(tr["ca_pems"].([]any)) != 1 || tr["renew"] != false {
		t.Fatalf("initial trust: %v", tr)
	}
	// Rotate: a second CA appears; the old one is still the newest-but-one.
	rot := h.adminCall("POST", "/v1/admin/ca/rotate", nil)
	newCA := rot["id"].(string)
	cas := h.adminCall("GET", "/v1/admin/ca", nil)
	if len(cas["items"].([]any)) != 2 || cas["devices"].(map[string]any)["on_older_bundle"].(float64) != 1 {
		t.Fatalf("after rotate: %v", cas)
	}
	// The device still connects (server cert still from the old CA) and is told to renew.
	tr := trust(dev1)
	if len(tr["ca_pems"].([]any)) != 2 || tr["renew"] != true {
		t.Fatalf("trust after rotate: %v", tr)
	}
	if cas := h.adminCall("GET", "/v1/admin/ca", nil); cas["devices"].(map[string]any)["on_older_bundle"].(float64) != 0 {
		t.Fatalf("device should now be on the current bundle: %v", cas)
	}
	// Retiring the old CA is refused while the device's cert came from it.
	items := cas["items"].([]any)
	var oldCA string
	for _, it := range items {
		m := it.(map[string]any)
		if m["id"] != newCA {
			oldCA = m["id"].(string)
		}
	}
	if st, out := h.call(h.client(nil), "POST", "/v1/admin/ca/"+oldCA+"/retire", h.admin, nil); st != 400 || out["code"] != "ca.in_use" {
		t.Fatalf("retire in use: %d %v", st, out)
	}
	// Renew with a fresh key: new cert from the new CA.
	key2, csr2 := csr(t)
	st, out = h.call(dev1, "POST", "/v1/devices/self/renew", "", map[string]any{"csr_pem": csr2})
	if st != 200 {
		t.Fatalf("renew: %d %v", st, out)
	}
	cert2 := mkCert(key2, out["certificate_pem"].(string))
	dev2 := h.client(&cert2)
	if tr := trust(dev2); tr["renew"] != false {
		t.Fatalf("after renew: %v", tr)
	}
	// The old certificate still works inside the grace window, and says renew.
	if tr := trust(dev1); tr["renew"] != true {
		t.Fatalf("old cert in grace should still work and ask to renew: %v", tr)
	}
	// Now the old CA can be retired; the old certificate is no longer accepted
	// (its CA is gone from the client pool), the new one is.
	if st, _ := h.call(h.client(nil), "POST", "/v1/admin/ca/"+oldCA+"/retire", h.admin, nil); st != 204 {
		t.Fatalf("retire after renew: %d", st)
	}
	if st, _ := h.call(dev2, "GET", "/v1/devices/self/trust", "", nil); st != 200 {
		t.Fatalf("new cert after retire: %d", st)
	}
	// A fresh handshake is what the rotation protects; a kept-alive
	// connection from before is torn down by the client here.
	dev1.CloseIdleConnections()
	req, _ := http.NewRequest("GET", h.ts.URL+"/v1/devices/self/trust", nil)
	if resp, err := dev1.Do(req); err == nil && resp.StatusCode == 200 {
		t.Fatal("old CA's certificate accepted after retirement")
	}
	// The last active CA cannot be retired.
	if st, out := h.call(h.client(nil), "POST", "/v1/admin/ca/"+newCA+"/retire", h.admin, nil); st != 400 || out["code"] != "ca.last_active" {
		t.Fatalf("retire last: %d %v", st, out)
	}
	if bad, err := audit.VerifyChain(h.ctx, h.db, h.tenantID); err != nil || bad != 0 {
		t.Fatalf("audit chain: %d %v", bad, err)
	}
}

// Regression: the Access screen listed nothing because the grants query referenced placeholders it never
// bound, and the helper swallowed the Postgres error into an empty page. A created grant must come back
// from the list, from the search, and from the group's detail.
func TestGrantsAreListed(t *testing.T) {
	h := newHarness(t)
	h.adminCall("POST", "/v1/admin/groups", map[string]any{"name": "members"})
	g := h.adminCall("POST", "/v1/admin/grants", map[string]any{"subject_kind": "group", "subject": "members", "role": "user", "resource_type": "workstations", "resource_id": "all"})
	id, _ := g["id"].(string)
	if id == "" {
		t.Fatalf("create grant: %v", g)
	}
	has := func(out map[string]any, key string) bool {
		items, _ := out[key].([]any)
		for _, it := range items {
			if m, ok := it.(map[string]any); ok && m["id"] == id {
				return true
			}
		}
		return false
	}
	if out := h.adminCall("GET", "/v1/admin/grants", nil); !has(out, "items") {
		t.Fatalf("grant missing from list: %v", out)
	}
	if out := h.adminCall("GET", "/v1/admin/grants?q=workstations", nil); !has(out, "items") {
		t.Fatalf("grant missing from search: %v", out)
	}
	if out := h.adminCall("GET", "/v1/admin/grants?q=nomatch", nil); has(out, "items") {
		t.Fatalf("search should exclude the grant: %v", out)
	}
	if out := h.adminCall("GET", "/v1/admin/groups/members", nil); !has(out, "grants") {
		t.Fatalf("grant missing from group detail: %v", out)
	}
}

// The grant form's pickers: every resource with its parent, and the
// permissions known per type, so nothing has to be typed from memory.
func TestResourcesForGrantForm(t *testing.T) {
	h := newHarness(t)
	h.adminCall("POST", "/v1/admin/resources", map[string]any{"type": "door", "id": "front"})
	h.adminCall("POST", "/v1/admin/roles", map[string]any{"resource_type": "door", "name": "enter", "permissions": []string{"enter"}})
	out := h.adminCall("GET", "/v1/admin/resources", nil)
	found := map[string]any{}
	for _, it := range out["items"].([]any) {
		m := it.(map[string]any)
		found[m["type"].(string)+":"+m["id"].(string)] = m["parent"]
	}
	for _, want := range []string{"directory:root", "workstations:all", "door:front"} {
		if _, ok := found[want]; !ok {
			t.Fatalf("resource %s missing: %v", want, out["items"])
		}
	}
	perms := out["permissions"].(map[string]any)
	has := func(typ, action string) bool {
		list, _ := perms[typ].([]any)
		for _, a := range list {
			if a == action {
				return true
			}
		}
		return false
	}
	if !has("directory", "grants.write") || !has("directory", "*") {
		t.Fatalf("directory permissions should include the API's checks and the admin wildcard: %v", perms["directory"])
	}
	if !has("workstations", "logon") || !has("workstation", "logon") {
		t.Fatalf("device actions missing: %v", perms)
	}
	if !has("door", "enter") {
		t.Fatalf("permissions from existing roles missing: %v", perms["door"])
	}
}

// The audit screen shows people by default; the appliance's own work (the
// built-ins it ensures on every start, device certificate checks) appears
// only with include_system=1.
func TestAuditHidesSystemByDefault(t *testing.T) {
	h := newHarness(t)
	h.adminCall("POST", "/v1/admin/groups", map[string]any{"name": "members"})
	kinds := func(path string) map[string]int {
		out := h.adminCall("GET", path, nil)
		seen := map[string]int{}
		for _, it := range out["items"].([]any) {
			actor := it.(map[string]any)["actor"].(map[string]any)
			seen[actor["kind"].(string)]++
		}
		return seen
	}
	people := kinds("/v1/admin/audit")
	if people["system"] != 0 || people["device"] != 0 {
		t.Fatalf("default view should hide system and device actors: %v", people)
	}
	if people["service"]+people["user"] == 0 {
		t.Fatalf("default view lost the people: %v", people)
	}
	all := kinds("/v1/admin/audit?include_system=1")
	if all["system"] == 0 {
		t.Fatalf("include_system should show the built-ins the harness created: %v", all)
	}
}

// SPEC-agents acceptance: an agent is an owned principal that can never do
// more than its owner; owners manage their own agents without being admins.
func TestAgents(t *testing.T) {
	h := newHarness(t)
	// dana: a member with logon on every workstation through the members group.
	h.adminCall("POST", "/v1/admin/users", map[string]any{"username": "dana", "display_name": map[string]string{"en": "Dana"}})
	h.adminCall("POST", "/v1/admin/users/dana/bindings", map[string]any{"method": "password", "fields": map[string]string{"password": "hunter2hunter2"}})
	h.adminCall("POST", "/v1/admin/groups", map[string]any{"name": "members"})
	h.adminCall("POST", "/v1/admin/groups/members/members", map[string]any{"member_kind": "principal", "member": "dana"})
	h.adminCall("POST", "/v1/admin/grants", map[string]any{"subject_kind": "group", "subject": "members", "role": "user", "resource_type": "workstations", "resource_id": "all"})
	h.adminCall("POST", "/v1/admin/resources", map[string]any{"type": "workstation", "id": "WS-1", "parent_type": "workstations", "parent_id": "all"})
	// Owning agents is a grant: the built-in agent-owners group holds the
	// agent-owner role and starts empty; putting dana in it is the switch.
	ao := h.adminCall("GET", "/v1/admin/groups/agent-owners", nil)
	if len(ao["members"].([]any)) != 0 || len(ao["grants"].([]any)) != 1 {
		t.Fatalf("agent-owners should exist, empty, with its grant: %v", ao)
	}
	h.adminCall("POST", "/v1/admin/groups/agent-owners/members", map[string]any{"member_kind": "principal", "member": "dana"})

	// An admin creates an agent owned by dana.
	ag := h.adminCall("POST", "/v1/admin/agents", map[string]any{"username": "helper", "display_name": map[string]string{"en": "Helper"}, "owner": "dana"})
	agentID, _ := ag["id"].(string)
	if agentID == "" || ag["kind"] != "agent" || ag["owner"].(map[string]any)["name"] != "Dana" {
		t.Fatalf("create agent: %v", ag)
	}
	// An agent can never own an agent.
	if st, out := h.call(h.client(nil), "POST", "/v1/admin/agents", h.admin, map[string]any{"username": "bot2", "owner": "helper"}); st != 400 || out["code"] != "agent.owner_invalid" {
		t.Fatalf("agent as owner should be refused: %d %v", st, out)
	}
	// Grant the agent what its owner holds.
	h.adminCall("POST", "/v1/admin/agents/"+agentID+"/grants", map[string]any{"role": "user", "resource_type": "workstations", "resource_id": "all"})
	why := func() map[string]any {
		return h.adminCall("GET", "/v1/admin/why?principal=helper&action=logon&resource_type=workstation&resource_id=WS-1", nil)
	}
	ex := why()
	if ex["decision"] != "ALLOW" || ex["owner"].(map[string]any)["decision"] != "ALLOW" {
		t.Fatalf("both legs should allow: %v", ex)
	}
	reason := func(ex map[string]any) (string, string) {
		rs := ex["reason"].([]any)[0].(map[string]any)
		inner, _ := rs["params"].(map[string]any)["reason"].(string)
		return rs["code"].(string), inner
	}
	// Owner loses the group → agent loses the right, with the owner's reason.
	h.adminCall("DELETE", "/v1/admin/groups/members/members", map[string]any{"member_kind": "principal", "member": "dana"})
	if ex := why(); ex["decision"] != "DENY" {
		t.Fatalf("agent should be denied once the owner is: %v", ex)
	} else if code, inner := reason(ex); code != "owner.denied" || inner != "grant.none" {
		t.Fatalf("reason: %s/%s", code, inner)
	}
	h.adminCall("POST", "/v1/admin/groups/members/members", map[string]any{"member_kind": "principal", "member": "dana"})
	// Owner suspended → agent denied.
	h.adminCall("POST", "/v1/admin/users/dana/state", map[string]any{"state": "suspended"})
	if ex := why(); ex["decision"] != "DENY" {
		t.Fatalf("suspended owner: %v", ex)
	} else if code, inner := reason(ex); code != "owner.denied" || inner != "principal.suspended" {
		t.Fatalf("reason: %s/%s", code, inner)
	}
	h.adminCall("POST", "/v1/admin/users/dana/state", map[string]any{"state": "active"})
	// A wider grant exists but never fires: admin on the directory while dana is no admin.
	h.adminCall("POST", "/v1/admin/agents/"+agentID+"/grants", map[string]any{"role": "admin", "resource_type": "directory", "resource_id": "root"})
	if ex := h.adminCall("GET", "/v1/admin/why?principal=helper&action=grants.write&resource_type=directory&resource_id=root", nil); ex["decision"] != "DENY" {
		t.Fatalf("agent must not exceed owner: %v", ex)
	} else if code, _ := reason(ex); code != "owner.denied" {
		t.Fatalf("reason: %s", code)
	}

	// Tokens: issue, use, rotate, revoke.
	tok1 := h.adminCall("POST", "/v1/admin/agents/"+agentID+"/token", nil)["token"].(string)
	if st, _ := h.call(h.client(nil), "GET", "/v1/admin/users", tok1, nil); st != 403 {
		t.Fatalf("agent with no admin rights listing users: %d", st)
	}
	if st, out := h.call(h.client(nil), "GET", "/v1/admin/users/helper", tok1, nil); st != 200 || out["kind"] != "agent" {
		t.Fatalf("agent reading its own record: %d %v", st, out)
	}
	tok2 := h.adminCall("POST", "/v1/admin/agents/"+agentID+"/token", nil)["token"].(string)
	if st, _ := h.call(h.client(nil), "GET", "/v1/admin/users/helper", tok1, nil); st != 401 {
		t.Fatalf("rotated token should be dead: %d", st)
	}
	if st, _ := h.call(h.client(nil), "GET", "/v1/admin/users/helper", tok2, nil); st != 200 {
		t.Fatalf("new token should work: %d", st)
	}
	h.adminCall("DELETE", "/v1/admin/agents/"+agentID+"/token", nil)
	if st, _ := h.call(h.client(nil), "GET", "/v1/admin/users/helper", tok2, nil); st != 401 {
		t.Fatalf("revoked token should be dead: %d", st)
	}
	// The agent's acts are audited under its identity with its owner named.
	if tok3 := h.adminCall("POST", "/v1/admin/agents/"+agentID+"/token", nil)["token"].(string); tok3 != "" {
		h.call(h.client(nil), "GET", "/v1/admin/users/helper", tok3, nil)
	}
	rows := h.adminCall("GET", "/v1/admin/audit?q=api_token", nil)["items"].([]any)
	if len(rows) == 0 {
		t.Fatal("token events should be audited")
	}

	// Self-service: dana signs in with a cookie and manages her own agents.
	c := h.client(nil)
	var cookie string
	do := func(method, path string, body any) (int, map[string]any) {
		var rd io.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			rd = bytes.NewReader(b)
		}
		req, _ := http.NewRequest(method, h.ts.URL+path, rd)
		if cookie != "" {
			req.AddCookie(&http.Cookie{Name: "rostor_session", Value: cookie})
		}
		req.Header.Set("X-Requested-With", "rostor-console")
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		out := map[string]any{}
		raw, _ := io.ReadAll(resp.Body)
		if len(raw) > 0 && raw[0] == '{' {
			_ = json.Unmarshal(raw, &out)
		}
		for _, ck := range resp.Cookies() {
			if ck.Name == "rostor_session" {
				cookie = ck.Value
			}
		}
		return resp.StatusCode, out
	}
	if st, out := do("POST", "/v1/auth/login", map[string]any{"identifier": "dana", "fields": map[string]string{"password": "hunter2hunter2"}}); st != 200 || cookie == "" {
		t.Fatalf("dana login: %d %v", st, out)
	}
	st, mine := do("POST", "/v1/admin/agents", map[string]any{"username": "dbot", "display_name": map[string]string{"en": "Dana's bot"}})
	if st != 201 || mine["owner"].(map[string]any)["name"] != "Dana" {
		t.Fatalf("owner creating own agent: %d %v", st, mine)
	}
	dbot := mine["id"].(string)
	if st, out := do("POST", "/v1/admin/agents", map[string]any{"username": "notmine", "owner": "admin"}); st != 403 || out["code"] != "agent.not_owned" {
		t.Fatalf("non-admin naming another owner: %d %v", st, out)
	}
	// dana owns both helper (created for her by the admin) and dbot; nothing else shows.
	if st, out := do("GET", "/v1/admin/agents", nil); st != 200 || out["total"] != float64(2) {
		t.Fatalf("owner list should be own agents only: %d %v", st, out)
	}
	if st, out := do("GET", "/v1/admin/agents/"+agentID, nil); st != 200 || out["id"] != agentID {
		t.Fatalf("owner reading own agent: %d %v", st, out)
	}
	// Handing over a held right works; a right she does not hold is refused.
	if st, out := do("POST", "/v1/admin/agents/"+dbot+"/grants", map[string]any{"role": "user", "resource_type": "workstations", "resource_id": "all"}); st != 201 {
		t.Fatalf("held right: %d %v", st, out)
	}
	if st, out := do("POST", "/v1/admin/agents/"+dbot+"/grants", map[string]any{"role": "admin", "resource_type": "directory", "resource_id": "root"}); st != 403 || out["code"] != "agent.grant_not_held" {
		t.Fatalf("unheld right should be refused: %d %v", st, out)
	}
	// grantable is what dana holds minus the right to own agents itself (agents cannot own agents).
	if st, out := do("GET", "/v1/admin/agents/"+dbot, nil); st != 200 || len(out["grantable"].([]any)) != 1 || len(out["grants"].([]any)) != 1 {
		t.Fatalf("agent detail: %v", out)
	}
	if st, out := do("POST", "/v1/admin/agents/"+dbot+"/grants", map[string]any{"role": "agent-owner", "resource_type": "directory", "resource_id": "root"}); st != 403 || out["code"] != "agent.grant_not_held" {
		t.Fatalf("agent-owner must not be handed to an agent: %d %v", st, out)
	}
	gid := do2(t, do, "GET", "/v1/admin/agents/"+dbot)["grants"].([]any)[0].(map[string]any)["id"].(string)
	if st, _ := do("DELETE", "/v1/admin/agents/"+dbot+"/grants/"+gid, nil); st != 204 {
		t.Fatalf("owner revoking own agent's grant: %d", st)
	}
	if st, _ := do("POST", "/v1/admin/agents/"+dbot+"/state", map[string]any{"state": "suspended"}); st != 204 {
		t.Fatalf("owner suspending own agent: %d", st)
	}
	// Agents appear among people with their owner.
	people := h.adminCall("GET", "/v1/admin/users?q=dbot", nil)["items"].([]any)
	if len(people) != 1 || people[0].(map[string]any)["owner"].(map[string]any)["name"] != "Dana" {
		t.Fatalf("people list should carry the owner: %v", people)
	}

	// Take the permission away: dana can no longer create or arm agents, and
	// every agent she owns stops at once, whatever else it holds.
	h.adminCall("DELETE", "/v1/admin/groups/agent-owners/members", map[string]any{"member_kind": "principal", "member": "dana"})
	if st, out := do("POST", "/v1/admin/agents", map[string]any{"username": "another"}); st != 403 || out["code"] != "agent.not_allowed" {
		t.Fatalf("create without agents.own: %d %v", st, out)
	}
	if st, out := do("POST", "/v1/admin/agents/"+agentID+"/token", nil); st != 403 || out["code"] != "agent.not_allowed" {
		t.Fatalf("token without agents.own: %d %v", st, out)
	}
	if st, _ := do("GET", "/v1/admin/agents", nil); st != 200 {
		t.Fatalf("listing to wind down should still work: %d", st)
	}
	if ex := why(); ex["decision"] != "DENY" {
		t.Fatalf("agent should stop when the owner may no longer have agents: %v", ex)
	} else if code, inner := reason(ex); code != "owner.denied" || inner != "agent.not_allowed" {
		t.Fatalf("reason: %s/%s", code, inner)
	}
	// Admins are unaffected: role admin covers agents.own.
	h.adminCall("POST", "/v1/admin/agents", map[string]any{"username": "adminbot", "owner": "dana"})
}

func do2(t *testing.T, do func(string, string, any) (int, map[string]any), method, path string) map[string]any {
	st, out := do(method, path, nil)
	if st != 200 {
		t.Fatalf("%s %s: %d %v", method, path, st, out)
	}
	return out
}

// SPEC-agents: MCP is the same API under the caller's own identity.
func TestMCP(t *testing.T) {
	h := newHarness(t)
	rpc := func(bearer string, body any) (int, map[string]any) {
		return h.call(h.client(nil), "POST", "/mcp", bearer, body)
	}
	// initialize negotiates a version and names the server.
	st, out := rpc(h.admin, map[string]any{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": map[string]any{"protocolVersion": "2025-03-26", "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "test", "version": "0"}}})
	if st != 200 || out["result"].(map[string]any)["protocolVersion"] != "2025-03-26" || out["result"].(map[string]any)["serverInfo"].(map[string]any)["name"] != "rostor" {
		t.Fatalf("initialize: %d %v", st, out)
	}
	// A notification gets 202 and no body.
	if st, _ := rpc(h.admin, map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"}); st != 202 {
		t.Fatalf("notification: %d", st)
	}
	// No credential → 401.
	if st, _ := rpc("", map[string]any{"jsonrpc": "2.0", "id": 2, "method": "tools/list"}); st != 401 {
		t.Fatalf("anonymous: %d", st)
	}
	_, out = rpc(h.admin, map[string]any{"jsonrpc": "2.0", "id": 3, "method": "tools/list"})
	tools := out["result"].(map[string]any)["tools"].([]any)
	names := map[string]bool{}
	for _, tl := range tools {
		m := tl.(map[string]any)
		names[m["name"].(string)] = true
		if m["description"] == "" || strings.HasPrefix(m["description"].(string), "mcp.tool.") {
			t.Fatalf("tool description missing from the catalog: %v", m)
		}
	}
	for _, want := range []string{"people_list", "grant_create", "why", "audit_list", "agent_get"} {
		if !names[want] {
			t.Fatalf("tool %s missing: %v", want, names)
		}
	}
	// A tool call is the API call: create a person, then list and find them.
	_, out = rpc(h.admin, map[string]any{"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": map[string]any{"name": "person_create", "arguments": map[string]any{"username": "mia", "display_name": "Mia"}}})
	if res := out["result"].(map[string]any); res["isError"] != false {
		t.Fatalf("person_create: %v", out)
	}
	_, out = rpc(h.admin, map[string]any{"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": map[string]any{"name": "people_list", "arguments": map[string]any{"q": "mia"}}})
	res := out["result"].(map[string]any)
	if !strings.Contains(res["content"].([]any)[0].(map[string]any)["text"].(string), `"username":"mia"`) {
		t.Fatalf("people_list: %v", res)
	}
	// Unknown tool → JSON-RPC error, not an HTTP error.
	if st, out := rpc(h.admin, map[string]any{"jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": map[string]any{"name": "nope"}}); st != 200 || out["error"] == nil {
		t.Fatalf("unknown tool: %d %v", st, out)
	}

	// An agent with no rights: reads its own resource, is refused a grant, and both are audited under it with its owner.
	h.adminCall("POST", "/v1/admin/groups/agent-owners/members", map[string]any{"member_kind": "principal", "member": "mia"})
	h.adminCall("POST", "/v1/admin/agents", map[string]any{"username": "helper", "display_name": map[string]string{"en": "Helper"}, "owner": "mia"})
	tok := h.adminCall("POST", "/v1/admin/agents/helper/token", nil)["token"].(string)
	_, out = rpc(tok, map[string]any{"jsonrpc": "2.0", "id": 7, "method": "resources/read", "params": map[string]any{"uri": "rostor://me"}})
	if !strings.Contains(out["result"].(map[string]any)["contents"].([]any)[0].(map[string]any)["text"].(string), `"username":"helper"`) {
		t.Fatalf("me: %v", out)
	}
	_, out = rpc(tok, map[string]any{"jsonrpc": "2.0", "id": 8, "method": "tools/call", "params": map[string]any{"name": "grant_create", "arguments": map[string]any{
		"subject_kind": "principal", "subject": "helper", "role": "admin", "resource_type": "directory", "resource_id": "root"}}})
	res = out["result"].(map[string]any)
	if res["isError"] != true || !strings.Contains(res["content"].([]any)[0].(map[string]any)["text"].(string), "request.forbidden") {
		t.Fatalf("agent grant_create should be refused: %v", res)
	}
	rows := h.adminCall("GET", "/v1/admin/audit?q=mcp.call", nil)["items"].([]any)
	var seen int
	for _, it := range rows {
		m := it.(map[string]any)
		actor := m["actor"].(map[string]any)
		if actor["kind"] == "agent" && actor["owner_name"] == "Mia" && m["target"].(map[string]any)["id"] == "grant_create" && m["outcome"] == "deny" {
			seen++
		}
	}
	if seen == 0 {
		t.Fatalf("agent's denied call should be audited with its owner: %v", rows)
	}
}

// badge.format = wiegand26: any reader names the same card, and the card is
// saved as facility:card. A card enrolled by its full UID is accepted from a
// Wiegand reader, a printed-number reader and a byte-reversed reader, and
// one enrolled from a Wiegand reader is accepted from a UID reader.
func TestBadgeFormatWiegand(t *testing.T) {
	h := newHarness(t)
	h.adminCall("PUT", "/v1/admin/settings/auth", map[string]any{"webauthn": map[string]any{"rp_id": "", "display_name": "", "origins": []string{}},
		"login": map[string]any{"default_method": "badge"}, "badge": map[string]any{"format": "wiegand26"}})
	if got := h.adminCall("GET", "/v1/admin/settings/auth", nil)["badge"].(map[string]any)["format"]; got != "wiegand26" {
		t.Fatalf("setting not saved: %v", got)
	}
	if st, out := h.call(h.client(nil), "PUT", "/v1/admin/settings/auth", h.admin, map[string]any{"webauthn": map[string]any{"origins": []string{}}, "badge": map[string]any{"format": "wiegand-24"}}); st != 400 {
		t.Fatalf("unknown format should be refused: %d %v", st, out)
	}
	h.adminCall("POST", "/v1/admin/users", map[string]any{"username": "dana", "display_name": map[string]string{"en": "Dana"}})
	h.adminCall("POST", "/v1/admin/groups", map[string]any{"name": "members"})
	h.adminCall("POST", "/v1/admin/groups/members/members", map[string]any{"member_kind": "principal", "member": "dana"})
	h.adminCall("POST", "/v1/admin/grants", map[string]any{"subject_kind": "group", "subject": "members", "role": "user", "resource_type": "workstations", "resource_id": "all"})
	// Enrolled from a reader that types the full UID.
	h.adminCall("POST", "/v1/admin/users/dana/bindings", map[string]any{"method": "badge", "fields": map[string]string{"number": "0a004a1f7e"}})
	forms := h.adminCall("GET", "/v1/admin/users/dana", nil)["bindings"].([]any)[0].(map[string]any)["forms"].([]any)
	if len(forms) != 1 || forms[0].(map[string]any)["kind"] != "wiegand26" || forms[0].(map[string]any)["value"] != "74:8062" {
		t.Fatalf("saved as wiegand only: %v", forms)
	}
	tok := h.adminCall("POST", "/v1/admin/enrollment-tokens", map[string]any{"resource_type": "workstation"})["enrollment_token"].(string)
	key, csrPEM := csr(t)
	st, out := h.call(h.client(nil), "POST", "/v1/devices/enroll", "", map[string]any{"enrollment_token": tok, "csr_pem": csrPEM, "posture": map[string]any{"hostname": "WS-W26"}})
	if st != 201 {
		t.Fatalf("enroll: %d %v", st, out)
	}
	certBlock, _ := pem.Decode([]byte(out["certificate_pem"].(string)))
	keyDER, _ := x509.MarshalECPrivateKey(key)
	cert, _ := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBlock.Bytes}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	dev := h.client(&cert)
	verify := func(cred map[string]string) string {
		_, out := h.call(dev, "POST", "/v1/verify", "", map[string]any{"credential": cred, "action": "logon", "resource": map[string]string{"type": "workstation", "id": "WS-W26"}})
		d, _ := out["decision"].(string)
		return d
	}
	for _, cred := range []map[string]string{
		{"type": "badge", "facility": "74", "card": "8062"}, // Wiegand reader
		{"type": "badge", "number": "74:8062"},              // Wiegand reader keeping the split
		{"type": "badge", "number": "4857726"},              // printed-number reader (low 24 bits, decimal)
		{"type": "badge", "number": "42954530686"},          // full UID typed in decimal
		{"type": "badge", "uid": "7e1f4a000a"},              // byte-reversed reader
	} {
		if d := verify(cred); d != "ALLOW" {
			t.Fatalf("%v should match the card: %s", cred, d)
		}
	}
	if d := verify(map[string]string{"type": "badge", "number": "74:8063"}); d != "DENY" {
		t.Fatalf("a different card must not match: %s", d)
	}
	// The other way round: enrolled from a Wiegand reader, presented by a UID reader.
	h.adminCall("POST", "/v1/admin/users", map[string]any{"username": "sam"})
	h.adminCall("POST", "/v1/admin/groups/members/members", map[string]any{"member_kind": "principal", "member": "sam"})
	h.adminCall("POST", "/v1/admin/users/sam/bindings", map[string]any{"method": "badge", "fields": map[string]string{"number": "12:345"}})
	if d := verify(map[string]string{"type": "badge", "uid": "ff0c0159"}); d != "ALLOW" { // 0x0c0159 = 12:345 under any high byte
		t.Fatalf("uid reader should match a card enrolled by wiegand: %s", d)
	}
	// Console sign-in by badge with the printed form.
	if st, out := h.call(h.client(nil), "POST", "/v1/auth/login", "", map[string]any{"method": "badge", "fields": map[string]string{"number": "4857726"}}); st != 200 || out["assurance"] != "AL1" {
		t.Fatalf("badge login: %d %v", st, out)
	}
	// The check line in the Register badge drawer: how a reading is understood, nothing stored.
	rd := h.adminCall("POST", "/v1/admin/badges/read", map[string]string{"number": "02622915"})
	if rd["wiegand26"] != "26:22915" || rd["value24"] != float64(1726851) || rd["stored"].(map[string]any)["badge.wiegand26"] != "26:22915" {
		t.Fatalf("read: %v", rd)
	}
	if st, _ := h.call(h.client(nil), "POST", "/v1/admin/badges/read", "", map[string]string{"number": "1"}); st != 401 {
		t.Fatalf("read needs a session: %d", st)
	}
	// Dan's fob from two readers: padded 24-bit decimal, and the Wiegand pair
	// run together. Enrolled from either, accepted from the other.
	h.adminCall("POST", "/v1/admin/users", map[string]any{"username": "kim"})
	h.adminCall("POST", "/v1/admin/groups/members/members", map[string]any{"member_kind": "principal", "member": "kim"})
	h.adminCall("POST", "/v1/admin/users/kim/bindings", map[string]any{"method": "badge", "fields": map[string]string{"number": "0001726851"}})
	if d := verify(map[string]string{"type": "badge", "number": "02622915"}); d != "ALLOW" {
		t.Fatalf("concatenated wiegand reader should match the padded-decimal enrolment: %s", d)
	}
	h.adminCall("POST", "/v1/admin/users", map[string]any{"username": "lee"})
	h.adminCall("POST", "/v1/admin/groups/members/members", map[string]any{"member_kind": "principal", "member": "lee"})
	h.adminCall("POST", "/v1/admin/users/lee/bindings", map[string]any{"method": "badge", "fields": map[string]string{"number": "02733001"}})
	if d := verify(map[string]string{"type": "badge", "number": "0001802473"}); d != "ALLOW" { // 27<<16 | 33001
		t.Fatalf("padded-decimal reader should match the concatenated-wiegand enrolment: %s", d)
	}
}

// SPEC-scripts acceptance: authoring needs AL2; devices receive their
// scripts in position order, signed by the CA; runs come back as records
// and audit rows.
func TestScripts(t *testing.T) {
	h := newHarness(t)
	// dana: an admin who signs in with badge + PIN (AL2).
	h.adminCall("POST", "/v1/admin/users", map[string]any{"username": "dana", "display_name": map[string]string{"en": "Dana"}})
	h.adminCall("POST", "/v1/admin/users/dana/bindings", map[string]any{"method": "badge", "fields": map[string]string{"uid": "0a004a1f7e", "pin": "2468"}})
	h.adminCall("POST", "/v1/admin/groups/directory-admins/members", map[string]any{"member_kind": "principal", "member": "dana"})
	c := h.client(nil)
	var cookie string
	do := func(method, path string, body any) (int, map[string]any) {
		var rd io.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			rd = bytes.NewReader(b)
		}
		req, _ := http.NewRequest(method, h.ts.URL+path, rd)
		if cookie != "" {
			req.AddCookie(&http.Cookie{Name: "rostor_session", Value: cookie})
		}
		req.Header.Set("X-Requested-With", "rostor-console")
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		out := map[string]any{}
		raw, _ := io.ReadAll(resp.Body)
		if len(raw) > 0 && raw[0] == '{' {
			_ = json.Unmarshal(raw, &out)
		}
		for _, ck := range resp.Cookies() {
			if ck.Name == "rostor_session" {
				cookie = ck.Value
			}
		}
		return resp.StatusCode, out
	}
	if st, out := do("POST", "/v1/auth/login", map[string]any{"method": "badge", "fields": map[string]string{"uid": "0a004a1f7e", "pin": "2468"}}); st != 200 || out["assurance"] != "AL2" {
		t.Fatalf("AL2 login: %d %v", st, out)
	}
	must := func(method, path string, body any, want int) map[string]any {
		st, out := do(method, path, body)
		if st != want {
			t.Fatalf("%s %s: %d %v", method, path, st, out)
		}
		return out
	}

	// The AL1 admin token may read but not write.
	if st, out := h.call(c, "POST", "/v1/admin/scripts", h.admin, map[string]any{"name": "x", "body": "Write-Host hi"}); st != 403 || out["code"] != "request.assurance_required" {
		t.Fatalf("AL1 write should be refused: %d %v", st, out)
	}
	h.adminCall("GET", "/v1/admin/scripts", nil)

	// Create two scripts; edit one so its version bumps; reorder.
	a := must("POST", "/v1/admin/scripts", map[string]any{"name": "Map printers", "description": "printers", "body": "Add-Printer -Name P1"}, 201)
	b := must("POST", "/v1/admin/scripts", map[string]any{"name": "Set wallpaper", "body": "Set-Wallpaper"}, 201)
	aID, bID := a["id"].(string), b["id"].(string)
	if a["version"] != float64(1) || a["body"] != "Add-Printer -Name P1" {
		t.Fatalf("create: %v", a)
	}
	if st, out := do("POST", "/v1/admin/scripts", map[string]any{"name": "", "body": "x"}); st != 400 {
		t.Fatalf("nameless script: %d %v", st, out)
	}
	if st, out := do("POST", "/v1/admin/scripts", map[string]any{"name": "bash", "language": "bash", "body": "x"}); st != 400 {
		t.Fatalf("unsupported language: %d %v", st, out)
	}
	if v := must("PUT", "/v1/admin/scripts/"+aID, map[string]any{"description": "printers v2"}, 200); v["version"] != float64(1) {
		t.Fatalf("description-only edit must not bump: %v", v)
	}
	if v := must("PUT", "/v1/admin/scripts/"+aID, map[string]any{"body": "Add-Printer -Name P2"}, 200); v["version"] != float64(2) {
		t.Fatalf("body edit must bump: %v", v)
	}
	must("PUT", "/v1/admin/scripts/order", map[string]any{"ids": []string{bID, aID}}, 204)
	list := must("GET", "/v1/admin/scripts", nil, 200)["items"].([]any)
	if len(list) != 2 || list[0].(map[string]any)["id"] != bID || list[1].(map[string]any)["id"] != aID {
		t.Fatalf("order: %v", list)
	}

	// Assign: b to every workstation (now), a to a device group (at sign-in).
	must("POST", "/v1/admin/scripts/"+bID+"/assignments", map[string]any{"target_kind": "all", "target": "workstation", "mode": "immediate"}, 201)
	h.adminCall("POST", "/v1/admin/groups", map[string]any{"name": "lab-pcs"})
	asg := must("POST", "/v1/admin/scripts/"+aID+"/assignments", map[string]any{"target_kind": "group", "target": "lab-pcs", "mode": "signin"}, 201)
	if st, out := do("POST", "/v1/admin/scripts/"+aID+"/assignments", map[string]any{"target_kind": "group", "target": "lab-pcs", "mode": "sometimes"}); st != 400 {
		t.Fatalf("bad mode: %d %v", st, out)
	}

	// Two devices: one in lab-pcs, one not.
	enrol := func(host string) (*http.Client, string) {
		tok := h.adminCall("POST", "/v1/admin/enrollment-tokens", map[string]any{"resource_type": "workstation"})["enrollment_token"].(string)
		key, csrPEM := csr(t)
		st, out := h.call(h.client(nil), "POST", "/v1/devices/enroll", "", map[string]any{"enrollment_token": tok, "csr_pem": csrPEM, "posture": map[string]any{"hostname": host}})
		if st != 201 {
			t.Fatalf("enroll %s: %d %v", host, st, out)
		}
		certBlock, _ := pem.Decode([]byte(out["certificate_pem"].(string)))
		keyDER, _ := x509.MarshalECPrivateKey(key)
		cert, _ := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBlock.Bytes}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
		return h.client(&cert), out["device_id"].(string)
	}
	labPC, labID := enrol("LAB-1")
	otherPC, _ := enrol("OFFICE-1")
	h.adminCall("POST", "/v1/admin/groups/lab-pcs/members", map[string]any{"member_kind": "principal", "member": labID})

	// The lab PC gets both, in position order (b first), each signed by a CA in its trust bundle.
	_, trust := h.call(labPC, "GET", "/v1/devices/self/trust", "", nil)
	var pubs []*ecdsa.PublicKey
	for _, p := range trust["ca_pems"].([]any) {
		blk, _ := pem.Decode([]byte(p.(string)))
		crt, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		pubs = append(pubs, crt.PublicKey.(*ecdsa.PublicKey))
	}
	verifies := func(sc map[string]any) bool {
		sig, _ := base64.StdEncoding.DecodeString(sc["signature"].(string))
		// The contract's signing input: id, version (decimal) and body, newline-separated.
		sum := sha256.Sum256([]byte(sc["id"].(string) + "\n" + strconv.Itoa(int(sc["version"].(float64))) + "\n" + sc["body"].(string)))
		for _, pub := range pubs {
			if ecdsa.VerifyASN1(pub, sum[:], sig) {
				return true
			}
		}
		return false
	}
	_, got := h.call(labPC, "GET", "/v1/devices/self/scripts", "", nil)
	scripts := got["scripts"].([]any)
	if len(scripts) != 2 || scripts[0].(map[string]any)["id"] != bID || scripts[0].(map[string]any)["mode"] != "immediate" ||
		scripts[1].(map[string]any)["id"] != aID || scripts[1].(map[string]any)["mode"] != "signin" || scripts[1].(map[string]any)["version"] != float64(2) {
		t.Fatalf("lab scripts: %v", scripts)
	}
	for _, sc := range scripts {
		if !verifies(sc.(map[string]any)) {
			t.Fatalf("signature should verify against the trust bundle: %v", sc)
		}
	}
	tampered := map[string]any{}
	for k, v := range scripts[0].(map[string]any) {
		tampered[k] = v
	}
	tampered["body"] = tampered["body"].(string) + "; Remove-Item C:\\ -Recurse"
	if verifies(tampered) {
		t.Fatal("a tampered body must not verify")
	}
	// The office PC only gets the one for every workstation.
	_, got = h.call(otherPC, "GET", "/v1/devices/self/scripts", "", nil)
	if scripts := got["scripts"].([]any); len(scripts) != 1 || scripts[0].(map[string]any)["id"] != bID {
		t.Fatalf("office scripts: %v", scripts)
	}

	// A run comes back as a record and an audit row.
	now := time.Now().UTC()
	if st, out := h.call(labPC, "POST", "/v1/devices/self/scripts/"+aID+"/runs", "", map[string]any{"version": 2, "mode": "signin", "principal_id": "",
		"started_at": now.Add(-2 * time.Second), "finished_at": now, "exit_code": 1, "status": "failed", "output_tail": "Add-Printer : not found"}); st != 201 {
		t.Fatalf("run: %d %v", st, out)
	}
	if st, out := h.call(labPC, "POST", "/v1/devices/self/scripts/"+aID+"/runs", "", map[string]any{"version": 2, "mode": "signin", "started_at": now, "finished_at": now, "exit_code": 0, "status": "great"}); st != 400 {
		t.Fatalf("bad status: %d %v", st, out)
	}
	runs := must("GET", "/v1/admin/scripts/"+aID+"/runs", nil, 200)["items"].([]any)
	if len(runs) != 1 || runs[0].(map[string]any)["status"] != "failed" || runs[0].(map[string]any)["device"].(map[string]any)["name"] != "LAB-1" {
		t.Fatalf("runs: %v", runs)
	}
	detail := must("GET", "/v1/admin/scripts/"+aID, nil, 200)
	if detail["last_run"].(map[string]any)["status"] != "failed" || len(detail["runs"].([]any)) != 1 || len(detail["assignments"].([]any)) != 1 {
		t.Fatalf("detail: %v", detail)
	}
	rows := h.adminCall("GET", "/v1/admin/audit?q=script.run&include_system=1", nil)["items"].([]any)
	if len(rows) == 0 || rows[0].(map[string]any)["actor"].(map[string]any)["kind"] != "device" {
		t.Fatalf("script.run should be audited by the device: %v", rows)
	}

	// Unassign, then delete: the script goes, the run history stays.
	must("DELETE", "/v1/admin/scripts/"+aID+"/assignments/"+asg["id"].(string), nil, 204)
	must("DELETE", "/v1/admin/scripts/"+aID, nil, 204)
	if st, _ := do("GET", "/v1/admin/scripts/"+aID, nil); st != 404 {
		t.Fatalf("deleted script should be gone: %d", st)
	}
	if runs := must("GET", "/v1/admin/scripts/"+aID+"/runs", nil, 200)["items"].([]any); len(runs) != 1 {
		t.Fatalf("runs should survive the delete: %v", runs)
	}
}

// SPEC-portal: anonymous visitors see public tiles; a member sees My account
// and what a grant lets them view; an admin sees the administration tiles;
// Why explains a tile grant like any other decision.
func TestPortal(t *testing.T) {
	h := newHarness(t)
	c := h.client(nil)
	// Anonymous, nothing public yet.
	st, out := h.call(c, "GET", "/v1/portal", "", nil)
	if st != 200 || out["signed_in"] != false || len(out["tiles"].([]any)) != 0 {
		t.Fatalf("anonymous portal: %d %v", st, out)
	}
	// Admin creates a public link, a private link, and grants the private one to members.
	pub := h.adminCall("POST", "/v1/admin/portal/tiles", map[string]any{"title": "Wiki", "href": "https://wiki.example.org", "icon": "W", "public": true})
	if pub["id"] != "wiki" || pub["public"] != true || pub["kind"] != "link" {
		t.Fatalf("public tile: %v", pub)
	}
	h.adminCall("POST", "/v1/admin/portal/tiles", map[string]any{"id": "booking", "title": "Booking", "href": "https://book.example.org"})
	h.adminCall("POST", "/v1/admin/groups", map[string]any{"name": "members"})
	h.adminCall("POST", "/v1/admin/grants", map[string]any{"subject_kind": "group", "subject": "members", "role": "viewer", "resource_type": "portal.tile", "resource_id": "booking"})
	if st, out := h.call(c, "POST", "/v1/admin/portal/tiles", h.admin, map[string]any{"title": "Bad", "href": "javascript:alert(1)"}); st != 400 {
		t.Fatalf("bad href: %d %v", st, out)
	}
	ids := func(out map[string]any) []string {
		var got []string
		for _, tl := range out["tiles"].([]any) {
			got = append(got, tl.(map[string]any)["id"].(string))
		}
		return got
	}
	// Anonymous sees the public link only.
	_, out = h.call(c, "GET", "/v1/portal", "", nil)
	if got := ids(out); len(got) != 1 || got[0] != "wiki" {
		t.Fatalf("anonymous should see wiki only: %v", got)
	}
	// The admin token sees every administration screen plus both links.
	_, out = h.call(c, "GET", "/v1/portal", h.admin, nil)
	admin := ids(out)
	want := map[string]bool{"people": true, "system": true, "wiki": true, "booking": true}
	for _, id := range admin {
		delete(want, id)
	}
	if len(want) != 0 {
		t.Fatalf("admin missing tiles %v in %v", want, admin)
	}
	// A member (cookie) sees My account, the public link, and the granted link; not People.
	h.adminCall("POST", "/v1/admin/users", map[string]any{"username": "dana"})
	h.adminCall("POST", "/v1/admin/users/dana/bindings", map[string]any{"method": "password", "fields": map[string]string{"password": "hunter2hunter2"}})
	h.adminCall("POST", "/v1/admin/groups/members/members", map[string]any{"member_kind": "principal", "member": "dana"})
	req, _ := jsonReq("POST", h.ts.URL+"/v1/auth/login", map[string]any{"identifier": "dana", "fields": map[string]string{"password": "hunter2hunter2"}})
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var cookie *http.Cookie
	for _, ck := range resp.Cookies() {
		if ck.Name == "rostor_session" {
			cookie = ck
		}
	}
	resp.Body.Close()
	if cookie == nil {
		t.Fatal("no session cookie")
	}
	req, _ = jsonReq("GET", h.ts.URL+"/v1/portal", nil)
	req.AddCookie(cookie)
	resp, err = c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	out = map[string]any{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	resp.Body.Close()
	member := map[string]bool{}
	for _, id := range ids(out) {
		member[id] = true
	}
	if !member["my-account"] || !member["wiki"] || !member["booking"] || member["people"] || member["system"] {
		t.Fatalf("member tiles: %v", member)
	}
	// Why explains the booking tile through the members grant.
	ex := h.adminCall("GET", "/v1/admin/why?principal=dana&action=view&resource_type=portal.tile&resource_id=booking", nil)
	if ex["decision"] != "ALLOW" {
		t.Fatalf("why: %v", ex)
	}
	// Unpublish the wiki: anonymous sees nothing again; built-ins cannot be deleted.
	h.adminCall("PUT", "/v1/admin/portal/tiles/wiki", map[string]any{"public": false})
	_, out = h.call(c, "GET", "/v1/portal", "", nil)
	if len(out["tiles"].([]any)) != 0 {
		t.Fatalf("unpublished: %v", out)
	}
	if st, _ := h.call(c, "DELETE", "/v1/admin/portal/tiles/people", h.admin, nil); st != 403 {
		t.Fatalf("built-in delete should be refused: %d", st)
	}
	if st, _ := h.call(c, "DELETE", "/v1/admin/portal/tiles/wiki", h.admin, nil); st != 204 {
		t.Fatalf("delete link: %d", st)
	}
}

// Sign-in policy applies to devices: a group override reaches the
// workstations in that group and no others; the tenant default otherwise.
func TestAuthPolicyForDevices(t *testing.T) {
	h := newHarness(t)
	h.adminCall("PUT", "/v1/admin/settings/auth", map[string]any{"webauthn": map[string]any{"rp_id": "", "display_name": "", "origins": []string{}}, "login": map[string]any{"default_method": "password"}, "badge": map[string]any{"format": "wiegand26"}})
	h.adminCall("POST", "/v1/admin/groups", map[string]any{"name": "lab-pcs"})
	enrol := func(host string) (*http.Client, string) {
		tok := h.adminCall("POST", "/v1/admin/enrollment-tokens", map[string]any{"resource_type": "workstation"})["enrollment_token"].(string)
		key, csrPEM := csr(t)
		st, out := h.call(h.client(nil), "POST", "/v1/devices/enroll", "", map[string]any{"enrollment_token": tok, "csr_pem": csrPEM, "posture": map[string]any{"hostname": host}})
		if st != 201 {
			t.Fatalf("enroll %s: %d %v", host, st, out)
		}
		certBlock, _ := pem.Decode([]byte(out["certificate_pem"].(string)))
		keyDER, _ := x509.MarshalECPrivateKey(key)
		cert, _ := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBlock.Bytes}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
		return h.client(&cert), out["device_id"].(string)
	}
	lab, labID := enrol("LAB-1")
	office, _ := enrol("OFFICE-1")
	h.adminCall("POST", "/v1/admin/groups/lab-pcs/members", map[string]any{"member_kind": "principal", "member": labID})
	policy := func(c *http.Client) (string, string) {
		st, out := h.call(c, "GET", "/v1/devices/self/policy", "", nil)
		if st != 200 {
			t.Fatalf("policy: %d %v", st, out)
		}
		if name, _ := out["tenant_name"].(string); name == "" {
			t.Fatalf("policy should name the tenant for the lock screen: %v", out)
		}
		return out["login"].(map[string]any)["default_method"].(string), out["badge"].(map[string]any)["format"].(string)
	}
	if m, f := policy(lab); m != "password" || f != "wiegand26" {
		t.Fatalf("tenant default should reach the lab PC: %s %s", m, f)
	}
	// Override the lab group to badge.
	ov := h.adminCall("PUT", "/v1/admin/settings/auth/overrides/lab-pcs", map[string]any{"login": map[string]any{"default_method": "badge"}})
	if ov["group"].(map[string]any)["name"] != "lab-pcs" || ov["login"].(map[string]any)["default_method"] != "badge" {
		t.Fatalf("override: %v", ov)
	}
	if st, out := h.call(h.client(nil), "PUT", "/v1/admin/settings/auth/overrides/lab-pcs", h.admin, map[string]any{"login": map[string]any{"default_method": "carrier-pigeon"}}); st != 400 {
		t.Fatalf("bad method: %d %v", st, out)
	}
	if st, out := h.call(h.client(nil), "PUT", "/v1/admin/settings/auth/overrides/nope", h.admin, map[string]any{"login": map[string]any{"default_method": "badge"}}); st != 404 {
		t.Fatalf("unknown group: %d %v", st, out)
	}
	if m, _ := policy(lab); m != "badge" {
		t.Fatalf("lab PC should follow its group: %s", m)
	}
	if m, _ := policy(office); m != "password" {
		t.Fatalf("office PC should keep the tenant default: %s", m)
	}
	// A second, newer override on a group the lab PC is also in wins.
	h.adminCall("POST", "/v1/admin/groups", map[string]any{"name": "kiosks"})
	h.adminCall("POST", "/v1/admin/groups/kiosks/members", map[string]any{"member_kind": "principal", "member": labID})
	h.adminCall("PUT", "/v1/admin/settings/auth/overrides/kiosks", map[string]any{"login": map[string]any{"default_method": "passkey"}})
	if m, _ := policy(lab); m != "passkey" {
		t.Fatalf("newest override should win: %s", m)
	}
	items := h.adminCall("GET", "/v1/admin/settings/auth/overrides", nil)["items"].([]any)
	if len(items) != 2 {
		t.Fatalf("overrides list: %v", items)
	}
	// Removing overrides restores the tenant default; the tenant setting is untouched.
	h.adminCall("DELETE", "/v1/admin/settings/auth/overrides/kiosks", nil)
	h.adminCall("DELETE", "/v1/admin/settings/auth/overrides/lab-pcs", nil)
	if st, _ := h.call(h.client(nil), "DELETE", "/v1/admin/settings/auth/overrides/lab-pcs", h.admin, nil); st != 404 {
		t.Fatalf("double delete: %d", st)
	}
	if m, _ := policy(lab); m != "password" {
		t.Fatalf("after removal: %s", m)
	}
	if got := h.adminCall("GET", "/v1/admin/settings/auth", nil)["login"].(map[string]any)["default_method"]; got != "password" {
		t.Fatalf("tenant setting changed: %v", got)
	}

	// A shared session account for a licensed workstation group: the lab PC
	// is told to run every session as "chattlab"; the office PC is not.
	if st, out := h.call(h.client(nil), "PUT", "/v1/admin/settings/auth/overrides/lab-pcs", h.admin, map[string]any{"logon": map[string]any{"session_account": "Chatt Lab!"}}); st != 400 {
		t.Fatalf("bad account name: %d %v", st, out)
	}
	ov = h.adminCall("PUT", "/v1/admin/settings/auth/overrides/lab-pcs", map[string]any{"login": map[string]any{"default_method": "badge"}, "logon": map[string]any{"session_account": "ChattLab"}})
	if ov["logon"].(map[string]any)["session_account"] != "chattlab" {
		t.Fatalf("override should carry the account, lowercased: %v", ov)
	}
	st, out := h.call(lab, "GET", "/v1/devices/self/policy", "", nil)
	if st != 200 || out["logon"].(map[string]any)["session_account"] != "chattlab" {
		t.Fatalf("lab policy: %d %v", st, out)
	}
	h.adminCall("POST", "/v1/admin/users", map[string]any{"username": "dana"})
	h.adminCall("POST", "/v1/admin/users/dana/bindings", map[string]any{"method": "password", "fields": map[string]string{"password": "hunter2hunter2"}})
	h.adminCall("POST", "/v1/admin/groups", map[string]any{"name": "members"})
	h.adminCall("POST", "/v1/admin/groups/members/members", map[string]any{"member_kind": "principal", "member": "dana"})
	h.adminCall("POST", "/v1/admin/grants", map[string]any{"subject_kind": "group", "subject": "members", "role": "user", "resource_type": "workstations", "resource_id": "all"})
	verify := func(c *http.Client, host string) map[string]any {
		_, out := h.call(c, "POST", "/v1/verify", "", map[string]any{"credential": map[string]string{"type": "password", "identifier": "dana", "secret": "hunter2hunter2"},
			"action": "logon", "resource": map[string]string{"type": "workstation", "id": host}})
		return out
	}
	if out := verify(lab, "LAB-1"); out["decision"] != "ALLOW" || out["session_account"] != "chattlab" || out["principal"].(map[string]any)["username"] != "dana" {
		t.Fatalf("lab verify should name the shared account and still the person: %v", out)
	}
	if out := verify(office, "OFFICE-1"); out["decision"] != "ALLOW" || out["session_account"] != nil {
		t.Fatalf("office verify should not carry a shared account: %v", out)
	}
	// Which tile the lock screen selects: tenant-wide windows, lab group back to rostor.
	h.adminCall("PUT", "/v1/admin/settings/auth", map[string]any{"webauthn": map[string]any{"rp_id": "", "display_name": "", "origins": []string{}}, "login": map[string]any{"default_method": "password"}, "logon": map[string]any{"default_provider": "windows"}})
	if got := h.adminCall("GET", "/v1/admin/settings/auth", nil)["logon"].(map[string]any)["default_provider"]; got != "windows" {
		t.Fatalf("tenant provider: %v", got)
	}
	st, out = h.call(office, "GET", "/v1/devices/self/policy", "", nil)
	if st != 200 || out["logon"].(map[string]any)["default_provider"] != "windows" {
		t.Fatalf("office should follow the tenant: %d %v", st, out)
	}
	h.adminCall("PUT", "/v1/admin/settings/auth/overrides/lab-pcs", map[string]any{"login": map[string]any{"default_method": "badge"}, "logon": map[string]any{"session_account": "chattlab", "default_provider": "rostor"}})
	st, out = h.call(lab, "GET", "/v1/devices/self/policy", "", nil)
	if st != 200 || out["logon"].(map[string]any)["default_provider"] != "rostor" || out["logon"].(map[string]any)["session_account"] != "chattlab" {
		t.Fatalf("lab should follow its override: %d %v", st, out)
	}
	if st, out := h.call(h.client(nil), "PUT", "/v1/admin/settings/auth/overrides/lab-pcs", h.admin, map[string]any{"logon": map[string]any{"default_provider": "linux"}}); st != 400 {
		t.Fatalf("bad provider: %d %v", st, out)
	}
	// The audit names dana, not the shared account.
	rows := h.adminCall("GET", "/v1/admin/audit?q=verify&include_system=1", nil)["items"].([]any)
	if len(rows) == 0 || rows[0].(map[string]any)["detail"].(map[string]any)["principal_name"] != "dana" {
		t.Fatalf("verify audit should name the person: %v", rows)
	}
}

// Deputy self-update: manual by default (only marked devices are told),
// auto tells every outdated device; the offer is the core's version with
// the bundle's hash signed by the CA; the report clears the mark.
func TestDeputyUpdate(t *testing.T) {
	h := newHarness(t)
	h.srv.StateDir = t.TempDir()
	// A cached "bundle" for the running version, as PrefetchDownloads would leave it.
	bundle := filepath.Join(h.srv.StateDir, "downloads", h.srv.Version, "rostor-windows-amd64.zip")
	if err := os.MkdirAll(filepath.Dir(bundle), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bundle, []byte("PK\x05\x06"+strings.Repeat("\x00", 18)), 0o644); err != nil {
		t.Fatal(err)
	}
	enrol := func(host, version string) (*http.Client, string) {
		tok := h.adminCall("POST", "/v1/admin/enrollment-tokens", map[string]any{"resource_type": "workstation"})["enrollment_token"].(string)
		key, csrPEM := csr(t)
		st, out := h.call(h.client(nil), "POST", "/v1/devices/enroll", "", map[string]any{"enrollment_token": tok, "csr_pem": csrPEM, "posture": map[string]any{"hostname": host, "deputy_version": version}})
		if st != 201 {
			t.Fatalf("enroll %s: %d %v", host, st, out)
		}
		certBlock, _ := pem.Decode([]byte(out["certificate_pem"].(string)))
		keyDER, _ := x509.MarshalECPrivateKey(key)
		cert, _ := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBlock.Bytes}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
		return h.client(&cert), out["device_id"].(string)
	}
	old, oldID := enrol("OLD-1", "v0.1.0")
	current, _ := enrol("NEW-1", h.srv.Version)
	offer := func(c *http.Client) map[string]any {
		st, out := h.call(c, "GET", "/v1/devices/self/update", "", nil)
		if st != 200 {
			t.Fatalf("update: %d %v", st, out)
		}
		u, _ := out["update"].(map[string]any)
		return u
	}
	// Manual by default: nobody is told.
	if got := h.adminCall("GET", "/v1/admin/settings/devices", nil)["deputy"].(map[string]any)["update"]; got != "manual" {
		t.Fatalf("default policy: %v", got)
	}
	if offer(old) != nil {
		t.Fatal("unmarked device should not be offered an update")
	}
	// Mark it: the offer names the core's version, the bundle's hash, and a CA signature that verifies.
	if st, _ := h.call(h.client(nil), "POST", "/v1/admin/devices/"+oldID+"/update", h.admin, nil); st != 202 {
		t.Fatalf("mark: %d", st)
	}
	u := offer(old)
	if u == nil || u["version"] != h.srv.Version {
		t.Fatalf("offer: %v", u)
	}
	_, trust := h.call(old, "GET", "/v1/devices/self/trust", "", nil)
	verified := false
	for _, p := range trust["ca_pems"].([]any) {
		blk, _ := pem.Decode([]byte(p.(string)))
		crt, _ := x509.ParseCertificate(blk.Bytes)
		sig, _ := base64.StdEncoding.DecodeString(u["signature"].(string))
		sum := sha256.Sum256([]byte("bundle\n" + u["version"].(string) + "\n" + u["sha256"].(string)))
		if ecdsa.VerifyASN1(crt.PublicKey.(*ecdsa.PublicKey), sum[:], sig) {
			verified = true
		}
	}
	if !verified {
		t.Fatal("bundle signature should verify against the trust bundle")
	}
	// The bundle streams and matches the offered hash.
	req, _ := jsonReq("GET", h.ts.URL+"/v1/devices/self/update/bundle", nil)
	resp, err := old.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || hex.EncodeToString(func() []byte { x := sha256.Sum256(body); return x[:] }()) != u["sha256"] || float64(len(body)) != u["size"] {
		t.Fatalf("bundle: %d %d bytes", resp.StatusCode, len(body))
	}
	// The device list shows the mark; a device already on the version is never offered one even when marked.
	for _, d := range h.adminCall("GET", "/v1/admin/devices", nil)["items"].([]any) {
		m := d.(map[string]any)
		if m["id"] == oldID && (m["update"].(map[string]any)["wanted"] != true || m["deputy_version"] != "v0.1.0") {
			t.Fatalf("device row: %v", m)
		}
	}
	if offer(current) != nil {
		t.Fatal("a current device is never offered an update")
	}
	// The report clears the mark, whatever the outcome, and is audited by the device.
	if st, out := h.call(old, "POST", "/v1/devices/self/update/runs", "", map[string]any{"version": h.srv.Version, "status": "failed", "from_version": "v0.1.0", "output_tail": "install-service failed (1)"}); st != 201 {
		t.Fatalf("report: %d %v", st, out)
	}
	if offer(old) != nil {
		t.Fatal("a failed attempt must not be retried until marked again")
	}
	for _, d := range h.adminCall("GET", "/v1/admin/devices", nil)["items"].([]any) {
		m := d.(map[string]any)
		if m["id"] == oldID && (m["update"].(map[string]any)["status"] != "failed" || m["update"].(map[string]any)["wanted"] != false) {
			t.Fatalf("device row after report: %v", m)
		}
	}
	rows := h.adminCall("GET", "/v1/admin/audit?q=deputy.update&include_system=1", nil)["items"].([]any)
	if len(rows) == 0 || rows[0].(map[string]any)["outcome"] != "error" {
		t.Fatalf("deputy.update audit: %v", rows)
	}
	// Auto: every outdated device is told without a mark; update-all marks them too.
	h.adminCall("PUT", "/v1/admin/settings/devices", map[string]any{"deputy": map[string]any{"update": "auto"}})
	if offer(old) == nil {
		t.Fatal("auto should offer the update to an outdated device")
	}
	if n := h.adminCall("POST", "/v1/admin/devices/update-all", nil)["marked"]; n != float64(1) {
		t.Fatalf("update-all should mark the one outdated device: %v", n)
	}
	// Cancelling takes the mark back; under auto the offer still stands.
	if st, _ := h.call(h.client(nil), "DELETE", "/v1/admin/devices/"+oldID+"/update", h.admin, nil); st != 204 {
		t.Fatalf("cancel: %d", st)
	}
	for _, d := range h.adminCall("GET", "/v1/admin/devices", nil)["items"].([]any) {
		if m := d.(map[string]any); m["id"] == oldID && m["update"].(map[string]any)["wanted"] != false {
			t.Fatalf("cancel should clear the mark: %v", m)
		}
	}
	// A deputy from before the updater (bare "0.1.0") is skipped by update-all: it needs a manual install.
	_, legacyID := enrol("LEGACY-1", "0.1.0")
	_ = legacyID
	h.adminCall("PUT", "/v1/admin/settings/devices", map[string]any{"deputy": map[string]any{"update": "manual"}})
	if n := h.adminCall("POST", "/v1/admin/devices/update-all", nil)["marked"]; n != float64(1) {
		t.Fatalf("update-all should skip the legacy deputy: %v", n)
	}
	if st, _ := h.call(h.client(nil), "PUT", "/v1/admin/settings/devices", h.admin, map[string]any{"deputy": map[string]any{"update": "sometimes"}}); st != 400 {
		t.Fatalf("bad policy value: %d", st)
	}
}

// The organisation's name is one field, shown everywhere: the brand the
// console reads without a session, and the tenant name devices get.
func TestOrganisationName(t *testing.T) {
	h := newHarness(t)
	if st, out := h.call(h.client(nil), "PUT", "/v1/admin/settings/organisation", h.admin, map[string]any{"name": "   "}); st != 400 {
		t.Fatalf("empty name: %d %v", st, out)
	}
	if got := h.adminCall("PUT", "/v1/admin/settings/organisation", map[string]any{"name": " ChattLab "})["name"]; got != "ChattLab" {
		t.Fatalf("rename: %v", got)
	}
	if st, out := h.call(h.client(nil), "GET", "/v1/brand", "", nil); st != 200 || out["tenant_name"] != "ChattLab" {
		t.Fatalf("brand should carry the new name: %d %v", st, out)
	}
	if got := h.adminCall("GET", "/v1/admin/settings/organisation", nil)["name"]; got != "ChattLab" {
		t.Fatalf("get: %v", got)
	}
	rows := h.adminCall("GET", "/v1/admin/audit?q=tenant.rename", nil)["items"].([]any)
	if len(rows) == 0 {
		t.Fatal("rename should be audited")
	}
}
