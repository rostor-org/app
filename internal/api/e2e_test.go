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
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
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
		must(directory.CreateResource(ctx, tx, h.tenantID, sys, directory.Resource{Type: "directory", ID: "root"}))
		must(directory.UpsertRole(ctx, tx, h.tenantID, sys, directory.Role{ResourceType: "directory", Name: "admin", Permissions: []string{"*"}}))
		must(directory.CreateResource(ctx, tx, h.tenantID, sys, directory.Resource{Type: "workstations", ID: "all"}))
		must(directory.UpsertRole(ctx, tx, h.tenantID, sys, directory.Role{ResourceType: "workstations", Name: "user", Permissions: []string{"logon"}}))
		must(directory.UpsertRole(ctx, tx, h.tenantID, sys, directory.Role{ResourceType: "workstation", Name: "user", Permissions: []string{"logon"}}))
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
	go func() {
		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
			if line := sc.Text(); strings.HasPrefix(line, "event: ") {
				got <- strings.TrimPrefix(line, "event: ")
			}
		}
	}()
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
