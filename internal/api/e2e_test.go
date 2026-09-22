package api_test

// End-to-end acceptance test for the Windows logon slice: the shape of spec
// scenario B.2 with a password in place of a badge. Runs against a real
// Postgres (ROSTOR_TEST_DATABASE_URL), in its own tenant.

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
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

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
	h.srv = &api.Server{DB: pool, Auth: authSvc, Authz: eng, Devices: dev, Catalog: cat, CA: h.ca, TenantID: h.tenantID,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
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
