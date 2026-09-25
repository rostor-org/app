package core

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
	"testing"
	"time"
)

// newMTLSServer starts a TLS server that requires a client certificate from
// the same tiny CA and returns a Client enrolled against it.
func newMTLSServer(t *testing.T, h http.Handler) *Client {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	issue := func(cn string, server bool) tls.Certificate {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature,
		}
		if server {
			tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			tmpl.IPAddresses = []net.IP{net.IPv4(127, 0, 0, 1)}
		} else {
			tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	srv := httptest.NewUnstartedServer(h)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{issue("core", true)}, ClientCAs: pool, ClientAuth: tls.RequireAndVerifyClientCert}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	dir := t.TempDir()
	dev := issue("WS", false)
	keyDER, _ := x509.MarshalPKCS8PrivateKey(dev.PrivateKey)
	write := func(name string, block *pem.Block) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, pem.EncodeToMemory(block), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	certPath := write("device.crt", &pem.Block{Type: "CERTIFICATE", Bytes: dev.Certificate[0]})
	keyPath := write("device.key", &pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	caPath := write("ca.crt", &pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	c, err := NewClient(srv.URL, certPath, keyPath, caPath, Resource{Type: "workstation", ID: "WS"}, "test")
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestScriptsAndReportRun(t *testing.T) {
	var gotRun ScriptRun
	var gotPath, gotMethod string
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/devices/self/scripts", func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"scripts":[{"id":"scr_1","name":"Map printers","language":"powershell","version":3,"position":10,"mode":"immediate","body":"Write-Host 1","signature":"AA==","signer":"cak_1"}]}`))
	})
	mux.HandleFunc("/v1/devices/self/scripts/", func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotMethod = r.URL.Path, r.Method
		if err := json.NewDecoder(r.Body).Decode(&gotRun); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusCreated)
	})
	c := newMTLSServer(t, mux)

	list, err := c.Scripts(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if gotMethod != http.MethodGet || len(list) != 1 || list[0].ID != "scr_1" || list[0].Version != 3 || list[0].Position != 10 ||
		list[0].Mode != "immediate" || list[0].Body != "Write-Host 1" || list[0].Signature != "AA==" || list[0].Signer != "cak_1" {
		t.Fatalf("scripts: %s %+v", gotMethod, list)
	}

	run := ScriptRun{Version: 3, Mode: "signin", PrincipalID: "usr_1",
		StartedAt: time.Date(2026, 9, 25, 1, 2, 3, 0, time.UTC), FinishedAt: time.Date(2026, 9, 25, 1, 2, 4, 0, time.UTC),
		ExitCode: 0, Status: "ok", OutputTail: "done"}
	if err := c.ReportRun(context.Background(), "scr 1/x", run); err != nil {
		t.Fatal(err)
	}
	if gotMethod != http.MethodPost || gotPath != "/v1/devices/self/scripts/scr 1/x/runs" {
		t.Fatalf("report request: %s %s", gotMethod, gotPath)
	}
	if gotRun != run {
		t.Fatalf("report body round trip: %+v", gotRun)
	}
}

func TestScriptsWireShape(t *testing.T) {
	// Field names on the wire are the contract's, not Go's.
	b, _ := json.Marshal(ScriptRun{Status: "ok"})
	for _, k := range []string{`"version"`, `"mode"`, `"principal_id"`, `"started_at"`, `"finished_at"`, `"exit_code"`, `"status"`, `"output_tail"`} {
		if !json.Valid(b) || !strings.Contains(string(b), k) {
			t.Fatalf("missing %s in %s", k, b)
		}
	}
}

func TestScriptsErrors(t *testing.T) {
	status := http.StatusInternalServerError
	body := ""
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	})
	c := newMTLSServer(t, mux)

	if _, err := c.Scripts(context.Background()); err == nil || !errors.Is(err, ErrUnreachable) {
		t.Fatalf("HTTP 500 on fetch: %v", err)
	}
	if err := c.ReportRun(context.Background(), "scr_1", ScriptRun{}); err == nil {
		t.Fatal("HTTP 500 on report should fail")
	}
	status, body = http.StatusOK, `{"scripts": [nope`
	if _, err := c.Scripts(context.Background()); err == nil || !errors.Is(err, ErrUnreachable) {
		t.Fatalf("bad JSON: %v", err)
	}
	// 200 is not the 201 the contract promises for a report.
	status, body = http.StatusOK, ""
	if err := c.ReportRun(context.Background(), "scr_1", ScriptRun{}); err == nil {
		t.Fatal("HTTP 200 on report should fail")
	}
	// An empty list is fine.
	body = `{"scripts":[]}`
	if list, err := c.Scripts(context.Background()); err != nil || len(list) != 0 {
		t.Fatalf("empty list: %v %v", list, err)
	}
}

func TestMockScripts(t *testing.T) {
	m := Mock{AllowIdentifier: "testuser"}
	if list, err := m.Scripts(context.Background()); err != nil || len(list) != 0 {
		t.Fatalf("mock scripts: %v %v", list, err)
	}
	if err := m.ReportRun(context.Background(), "scr_1", ScriptRun{}); err != nil {
		t.Fatal(err)
	}
}
