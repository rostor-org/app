package enroll

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCSR(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pemStr, err := CSR(key, "DESKTOP-TEST")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		t.Fatal("bad PEM")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatal(err)
	}
	if csr.Subject.CommonName != "DESKTOP-TEST" {
		t.Fatalf("CN=%q", csr.Subject.CommonName)
	}
}

// A tiny CA that signs whatever CSR arrives, standing in for core.
func TestRunAgainstFakeCore(t *testing.T) {
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Rostor Test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	caCert, _ := x509.ParseCertificate(caDER)

	var gotToken string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/devices/enroll" {
			http.NotFound(w, r)
			return
		}
		var req request
		_ = json.NewDecoder(r.Body).Decode(&req)
		gotToken = req.EnrollmentToken
		block, _ := pem.Decode([]byte(req.CSRPEM))
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(2), Subject: csr.Subject,
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}
		der, _ := x509.CreateCertificate(rand.Reader, tmpl, caCert, csr.PublicKey, caKey)
		w.WriteHeader(201)
		_ = json.NewEncoder(w).Encode(response{
			DeviceID:       "dev_123",
			CertificatePEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
			CAPEM:          string(caPEM),
		})
	}))
	defer srv.Close()

	dir := t.TempDir()
	files := Files{
		AgentJSON: filepath.Join(dir, "agent.json"), DeviceKey: filepath.Join(dir, "device.key"),
		DeviceCert: filepath.Join(dir, "device.crt"), CACert: filepath.Join(dir, "ca.crt"),
	}
	secured := ""
	cfg, err := Run(context.Background(), Options{
		CoreURL: srv.URL, Token: "tok", Insecure: true,
		Posture:   Posture{OS: "windows", OSVersion: "10.0.19045", Hostname: "PC1"},
		Files:     files,
		SecureKey: func(p string) error { secured = p; return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if gotToken != "tok" || cfg.DeviceID != "dev_123" || cfg.Resource.ID != "PC1" || cfg.Resource.Type != "workstation" {
		t.Fatalf("cfg=%+v token=%q", cfg, gotToken)
	}
	if secured != files.DeviceKey {
		t.Fatalf("SecureKey called with %q", secured)
	}
	for _, p := range []string{files.AgentJSON, files.DeviceKey, files.DeviceCert, files.CACert} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("missing %s", p)
		}
	}
	loaded, err := LoadConfig(files.AgentJSON)
	if err != nil || loaded.DeviceID != "dev_123" {
		t.Fatalf("LoadConfig: %v %+v", err, loaded)
	}
	if _, err := Run(context.Background(), Options{CoreURL: srv.URL, Token: "tok", Insecure: true, Files: files}); err == nil {
		t.Fatal("second enrollment should refuse to overwrite")
	}
}
