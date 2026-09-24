package api_test

// A software authenticator: enough of WebAuthn to register a "none"
// attestation credential and answer an assertion, so the passkey ceremonies
// are exercised end to end without a browser.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

type softAuthenticator struct {
	key    *ecdsa.PrivateKey
	credID []byte
	rpID   string
	origin string
	count  int
	backup bool
}

func newSoftAuthenticator(rpID, origin string, backup bool) *softAuthenticator {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	id := make([]byte, 32)
	rand.Read(id)
	return &softAuthenticator{key: k, credID: id, rpID: rpID, origin: origin, backup: backup}
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func (a *softAuthenticator) flags(at bool) byte {
	f := byte(0x01 | 0x04) // UP | UV
	if at {
		f |= 0x40
	}
	if a.backup {
		f |= 0x08 | 0x10 // BE | BS
	}
	return f
}

func (a *softAuthenticator) authData(at bool) []byte {
	rp := sha256.Sum256([]byte(a.rpID))
	out := append([]byte{}, rp[:]...)
	out = append(out, a.flags(at))
	out = binary.BigEndian.AppendUint32(out, uint32(a.count))
	if at {
		aaguid := make([]byte, 16)
		out = append(out, aaguid...)
		out = binary.BigEndian.AppendUint16(out, uint16(len(a.credID)))
		out = append(out, a.credID...)
		// COSE_Key: EC2, P-256, ES256
		cose := map[int]any{1: 2, 3: -7, -1: 1, -2: a.key.PublicKey.X.FillBytes(make([]byte, 32)), -3: a.key.PublicKey.Y.FillBytes(make([]byte, 32))}
		ck, _ := cbor.Marshal(cose)
		out = append(out, ck...)
	}
	return out
}

func (a *softAuthenticator) clientData(typ, challenge string) []byte {
	cd, _ := json.Marshal(map[string]any{"type": typ, "challenge": challenge, "origin": a.origin})
	return cd
}

// register answers a creation options object (as returned by begin).
func (a *softAuthenticator) register(opts map[string]any) json.RawMessage {
	pk := opts["publicKey"].(map[string]any)
	cd := a.clientData("webauthn.create", pk["challenge"].(string))
	att, _ := cbor.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": a.authData(true)})
	resp, _ := json.Marshal(map[string]any{
		"id": b64(a.credID), "rawId": b64(a.credID), "type": "public-key",
		"response":               map[string]any{"clientDataJSON": b64(cd), "attestationObject": b64(att)},
		"clientExtensionResults": map[string]any{},
	})
	return resp
}

// assert answers an assertion options object.
func (a *softAuthenticator) assert(opts map[string]any, userHandle string) json.RawMessage {
	pk := opts["publicKey"].(map[string]any)
	a.count++
	cd := a.clientData("webauthn.get", pk["challenge"].(string))
	ad := a.authData(false)
	h := sha256.Sum256(cd)
	sig, _ := ecdsa.SignASN1(rand.Reader, a.key, sha256.New().Sum(nil)[:0])
	_ = sig
	msg := append(append([]byte{}, ad...), h[:]...)
	digest := sha256.Sum256(msg)
	sig, _ = ecdsa.SignASN1(rand.Reader, a.key, digest[:])
	resp, _ := json.Marshal(map[string]any{
		"id": b64(a.credID), "rawId": b64(a.credID), "type": "public-key",
		"response":               map[string]any{"clientDataJSON": b64(cd), "authenticatorData": b64(ad), "signature": b64(sig), "userHandle": b64([]byte(userHandle))},
		"clientExtensionResults": map[string]any{},
	})
	return resp
}

func TestPasskeys(t *testing.T) {
	h := newHarness(t)
	h.adminCall("POST", "/v1/admin/users", map[string]any{"username": "dan", "display_name": map[string]string{"en": "Dan"}})
	h.adminCall("POST", "/v1/admin/users/dan/bindings", map[string]any{"method": "password", "fields": map[string]string{"password": "hunter2hunter2"}})
	h.adminCall("POST", "/v1/admin/grants", map[string]any{"subject_kind": "principal", "subject": "dan", "role": "admin", "resource_type": "directory", "resource_id": "root"})

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

	// Passkeys are off until the tenant sets a relying party.
	do("POST", "/v1/auth/login", map[string]any{"identifier": "dan", "fields": map[string]string{"password": "hunter2hunter2"}})
	// Unset settings serialise with an empty origins list, never null (the
	// v0.3.1 System screen crash).
	if st, out := do("GET", "/v1/admin/settings/auth", nil); st != 200 {
		t.Fatalf("settings: %d", st)
	} else if o, ok := out["webauthn"].(map[string]any)["origins"].([]any); !ok || len(o) != 0 {
		t.Fatalf("origins should be [] when unset: %v", out)
	}
	if st, out := do("POST", "/v1/auth/passkeys/register/begin", nil); st != 400 || out["code"] != "auth.passkeys_unconfigured" {
		t.Fatalf("unconfigured: %d %v", st, out)
	}
	if st, _ := do("PUT", "/v1/admin/settings/auth", map[string]any{"webauthn": map[string]any{"rp_id": "example.org", "display_name": "Example", "origins": []string{"https://rostor.example.org"}},
		"login": map[string]any{"default_method": "badge"}}); st != 200 {
		t.Fatalf("settings: %d", st)
	}
	// The default sign-in method is public (the sign-in page needs it).
	if _, out := do("GET", "/v1/auth/setup", nil); out["default_method"] != "badge" {
		t.Fatalf("default method: %v", out)
	}
	if st, _ := do("PUT", "/v1/admin/settings/auth", map[string]any{"webauthn": map[string]any{"rp_id": "example.org", "origins": []string{"https://rostor.example.org"}},
		"login": map[string]any{"default_method": "carrier-pigeon"}}); st != 400 {
		t.Fatalf("bad default method should be 400, got %d", st)
	}

	// Register a synced passkey (backup-eligible) as the signed-in person.
	synced := newSoftAuthenticator("example.org", "https://rostor.example.org", true)
	st, begin := do("POST", "/v1/auth/passkeys/register/begin", nil)
	if st != 200 {
		t.Fatalf("register begin: %d %v", st, begin)
	}
	st, fin := do("POST", "/v1/auth/passkeys/register/finish", map[string]any{"ceremony_id": begin["ceremony_id"], "label": "1Password", "response": synced.register(begin["options"].(map[string]any))})
	if st != 201 || fin["method"] != "webauthn" {
		t.Fatalf("register finish: %d %v", st, fin)
	}
	// A ceremony can only be finished once.
	if st, _ := do("POST", "/v1/auth/passkeys/register/finish", map[string]any{"ceremony_id": begin["ceremony_id"], "response": synced.register(begin["options"].(map[string]any))}); st == 201 {
		t.Fatal("ceremony replay accepted")
	}
	do("POST", "/v1/auth/logout", nil)
	delete(jar, "rostor_session")

	// Discoverable sign-in: no identifier at all. Synced passkey → AL2.
	st, lb := do("POST", "/v1/auth/login/passkey/begin", map[string]any{})
	if st != 200 {
		t.Fatalf("login begin: %d %v", st, lb)
	}
	danID := fin["principal_id"].(string)
	st, lf := do("POST", "/v1/auth/login/passkey/finish", map[string]any{"ceremony_id": lb["ceremony_id"], "response": synced.assert(lb["options"].(map[string]any), danID)})
	if st != 200 || lf["assurance"] != "AL2" || jar["rostor_session"] == "" {
		t.Fatalf("login finish: %d %v", st, lf)
	}
	// The session is real.
	if st, _ := do("GET", "/v1/auth/session", nil); st != 200 {
		t.Fatalf("session after passkey login: %d", st)
	}
	// A second, valid sign-in after the counter was re-sealed must work.
	do("POST", "/v1/auth/logout", nil)
	delete(jar, "rostor_session")
	_, lbAgain := do("POST", "/v1/auth/login/passkey/begin", map[string]any{})
	if _, lfAgain := do("POST", "/v1/auth/login/passkey/finish", map[string]any{"ceremony_id": lbAgain["ceremony_id"], "response": synced.assert(lbAgain["options"].(map[string]any), danID)}); lfAgain["assurance"] != "AL2" {
		t.Fatalf("second passkey login: %v", lfAgain)
	}
	// Authenticators that never advance the counter (many synced passkeys
	// report 0) must keep working.
	zero := newSoftAuthenticator("example.org", "https://rostor.example.org", true)
	do("POST", "/v1/auth/login", map[string]any{"identifier": "dan", "fields": map[string]string{"password": "hunter2hunter2"}})
	_, bz := do("POST", "/v1/auth/passkeys/register/begin", nil)
	do("POST", "/v1/auth/passkeys/register/finish", map[string]any{"ceremony_id": bz["ceremony_id"], "label": "zero", "response": zero.register(bz["options"].(map[string]any))})
	do("POST", "/v1/auth/logout", nil)
	delete(jar, "rostor_session")
	for i := 0; i < 2; i++ {
		zero.count = 0 // stays 0 across sign-ins
		_, lbz := do("POST", "/v1/auth/login/passkey/begin", map[string]any{})
		zero.count = -1 // assert() increments to 0
		if _, lfz := do("POST", "/v1/auth/login/passkey/finish", map[string]any{"ceremony_id": lbz["ceremony_id"], "response": zero.assert(lbz["options"].(map[string]any), danID)}); lfz["assurance"] != "AL2" {
			t.Fatalf("zero-counter passkey login %d: %v", i+1, lfz)
		}
		do("POST", "/v1/auth/logout", nil)
		delete(jar, "rostor_session")
	}

	// A replayed assertion (same counter) fails.
	do("POST", "/v1/auth/logout", nil)
	delete(jar, "rostor_session")
	st, lb2 := do("POST", "/v1/auth/login/passkey/begin", map[string]any{"identifier": "dan"})
	synced.count-- // pretend the authenticator did not advance
	_, lf2 := do("POST", "/v1/auth/login/passkey/finish", map[string]any{"ceremony_id": lb2["ceremony_id"], "response": synced.assert(lb2["options"].(map[string]any), danID)})
	if lf2["code"] != "auth.failed" {
		t.Fatalf("cloned counter should fail: %v", lf2)
	}

	// A device-bound passkey (not backup-eligible) → AL3.
	do("POST", "/v1/auth/login", map[string]any{"identifier": "dan", "fields": map[string]string{"password": "hunter2hunter2"}})
	hw := newSoftAuthenticator("example.org", "https://rostor.example.org", false)
	_, b2 := do("POST", "/v1/auth/passkeys/register/begin", nil)
	if st, out := do("POST", "/v1/auth/passkeys/register/finish", map[string]any{"ceremony_id": b2["ceremony_id"], "label": "YubiKey", "response": hw.register(b2["options"].(map[string]any))}); st != 201 {
		t.Fatalf("hw register: %d %v", st, out)
	}
	do("POST", "/v1/auth/logout", nil)
	delete(jar, "rostor_session")
	_, lb3 := do("POST", "/v1/auth/login/passkey/begin", map[string]any{})
	if _, lf3 := do("POST", "/v1/auth/login/passkey/finish", map[string]any{"ceremony_id": lb3["ceremony_id"], "response": hw.assert(lb3["options"].(map[string]any), danID)}); lf3["assurance"] != "AL3" {
		t.Fatalf("hardware-bound passkey should be AL3: %v", lf3)
	}
}
