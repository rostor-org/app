package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// WebAuthnMethod: passkeys (spec §7.2 "Passkey / WebAuthn"). A passkey is
// possession + user verification and phishing-resistant, which derives to
// AL2; a hardware-bound (non-synced) one derives to AL3. Synced passkeys
// held in a password manager are ordinary credentials here; the
// authenticator's backup flags tell the two apart, never a vendor list.
//
// Ceremonies are two-step (begin → finish) and the challenge state is kept
// by the core in the ceremonies table; this method only knows how to turn
// relying-party settings plus stored material into WebAuthn calls.
type WebAuthnMethod struct {
	// Settings returns the relying party for the tenant. It is a function so
	// the value comes from policy at call time, never from a build constant.
	Settings func(ctx context.Context) (RelyingParty, error)
	// Log receives the reason a verification failed (never secrets), so an
	// operator can tell an RP-ID mismatch from a bad counter. Optional.
	Log func(msg string, kv ...any)
}

func (m *WebAuthnMethod) logf(msg string, kv ...any) {
	if m.Log != nil {
		m.Log(msg, kv...)
	}
}

type RelyingParty struct {
	ID          string   // e.g. "chattlab.org"
	DisplayName string   // e.g. "ChattLab"
	Origins     []string // e.g. ["https://rostor.chattlab.org"]
}

type passkeyMaterial struct {
	Credential webauthn.Credential `json:"credential"`
}

func (m *WebAuthnMethod) Describe() Description {
	return Description{Method: "webauthn", Properties: []string{"possession", "user-verified", "phishing-resistant", "can-identify-user"},
		Modes: []string{"inline"}, Assurance: "AL2"}
}

func (m *WebAuthnMethod) lib(ctx context.Context) (*webauthn.WebAuthn, error) {
	rp, err := m.Settings(ctx)
	if err != nil {
		return nil, err
	}
	if rp.ID == "" || len(rp.Origins) == 0 {
		return nil, errors.New("passkeys are not configured: relying-party id and origins are unset")
	}
	return webauthn.New(&webauthn.Config{
		RPID: rp.ID, RPDisplayName: rp.DisplayName, RPOrigins: rp.Origins,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			ResidentKey: protocol.ResidentKeyRequirementPreferred, UserVerification: protocol.VerificationRequired},
		AttestationPreference: protocol.PreferNoAttestation,
		Timeouts: webauthn.TimeoutsConfig{
			Login:        webauthn.TimeoutConfig{Enforce: true, Timeout: 2 * time.Minute, TimeoutUVD: 2 * time.Minute},
			Registration: webauthn.TimeoutConfig{Enforce: true, Timeout: 2 * time.Minute, TimeoutUVD: 2 * time.Minute},
		},
	})
}

// user adapts a principal for the library. The WebAuthn user handle is the
// principal ID: stable, opaque, never reused.
type user struct {
	id, name, display string
	creds             []webauthn.Credential
}

func (u user) WebAuthnID() []byte                         { return []byte(u.id) }
func (u user) WebAuthnName() string                       { return u.name }
func (u user) WebAuthnDisplayName() string                { return u.display }
func (u user) WebAuthnCredentials() []webauthn.Credential { return u.creds }

// ---- registration -----------------------------------------------------------

// BeginRegistration returns the options for navigator.credentials.create and
// the session state the core must persist in the ceremony.
func (m *WebAuthnMethod) BeginRegistration(ctx context.Context, principalID, username, display string, existing []webauthn.Credential) (options any, state []byte, err error) {
	w, err := m.lib(ctx)
	if err != nil {
		return nil, nil, err
	}
	u := user{id: principalID, name: username, display: display, creds: existing}
	var excl []protocol.CredentialDescriptor
	for _, c := range existing {
		excl = append(excl, c.Descriptor())
	}
	opts, sess, err := w.BeginRegistration(u, webauthn.WithExclusions(excl))
	if err != nil {
		return nil, nil, err
	}
	state, err = json.Marshal(sess)
	return opts, state, err
}

// FinishRegistration validates the browser's response and returns the
// material to seal plus the identifiers to index (the credential ID).
func (m *WebAuthnMethod) FinishRegistration(ctx context.Context, principalID, username, display string, state []byte, response []byte) ([]byte, []Identifier, error) {
	w, err := m.lib(ctx)
	if err != nil {
		return nil, nil, err
	}
	var sess webauthn.SessionData
	if err := json.Unmarshal(state, &sess); err != nil {
		return nil, nil, err
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(response)
	if err != nil {
		return nil, nil, err
	}
	cred, err := w.CreateCredential(user{id: principalID, name: username, display: display}, sess, parsed)
	if err != nil {
		return nil, nil, err
	}
	raw, err := json.Marshal(passkeyMaterial{Credential: *cred})
	if err != nil {
		return nil, nil, err
	}
	return raw, []Identifier{{Kind: "webauthn.id", Value: base64.RawURLEncoding.EncodeToString(cred.ID)}}, nil
}

// ---- authentication ---------------------------------------------------------

// BeginLogin returns the options for navigator.credentials.get. With no
// allowed credentials it is a discoverable (identifier-less) request.
func (m *WebAuthnMethod) BeginLogin(ctx context.Context, allowed []webauthn.Credential) (options any, state []byte, err error) {
	w, err := m.lib(ctx)
	if err != nil {
		return nil, nil, err
	}
	var opts *protocol.CredentialAssertion
	var sess *webauthn.SessionData
	if len(allowed) == 0 {
		opts, sess, err = w.BeginDiscoverableLogin()
	} else {
		opts, sess, err = w.BeginLogin(user{creds: allowed})
	}
	if err != nil {
		return nil, nil, err
	}
	state, err = json.Marshal(sess)
	return opts, state, err
}

// Enroll is not used for passkeys: registration is a two-step ceremony
// (BeginRegistration/FinishRegistration) driven by the API.
func (m *WebAuthnMethod) Enroll(context.Context, StepInput) ([]byte, []Identifier, error) {
	return nil, nil, errors.New("passkeys enroll through the registration ceremony")
}

// Identify extracts the credential ID from a finished assertion so the core
// can find the binding without a username (discoverable passkeys).
func (m *WebAuthnMethod) Identify(in StepInput) []Identifier {
	resp := in.Fields["response"]
	if resp == "" {
		return nil
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes([]byte(resp))
	if err != nil {
		return nil
	}
	return []Identifier{{Kind: "webauthn.id", Value: base64.RawURLEncoding.EncodeToString(parsed.RawID)}}
}

// Authenticate finishes the login ceremony: state (from Begin) and the
// browser's assertion arrive in the input; the stored credential is the
// sealed material. Sign-count updates are returned via the assertion's
// material update so the core can re-seal them.
func (m *WebAuthnMethod) Authenticate(ctx context.Context, bindingID string, sm SealedMaterial, in StepInput, _ map[string]any) (StepResult, error) {
	w, err := m.lib(ctx)
	if err != nil {
		return StepResult{}, err
	}
	raw, err := sm.Read(ctx)
	if err != nil {
		return StepResult{}, err
	}
	var mat passkeyMaterial
	if err := json.Unmarshal(raw, &mat); err != nil {
		return StepResult{Failed: true}, nil
	}
	var sess webauthn.SessionData
	if err := json.Unmarshal([]byte(in.Fields["state"]), &sess); err != nil {
		m.logf("webauthn: bad ceremony state", "binding", bindingID, "err", err)
		return StepResult{Failed: true}, nil
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes([]byte(in.Fields["response"]))
	if err != nil {
		m.logf("webauthn: unparseable assertion", "binding", bindingID, "err", err)
		return StepResult{Failed: true}, nil
	}
	// For identifier-first ceremonies the session carries the expected user
	// handle; for discoverable ones the handle comes from the assertion and
	// must match the binding's principal, which the core checked by
	// credential ID. Either way the binding decides, never the caller.
	if exp := in.Fields["expect_principal"]; exp != "" && string(sess.UserID) != exp {
		m.logf("webauthn: assertion for a different principal than the ceremony", "binding", bindingID)
		return StepResult{Failed: true}, nil
	}
	if len(sess.UserID) == 0 {
		sess.UserID = parsed.Response.UserHandle
	}
	u := user{id: string(sess.UserID), creds: []webauthn.Credential{mat.Credential}}
	cred, err := w.ValidateLogin(u, sess, parsed)
	if err != nil {
		m.logf("webauthn: assertion rejected", "binding", bindingID, "err", err,
			"stored_count", mat.Credential.Authenticator.SignCount, "presented_count", parsed.Response.AuthenticatorData.Counter)
		return StepResult{Failed: true}, nil
	}
	if cred.Authenticator.CloneWarning {
		m.logf("webauthn: clone warning (counter did not advance)", "binding", bindingID,
			"stored_count", mat.Credential.Authenticator.SignCount, "presented_count", parsed.Response.AuthenticatorData.Counter)
		return StepResult{Failed: true}, nil
	}
	props := []string{"possession", "user-verified", "phishing-resistant", "can-identify-user"}
	assurance := "AL2"
	// Device-bound (not backup-eligible) passkeys are hardware-bound → AL3.
	if !cred.Flags.BackupEligible {
		props = append(props, "hardware-bound")
		assurance = "AL3"
	}
	updated, _ := json.Marshal(passkeyMaterial{Credential: *cred})
	return StepResult{Assertion: &Assertion{Method: "webauthn", BindingID: bindingID, At: time.Now().UTC(), Properties: props, Assurance: assurance,
		UpdatedMaterial: updated}}, nil
}

// StoredCredential decodes sealed material back to the library type (for
// exclusion lists and identifier-first login).
func StoredCredential(raw []byte) (*webauthn.Credential, error) {
	var mat passkeyMaterial
	if err := json.Unmarshal(raw, &mat); err != nil {
		return nil, err
	}
	return &mat.Credential, nil
}
