// Package core is the deputy's client for the Rostor core HTTP API (contract
// §1). The Verifier interface lets the broker be tested without a server and
// lets `run --mock-core` stand in for core until it exists.
package core

import (
	"context"
	"time"
)

// Credential is the §1.2 credential presentation: "password" carries
// identifier+secret, "badge" carries the number as typed by a reader plus an
// optional PIN. Core derives the other badge forms (uid, facility+card) itself.
type Credential struct {
	Type       string `json:"type"`
	Identifier string `json:"identifier,omitempty"`
	Secret     string `json:"secret,omitempty"`
	Number     string `json:"number,omitempty"`
	PIN        string `json:"pin,omitempty"`
}

// Resource identifies the workstation this deputy enrolled as.
type Resource struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// VerifyRequest is the §1.2 request body.
type VerifyRequest struct {
	Credential Credential `json:"credential"`
	Action     string     `json:"action"`
	Resource   Resource   `json:"resource"`
	Locale     string     `json:"locale"`
}

// Principal is the subset of the §1.2 ALLOW response the deputy needs.
type Principal struct {
	ID          string `json:"id"`
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
}

// Reason is one entry of the §1.2 reason list.
type Reason struct {
	Code   string         `json:"code"`
	Params map[string]any `json:"params,omitempty"`
}

// Decisions core can answer. CONTINUE (reason auth.continue) means the
// credential matched but the presenter must add something — for a badge, the
// PIN — before a decision is made; nothing has been allowed or denied yet.
const (
	DecisionAllow    = "ALLOW"
	DecisionDeny     = "DENY"
	DecisionContinue = "CONTINUE"
)

// CodeContinue is the reason code that accompanies DecisionContinue.
const CodeContinue = "auth.continue"

// VerifyResponse is the §1.2 response body for any decision. SessionAccount
// ("Shared session account", v0.13.0) names a local account the session
// must run as instead of the person's own derived account; the person is
// still the one core audited and the one named in the deputy's log.
type VerifyResponse struct {
	Decision       string     `json:"decision"`
	Principal      *Principal `json:"principal,omitempty"`
	Assurance      string     `json:"assurance,omitempty"`
	Reason         []Reason   `json:"reason,omitempty"`
	Message        string     `json:"message,omitempty"`
	SessionAccount string     `json:"session_account,omitempty"`
}

// Verifier is the one core operation the logon path depends on.
type Verifier interface {
	Verify(ctx context.Context, req VerifyRequest) (*VerifyResponse, error)
}

// FirstCode returns the leading reason code, or "" when there is none.
func (r *VerifyResponse) FirstCode() string {
	if r == nil || len(r.Reason) == 0 {
		return ""
	}
	return r.Reason[0].Code
}

// Need returns what a CONTINUE asks for (reason params "need"), defaulting
// to "pin", which is the only continuation this slice knows.
func (r *VerifyResponse) Need() string {
	if r != nil && len(r.Reason) > 0 {
		if s, ok := r.Reason[0].Params["need"].(string); ok && s != "" {
			return s
		}
	}
	return "pin"
}

// TrustResponse is GET /v1/devices/self/trust (console-api.md, "Certificates
// and trust"). CAPEMs lists every active CA, newest first; Version changes
// whenever that set changes. Renew is core's own verdict: expiry within 30
// days, issuing CA no longer the newest, or the device is presenting a
// superseded certificate inside the grace window.
type TrustResponse struct {
	Version      string    `json:"version"`
	CAPEMs       []string  `json:"ca_pems"`
	Renew        bool      `json:"renew"`
	CertNotAfter time.Time `json:"cert_not_after"`
}

// RenewResponse is POST /v1/devices/self/renew.
type RenewResponse struct {
	CertificatePEM string    `json:"certificate_pem"`
	NotAfter       time.Time `json:"not_after"`
	CAPEMs         []string  `json:"ca_pems"`
	TrustVersion   string    `json:"trust_version"`
}

// Script is one entry of GET /v1/devices/self/scripts (§1.4). Version
// increments whenever the body changes; Position orders scripts across the
// tenant; Mode is "immediate" (run once per version) or "signin" (run at
// every sign-in). Signature is base64 ASN.1 DER ECDSA P-256 over SHA-256 of
// id + "\n" + version + "\n" + body, made with the CA key named by Signer.
type Script struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Language  string `json:"language"`
	Version   int    `json:"version"`
	Position  int    `json:"position"`
	Mode      string `json:"mode"`
	Body      string `json:"body"`
	Signature string `json:"signature"`
	Signer    string `json:"signer"`
}

// Script modes (§1.4).
const (
	ScriptModeImmediate = "immediate"
	ScriptModeSignin    = "signin"
)

// ScriptRun is the body of POST /v1/devices/self/scripts/{id}/runs (§1.4).
type ScriptRun struct {
	Version     int       `json:"version"`
	Mode        string    `json:"mode"`
	PrincipalID string    `json:"principal_id"`
	StartedAt   time.Time `json:"started_at"`
	FinishedAt  time.Time `json:"finished_at"`
	ExitCode    int       `json:"exit_code"`
	Status      string    `json:"status"`
	OutputTail  string    `json:"output_tail"`
}

// Run statuses (§1.4): ok for exit 0, failed for any other exit code,
// timeout after the run limit, error when PowerShell could not be started.
const (
	RunOK      = "ok"
	RunFailed  = "failed"
	RunTimeout = "timeout"
	RunError   = "error"
)

// PolicyResponse is GET /v1/devices/self/policy (§1.5): the tenant's auth
// policy as it applies to this device. Login.DefaultMethod is one of the
// DefaultMethod* constants; Badge.Format names the card format the tenant's
// readers produce ("none" when badges are not in use). TenantName (§1.5a,
// v0.13.0) is the organisation's display name for the lock-screen heading;
// a core older than the contract omits it and the heading is rendered
// without it. Logon (v0.13.0) carries the lock-screen policy: which tile
// is selected when the lock screen appears (DefaultProvider, one of the
// DefaultProvider* constants, empty meaning rostor) and the shared local
// account a session runs as, if any (SessionAccount; informational here,
// the value that counts arrives on the ALLOW itself).
type PolicyResponse struct {
	Login struct {
		DefaultMethod string `json:"default_method"`
	} `json:"login"`
	Badge struct {
		Format string `json:"format"`
	} `json:"badge"`
	TenantName string `json:"tenant_name"`
	Logon      struct {
		SessionAccount  string `json:"session_account"`
		DefaultProvider string `json:"default_provider"`
	} `json:"logon"`
}

// Default sign-in methods a policy can name (§1.5).
const (
	DefaultMethodPassword = "password"
	DefaultMethodPasskey  = "passkey"
	DefaultMethodBadge    = "badge"
)

// Lock-screen default providers a policy can name ("Which tile is the
// default", v0.13.0): rostor selects the Rostor tile, windows leaves the
// selection to Windows' own password tile with Rostor one click away.
const (
	DefaultProviderRostor  = "rostor"
	DefaultProviderWindows = "windows"
)

// UpdateInfo is the non-null half of GET /v1/devices/self/update (§1.6):
// the deputy version this device should run, the sha256 (hex) and byte
// size of rostor-windows-amd64.zip, and the core's signature over
// "bundle\n" + version + "\n" + sha256 (base64 ASN.1 DER ECDSA P-256 with
// the CA key named by Signer, verified against ca.crt like a script).
type UpdateInfo struct {
	Version   string `json:"version"`
	SHA256    string `json:"sha256"`
	Signature string `json:"signature"`
	Signer    string `json:"signer"`
	Size      int64  `json:"size"`
}

// UpdateResponse is GET /v1/devices/self/update. Update is nil when the
// device should stay as it is.
type UpdateResponse struct {
	Update *UpdateInfo `json:"update"`
}

// UpdateRun is the body of POST /v1/devices/self/update/runs (§1.6): the
// outcome of an update attempt, sent by whichever deputy comes up after
// the installer ran. Status is RunOK when the running version equals the
// version that was installed, RunFailed otherwise.
type UpdateRun struct {
	Version     string `json:"version"`
	Status      string `json:"status"`
	FromVersion string `json:"from_version"`
	OutputTail  string `json:"output_tail"`
}
