// Package core is the agent's client for the Rostor core HTTP API (contract
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

// Resource identifies the workstation this agent enrolled as.
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

// Principal is the subset of the §1.2 ALLOW response the agent needs.
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

// VerifyResponse is the §1.2 response body for any decision.
type VerifyResponse struct {
	Decision  string     `json:"decision"`
	Principal *Principal `json:"principal,omitempty"`
	Assurance string     `json:"assurance,omitempty"`
	Reason    []Reason   `json:"reason,omitempty"`
	Message   string     `json:"message,omitempty"`
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
