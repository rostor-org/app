// Package core is the agent's client for the Rostor core HTTP API (contract
// §1). The Verifier interface lets the broker be tested without a server and
// lets `run --mock-core` stand in for core until it exists.
package core

import "context"

// Credential is the §1.2 credential presentation. Only "password" is used by
// this slice; the shape is kept generic so a badge type slots in unchanged.
type Credential struct {
	Type       string `json:"type"`
	Identifier string `json:"identifier,omitempty"`
	Secret     string `json:"secret,omitempty"`
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

// VerifyResponse is the §1.2 response body for either decision.
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
