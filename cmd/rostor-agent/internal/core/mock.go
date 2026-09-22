package core

import "context"

// Mock is the `--mock-core` verifier: ALLOW for one identifier with any
// secret, DENY auth.failed otherwise, no network. It exists so the pipe →
// local account → reply path can be exercised before core is running.
type Mock struct {
	AllowIdentifier string
}

// Verify implements Verifier.
func (m Mock) Verify(_ context.Context, req VerifyRequest) (*VerifyResponse, error) {
	if req.Credential.Type == "password" && req.Credential.Identifier == m.AllowIdentifier {
		return &VerifyResponse{
			Decision:  "ALLOW",
			Principal: &Principal{ID: "usr_mock", Username: m.AllowIdentifier, DisplayName: "Mock Test User"},
			Assurance: "AL1",
			Reason:    []Reason{{Code: "grant.matched", Params: map[string]any{"grant_id": "mock"}}},
		}, nil
	}
	// The mock has no catalog of its own; the broker renders auth.failed from
	// the agent catalog when core supplies no message, exactly as it would
	// for a real core reply that omitted one.
	return &VerifyResponse{Decision: "DENY", Reason: []Reason{{Code: "auth.failed"}}}, nil
}
