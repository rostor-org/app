package core

import "context"

// Mock is the `--mock-core` verifier: no network, fixed answers so the pipe →
// local account → reply path can be exercised before core is running.
//
//   - password: ALLOW for AllowIdentifier with any secret, else auth.failed.
//   - badge MockBadgePlain: ALLOW as AllowIdentifier.
//   - badge MockBadgePIN: CONTINUE (auth.continue, need pin) until the PIN
//     MockPIN is supplied, then ALLOW as AllowIdentifier.
//   - any other badge: auth.failed.
type Mock struct {
	AllowIdentifier string
}

// Badge numbers and PIN the mock recognises (documented in windows-logon-build.md).
const (
	MockBadgePlain = "1234567890"
	MockBadgePIN   = "5555555555"
	MockPIN        = "2468"
)

// Verify implements Verifier.
func (m Mock) Verify(_ context.Context, req VerifyRequest) (*VerifyResponse, error) {
	c := req.Credential
	switch {
	case c.Type == "password" && c.Identifier == m.AllowIdentifier:
		return m.allow("AL1"), nil
	case c.Type == "badge" && c.Number == MockBadgePlain:
		return m.allow("AL1"), nil
	case c.Type == "badge" && c.Number == MockBadgePIN && c.PIN == "":
		// The mock has no catalog; the broker renders auth.continue from the
		// agent catalog when core supplies no message.
		return &VerifyResponse{Decision: DecisionContinue, Reason: []Reason{{Code: CodeContinue, Params: map[string]any{"need": "pin"}}}}, nil
	case c.Type == "badge" && c.Number == MockBadgePIN && c.PIN == MockPIN:
		return m.allow("AL2"), nil
	}
	// Same rendering fallback as above: the broker fills auth.failed from
	// the agent catalog, exactly as for a real core reply that omitted text.
	return &VerifyResponse{Decision: DecisionDeny, Reason: []Reason{{Code: "auth.failed"}}}, nil
}

func (m Mock) allow(assurance string) *VerifyResponse {
	return &VerifyResponse{
		Decision:  DecisionAllow,
		Principal: &Principal{ID: "usr_mock", Username: m.AllowIdentifier, DisplayName: "Mock Test User"},
		Assurance: assurance,
		Reason:    []Reason{{Code: "grant.matched", Params: map[string]any{"grant_id": "mock"}}},
	}
}

// Scripts implements the §1.4 fetch for the mock: there is nothing to run.
func (m Mock) Scripts(_ context.Context) ([]Script, error) { return nil, nil }

// ReportRun accepts and discards a run report.
func (m Mock) ReportRun(_ context.Context, _ string, _ ScriptRun) error { return nil }

// Policy implements the §1.5 fetch for the mock: password first, no badges.
func (m Mock) Policy(_ context.Context) (*PolicyResponse, error) {
	var p PolicyResponse
	p.Login.DefaultMethod = DefaultMethodPassword
	p.Badge.Format = "none"
	return &p, nil
}
