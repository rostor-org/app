package auth

import (
	"context"
	"errors"
	"time"

	"rostor.org/app/internal/crypto"
)

// PasswordMethod is the opt-in fallback method (§7.1). It declares a single
// knowledge factor and therefore derives to AL1 on its own; policy that wants
// AL2 will demand a second binding, never a stronger password.
type PasswordMethod struct {
	Provider crypto.Provider
}

func (m *PasswordMethod) Describe() Description {
	return Description{Method: "password", Properties: []string{"knowledge"}, Modes: []string{"inline"}, Assurance: "AL1"}
}

func (m *PasswordMethod) Enroll(ctx context.Context, in StepInput) ([]byte, []Identifier, error) {
	pw := in.Fields["password"]
	if len(pw) < 8 {
		return nil, nil, errors.New("password too short")
	}
	mat, err := m.Provider.PasswordHash([]byte(pw))
	return mat, nil, err
}

// A password never identifies the user; it is always identifier-first.
func (m *PasswordMethod) Identify(StepInput) []Identifier { return nil }

func (m *PasswordMethod) Authenticate(ctx context.Context, bindingID string, mat SealedMaterial, in StepInput, _ map[string]any) (StepResult, error) {
	stored, err := mat.Read(ctx)
	if err != nil {
		return StepResult{}, err
	}
	ok, err := m.Provider.PasswordVerify(stored, []byte(in.Fields["password"]))
	if err != nil {
		return StepResult{}, err
	}
	if !ok {
		return StepResult{Failed: true}, nil
	}
	d := m.Describe()
	return StepResult{Assertion: &Assertion{Method: d.Method, BindingID: bindingID, At: time.Now().UTC(),
		Properties: d.Properties, Assurance: d.Assurance}}, nil
}
