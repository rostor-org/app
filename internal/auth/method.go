// Package auth owns authenticator bindings, the sealed credential store, the
// ceremony contract, cross-method lockout, sessions and API tokens (spec §7).
//
// Methods are plugins behind the §7.6 contract. In this slice the password
// method is compiled in-process, but it only ever sees the contract: it
// verifies against sealed bytes the core hands it and returns an assertion.
// It cannot read the principal table and it cannot mint a session.
package auth

import (
	"context"
	"time"
)

// Description is what a method declares about itself (§7.2 properties).
type Description struct {
	Method     string
	Properties []string // knowledge | possession | inherence | phishing-resistant | hardware-bound | can-identify-user | usable-for-recovery | delegated
	Modes      []string // inline | redirect | out_of_band | headless
	Assurance  string   // derived tier for a single use of this method
}

// Assertion is the only thing a method can hand the core: "method M verified
// the holder of binding B at time T with properties C".
type Assertion struct {
	Method     string
	BindingID  string
	At         time.Time
	Properties []string
	Assurance  string
	// UpdatedMaterial, when set, is re-sealed by the core after a successful
	// step (e.g. a passkey's sign counter). Methods never write storage.
	UpdatedMaterial []byte
}

// StepInput is one step of a ceremony. Inline methods complete in one step;
// others return Continue with state for the next step.
type StepInput struct {
	Fields map[string]string
}

// StepResult is either an Assertion (done), a Continue (more steps), or a
// failure (Failed=true, never with a reason that distinguishes "no such user"
// from "wrong secret").
type StepResult struct {
	Assertion *Assertion
	Continue  map[string]any
	Failed    bool
}

// SealedMaterial is the core-provided view of a binding's secret material:
// opaque bytes the method wrote at enrollment and reads at authentication.
type SealedMaterial interface {
	Read(ctx context.Context) ([]byte, error)
}

// Identifier is a value by which a credential can be found without a
// username (property can-identify-user). Kinds are method-scoped, e.g.
// "badge.uid", "webauthn.id". The core owns the lookup table; methods only
// declare what to index and how to canonicalise a presented value.
type Identifier struct {
	Kind  string
	Value string
}

// Method is the §7.6 plugin contract as seen from core.
type Method interface {
	Describe() Description
	// Enroll returns the material to seal for a new binding of this method,
	// plus the identifiers the core should index for it (may be empty).
	Enroll(ctx context.Context, input StepInput) (material []byte, ids []Identifier, err error)
	// Identify canonicalises a presentation into the identifiers to look up,
	// for methods whose credential names the user. Nil for methods that
	// require an identifier-first flow (password).
	Identify(input StepInput) []Identifier
	// Authenticate performs one ceremony step against the binding's material.
	Authenticate(ctx context.Context, bindingID string, material SealedMaterial, input StepInput, state map[string]any) (StepResult, error)
}
