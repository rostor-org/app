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

// Method is the §7.6 plugin contract as seen from core.
type Method interface {
	Describe() Description
	// Enroll returns the material to seal for a new binding of this method.
	Enroll(ctx context.Context, input StepInput) (material []byte, err error)
	// Authenticate performs one ceremony step against the binding's material.
	Authenticate(ctx context.Context, bindingID string, material SealedMaterial, input StepInput, state map[string]any) (StepResult, error)
}
