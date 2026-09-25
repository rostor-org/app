// Package scripts is the agent half of SPEC-scripts (contract §1.4): it
// verifies the core's signature on every delivered script, decides which
// ones are due, runs them one at a time through powershell.exe, and reports
// each run back. Nothing here runs a body whose signature did not verify
// against the pinned CA bundle — that is the whole security posture of the
// feature, so verification is a separate pure function with its own tests.
package scripts

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"strconv"

	"rostor.org/app/cmd/rostor-agent/internal/core"
	"rostor.org/app/cmd/rostor-agent/internal/trust"
)

// Script is the wire type; aliased so callers of this package need not
// import core for the plain data.
type Script = core.Script

// Run is a run report (§1.4).
type Run = core.ScriptRun

// Verification failures. ErrSignature is the one that matters operationally:
// it means the body on the wire is not what the core signed.
var (
	ErrSignature = errors.New("script signature does not verify against the trust bundle")
	ErrNoCA      = errors.New("trust bundle holds no certificates")
)

// SignedMessage returns the bytes the core signs for a script: id, version
// (decimal) and body joined by newlines. Kept exported so a test can sign
// exactly what the agent verifies.
func SignedMessage(id string, version int, body string) []byte {
	return []byte(id + "\n" + strconv.Itoa(version) + "\n" + body)
}

// Verify checks the script's signature against every CA certificate in the
// PEM bundle (ca.crt holds all active CAs, so a script signed by the previous
// CA during a rotation still verifies). The signer id is informational: the
// agent has no key-id map, and trying every CA is cheap.
func Verify(s Script, caPEMs []byte) error {
	certs, err := trust.ParseBundle(caPEMs)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrNoCA, err)
	}
	if s.Signature == "" {
		return fmt.Errorf("%w: empty signature", ErrSignature)
	}
	sig, err := base64.StdEncoding.DecodeString(s.Signature)
	if err != nil {
		return fmt.Errorf("%w: signature is not base64: %v", ErrSignature, err)
	}
	digest := sha256.Sum256(SignedMessage(s.ID, s.Version, s.Body))
	for _, c := range certs {
		pub, ok := c.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			continue
		}
		if ecdsa.VerifyASN1(pub, digest[:], sig) {
			return nil
		}
	}
	return ErrSignature
}

// Plan returns the immediate scripts that have not yet run at their current
// version, in run order: position ascending, then id so the order is total
// and stable across heartbeats. A script listed twice with the same mode is
// planned once.
func Plan(list []Script, state *State) []Script {
	var due []Script
	seen := map[string]bool{}
	for _, s := range list {
		if s.Mode != core.ScriptModeImmediate || seen[s.ID] {
			continue
		}
		seen[s.ID] = true
		if s.Version > state.Get(s.ID).ImmediateVersionRan {
			due = append(due, s)
		}
	}
	sortScripts(due)
	return due
}

// PlanSignin returns every sign-in script in run order.
func PlanSignin(list []Script) []Script {
	var due []Script
	seen := map[string]bool{}
	for _, s := range list {
		if s.Mode != core.ScriptModeSignin || seen[s.ID] {
			continue
		}
		seen[s.ID] = true
		due = append(due, s)
	}
	sortScripts(due)
	return due
}

func sortScripts(list []Script) {
	sort.SliceStable(list, func(i, j int) bool {
		if list[i].Position != list[j].Position {
			return list[i].Position < list[j].Position
		}
		return list[i].ID < list[j].ID
	})
}
