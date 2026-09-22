package localuser

import "errors"

// Manager is what the broker needs from the local account layer. The Windows
// implementation is in accounts_windows.go; tests use a fake.
type Manager interface {
	// EnsureEnabled creates the account if missing, sets a fresh secret,
	// clears the disabled flag and returns the secret.
	EnsureEnabled(username, displayName string) (secret string, err error)
	// Disable sets UF_ACCOUNTDISABLE if the account exists and is on the
	// ledger. A missing account is not an error.
	Disable(username string) error
}

// ErrNotManaged is returned when an account exists but is not on the ledger.
// The agent must never touch such accounts (contract §3).
var ErrNotManaged = errors.New("localuser: account exists but is not managed by Rostor")
