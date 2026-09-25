// Package localuser derives and manages the local Windows account for a
// principal (contract §3). Only this file is portable; the netapi32 calls are
// in accounts_windows.go.
package localuser

import (
	"regexp"
	"strings"
)

// The contract fixes the accepted shape after lowercasing. Windows itself
// accepts more, but a narrow set keeps the derived account name predictable
// and rules out names that need quoting anywhere.
var usernameRE = regexp.MustCompile(`^[a-z0-9._-]{1,20}$`)

// Comment marks deputy-managed accounts for humans looking at lusrmgr.
const Comment = "Managed by Rostor — do not edit"

// NormalizeUsername lowercases a principal username and reports whether it is
// acceptable as a local account name.
func NormalizeUsername(s string) (string, bool) {
	u := strings.ToLower(strings.TrimSpace(s))
	if !usernameRE.MatchString(u) {
		return "", false
	}
	// A name of only dots is legal by the regex but is not a usable account
	// name on Windows ("." and ".." are rejected by SAM).
	if strings.Trim(u, ".") == "" {
		return "", false
	}
	return u, true
}
