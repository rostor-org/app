// Package ids mints opaque, prefixed, never-reused identifiers.
package ids

import (
	"crypto/rand"
	"encoding/hex"
)

// New returns prefix + "_" + 16 random bytes in hex. Callers never parse the
// suffix; the prefix exists only so humans can tell object kinds apart in logs.
func New(prefix string) string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("ids: crypto/rand unavailable: " + err.Error())
	}
	return prefix + "_" + hex.EncodeToString(b[:])
}

// Token returns a URL-safe secret of n random bytes, hex encoded. Used for
// bearer-style secrets that are stored only as hashes.
func Token(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("ids: crypto/rand unavailable: " + err.Error())
	}
	return hex.EncodeToString(b)
}
