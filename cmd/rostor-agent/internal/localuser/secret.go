package localuser

import (
	"crypto/rand"
	"fmt"
)

// SecretLength is fixed by the contract (§2.2: "32 random chars").
const SecretLength = 32

// Alphabet mixes the four classes Windows password complexity can require so
// the rotated secret never trips a local policy; every character is safe to
// pass through JSON and the Kerberos logon buffer unchanged.
const secretAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#%+-.=?@_~"

// NewSecret returns a 32-character random password with at least one
// character from each class. It is generated fresh on every logon and never
// written anywhere.
func NewSecret() (string, error) {
	for attempt := 0; attempt < 16; attempt++ {
		buf := make([]byte, SecretLength)
		if _, err := rand.Read(buf); err != nil {
			return "", err
		}
		out := make([]byte, SecretLength)
		var upper, lower, digit, symbol bool
		for i, b := range buf {
			c := secretAlphabet[int(b)%len(secretAlphabet)]
			out[i] = c
			switch {
			case c >= 'A' && c <= 'Z':
				upper = true
			case c >= 'a' && c <= 'z':
				lower = true
			case c >= '0' && c <= '9':
				digit = true
			default:
				symbol = true
			}
		}
		if upper && lower && digit && symbol {
			return string(out), nil
		}
	}
	return "", fmt.Errorf("localuser: could not generate a complex secret")
}
