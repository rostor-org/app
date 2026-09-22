package localuser

import (
	"strings"
	"testing"
)

func TestNewSecret(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		s, err := NewSecret()
		if err != nil {
			t.Fatal(err)
		}
		if len(s) != SecretLength {
			t.Fatalf("len=%d", len(s))
		}
		if seen[s] {
			t.Fatal("duplicate secret")
		}
		seen[s] = true
		if !strings.ContainsAny(s, "0123456789") || !strings.ContainsAny(s, "!#%+-.=?@_~") {
			t.Fatalf("secret lacks a class: %s", s)
		}
	}
}
