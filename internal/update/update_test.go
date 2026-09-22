package update

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

func TestSignVerify(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	m := Manifest{Channel: "stable", Version: "v0.1.0", Published: time.Now().UTC(),
		Files: map[string]File{"linux-amd64": {URL: "https://x/y", SHA256: "ab", Size: 1}}}
	if err := Sign(&m, priv); err != nil {
		t.Fatal(err)
	}
	if err := Verify(m, pub); err != nil {
		t.Fatal(err)
	}
	m.Version = "v9.9.9"
	if err := Verify(m, pub); err == nil {
		t.Fatal("tampered manifest verified")
	}
}

func TestNewerThan(t *testing.T) {
	cases := []struct{ a, b string; want bool }{
		{"v0.2.0", "v0.1.9", true}, {"v0.1.0", "v0.1.0", false}, {"v1.0.0", "dev", true},
		{"dev", "v1.0.0", false}, {"v0.1.0-rc1", "v0.1.0", false}, {"v0.10.0", "v0.9.0", true},
	}
	for _, c := range cases {
		if got := NewerThan(c.a, c.b); got != c.want {
			t.Errorf("NewerThan(%s,%s)=%v want %v", c.a, c.b, got, c.want)
		}
	}
}
