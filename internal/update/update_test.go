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
	cases := []struct {
		a, b string
		want bool
	}{
		{"v0.2.0", "v0.1.9", true}, {"v0.1.0", "v0.1.0", false}, {"v1.0.0", "dev", true},
		{"dev", "v1.0.0", false}, {"v0.1.0-rc1", "v0.1.0", false}, {"v0.10.0", "v0.9.0", true},
	}
	for _, c := range cases {
		if got := NewerThan(c.a, c.b); got != c.want {
			t.Errorf("NewerThan(%s,%s)=%v want %v", c.a, c.b, got, c.want)
		}
	}
}

func TestMinUpgradeFrom(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	m := Manifest{Channel: "stable", Version: "v2.0.0", MinUpgradeFrom: "v1.5.0", Published: time.Now().UTC(),
		Files: map[string]File{"linux-amd64": {URL: "https://x/y", SHA256: "ab", Size: 1}}}
	if err := Sign(&m, priv); err != nil {
		t.Fatal(err)
	}
	if err := Verify(m, pub); err != nil {
		t.Fatal(err)
	}
	// Simulate Check's decision without the network.
	decide := func(current string) (available, blocked string) {
		if NewerThan(m.Version, current) {
			if m.MinUpgradeFrom != "" && NewerThan(m.MinUpgradeFrom, current) {
				return "", m.MinUpgradeFrom
			}
			return m.Version, ""
		}
		return "", ""
	}
	if a, b := decide("v1.2.0"); a != "" || b != "v1.5.0" {
		t.Fatalf("too old: available=%q blocked=%q", a, b)
	}
	if a, b := decide("v1.5.0"); a != "v2.0.0" || b != "" {
		t.Fatalf("stepping stone: available=%q blocked=%q", a, b)
	}
	if a, b := decide("v2.0.0"); a != "" || b != "" {
		t.Fatalf("current: available=%q blocked=%q", a, b)
	}
}
