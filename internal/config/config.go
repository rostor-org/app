// Package config reads process configuration from the environment. Only
// deployment facts live here (where the database is, where keys are); every
// behavioural setting is a policy (spec §4).
package config

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type Config struct {
	DatabaseURL string
	DataDir     string // master key + TLS material for self-hosted PoC
	Listen      string
	TLSHosts    []string // SANs for the core's own certificate
	// AdminListen is an optional plain-HTTP listener for traffic that arrives
	// through a TLS-terminating reverse proxy (admin API, future UI). Device
	// endpoints need a client certificate and so never work through it.
	AdminListen    string
	TrustedProxies []string // peers whose X-Forwarded-* headers are believed
	StateDir       string   // runtime state (update requests/status); DataDir if empty
	ReleasePubKey  string   // path to the pinned release-signing public key
}

func FromEnv() Config {
	home, _ := os.UserHomeDir()
	c := Config{
		DatabaseURL:   getenv("ROSTOR_DATABASE_URL", "postgres:///rostor_dev?sslmode=disable"),
		DataDir:       getenv("ROSTOR_DATA_DIR", filepath.Join(home, ".rostor")),
		Listen:        getenv("ROSTOR_LISTEN", ":8443"),
		AdminListen:   os.Getenv("ROSTOR_ADMIN_LISTEN"),
		StateDir:      os.Getenv("ROSTOR_STATE_DIR"),
		ReleasePubKey: getenv("ROSTOR_RELEASE_PUBKEY", "/etc/rostor/release.pub"),
	}
	if p := os.Getenv("ROSTOR_TRUSTED_PROXIES"); p != "" {
		c.TrustedProxies = strings.Split(p, ",")
	}
	if c.StateDir == "" {
		c.StateDir = c.DataDir
	}
	if h := os.Getenv("ROSTOR_TLS_HOSTS"); h != "" {
		c.TLSHosts = strings.Split(h, ",")
	}
	return c
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// MasterKey loads the 32-byte provider master key from DataDir/master.key,
// creating it on first use. This is the PoC key-at-rest story; the production
// one is the crypto-provider's KMS/HSM binding (spec §12).
func (c Config) MasterKey(create bool) ([]byte, error) {
	path := filepath.Join(c.DataDir, "master.key")
	raw, err := os.ReadFile(path)
	if err == nil {
		k, err := hex.DecodeString(strings.TrimSpace(string(raw)))
		if err != nil || len(k) != 32 {
			return nil, fmt.Errorf("config: %s is not a 32-byte hex key", path)
		}
		return k, nil
	}
	if !errors.Is(err, os.ErrNotExist) || !create {
		return nil, fmt.Errorf("config: master key: %w", err)
	}
	if err := os.MkdirAll(c.DataDir, 0o700); err != nil {
		return nil, err
	}
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, []byte(hex.EncodeToString(k)+"\n"), 0o600); err != nil {
		return nil, err
	}
	return k, nil
}
