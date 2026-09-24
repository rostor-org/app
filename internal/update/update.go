// Package update implements the signed release channel (spec §13 "Staged"
// class: deliberate, visible rollouts). A channel is a JSON manifest served
// over HTTPS and signed with the release key whose public half is pinned at
// install time. Nothing is ever pulled from git and nothing is built on the
// appliance: the binary is downloaded, its digest checked against the signed
// manifest, and swapped into place atomically.
package update

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Manifest is what a channel publishes. The signature covers the canonical
// JSON of Manifest with Signature empty.
type Manifest struct {
	Channel   string    `json:"channel"`
	Version   string    `json:"version"`
	Published time.Time `json:"published"`
	Notes     string    `json:"notes,omitempty"`
	// MinUpgradeFrom, when set, is the oldest running version this release
	// can be applied from in one jump; older boxes must install that version
	// first. Optional and additive, so old updaters ignore it safely.
	MinUpgradeFrom string          `json:"min_upgrade_from,omitempty"`
	Files          map[string]File `json:"files"`               // key: "<os>-<arch>", e.g. linux-amd64
	Signature      string          `json:"signature,omitempty"` // base64 ed25519 over canonical bytes
}

type File struct {
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// Canonical returns the bytes that are signed: the manifest with Signature
// cleared, encoded by encoding/json (deterministic key order for structs).
func (m Manifest) Canonical() ([]byte, error) {
	m.Signature = ""
	return json.Marshal(m)
}

func Sign(m *Manifest, priv ed25519.PrivateKey) error {
	b, err := m.Canonical()
	if err != nil {
		return err
	}
	m.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, b))
	return nil
}

func Verify(m Manifest, pub ed25519.PublicKey) error {
	sig, err := base64.StdEncoding.DecodeString(m.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return errors.New("update: manifest signature malformed")
	}
	b, err := m.Canonical()
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, b, sig) {
		return errors.New("update: manifest signature invalid")
	}
	return nil
}

// LoadPublicKey reads a pinned key file: base64 or hex of 32 bytes, one line.
func LoadPublicKey(path string) (ed25519.PublicKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	s := strings.TrimSpace(string(raw))
	if b, err := hex.DecodeString(s); err == nil && len(b) == ed25519.PublicKeySize {
		return ed25519.PublicKey(b), nil
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil && len(b) == ed25519.PublicKeySize {
		return ed25519.PublicKey(b), nil
	}
	return nil, fmt.Errorf("update: %s is not a 32-byte ed25519 public key", path)
}

// Client talks to one channel.
type Client struct {
	ManifestURL string
	PublicKey   ed25519.PublicKey
	Token       string // optional bearer for private release hosts
	HTTP        *http.Client
}

func (c *Client) get(ctx context.Context, url string, accept string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	h := c.HTTP
	if h == nil {
		h = &http.Client{Timeout: 5 * time.Minute}
	}
	resp, err := h.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		resp.Body.Close()
		return nil, fmt.Errorf("update: GET %s: %s", url, resp.Status)
	}
	return resp, nil
}

// Fetch downloads and verifies the channel manifest.
func (c *Client) Fetch(ctx context.Context) (*Manifest, error) {
	resp, err := c.get(ctx, c.ManifestURL, "application/octet-stream")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var m Manifest
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&m); err != nil {
		return nil, fmt.Errorf("update: manifest: %w", err)
	}
	if err := Verify(m, c.PublicKey); err != nil {
		return nil, err
	}
	return &m, nil
}

// Platform is the manifest key for this build.
func Platform() string { return runtime.GOOS + "-" + runtime.GOARCH }

// Download fetches the file for this platform into dir, verifying its
// digest and size against the signed manifest before returning the path.
func (c *Client) Download(ctx context.Context, m *Manifest, dir string) (string, error) {
	f, ok := m.Files[Platform()]
	if !ok {
		return "", fmt.Errorf("update: no file for %s in %s", Platform(), m.Version)
	}
	resp, err := c.get(ctx, f.URL, "application/octet-stream")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	tmp, err := os.CreateTemp(dir, "rostor-"+m.Version+"-*.part")
	if err != nil {
		return "", err
	}
	defer func() {
		if tmp != nil {
			tmp.Close()
			os.Remove(tmp.Name())
		}
	}()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(resp.Body, f.Size+1))
	if err != nil {
		return "", err
	}
	if n != f.Size {
		return "", fmt.Errorf("update: size mismatch: got %d want %d", n, f.Size)
	}
	if got := hex.EncodeToString(h.Sum(nil)); !strings.EqualFold(got, f.SHA256) {
		return "", fmt.Errorf("update: sha256 mismatch: got %s want %s", got, f.SHA256)
	}
	if err := tmp.Chmod(0o755); err != nil {
		return "", err
	}
	name := tmp.Name()
	if err := tmp.Close(); err != nil {
		return "", err
	}
	tmp = nil
	return name, nil
}

// Swap replaces target with newPath atomically, keeping the previous binary
// as target.previous for rollback.
func Swap(newPath, target string) error {
	prev := target + ".previous"
	_ = os.Remove(prev)
	if _, err := os.Stat(target); err == nil {
		if err := os.Rename(target, prev); err != nil {
			return err
		}
	}
	if err := os.Rename(newPath, target); err != nil {
		// Try to put the old one back so the box is never left without a binary.
		_ = os.Rename(prev, target)
		return err
	}
	return nil
}

// State is what the appliance records about the channel, for the API and
// the admin UI: last check, what is available, what was applied.
type State struct {
	Channel   string     `json:"channel"`
	Current   string     `json:"current"`
	Available string     `json:"available,omitempty"`
	CheckedAt *time.Time `json:"checked_at,omitempty"`
	AppliedAt *time.Time `json:"applied_at,omitempty"`
	LastError string     `json:"last_error,omitempty"`
	Requested bool       `json:"apply_requested"`
	Notes     string     `json:"notes,omitempty"`
	// Blocked names the version that must be installed first when the
	// channel's release cannot be applied from Current in one jump.
	Blocked string `json:"blocked_needs_version,omitempty"`
}

func StatePath(stateDir string) string   { return filepath.Join(stateDir, "update-state.json") }
func RequestPath(stateDir string) string { return filepath.Join(stateDir, "update.request") }

func LoadState(stateDir string) State {
	var s State
	raw, err := os.ReadFile(StatePath(stateDir))
	if err == nil {
		_ = json.Unmarshal(raw, &s)
	}
	_, err = os.Stat(RequestPath(stateDir))
	s.Requested = err == nil
	return s
}

func SaveState(stateDir string, s State) error {
	raw, _ := json.MarshalIndent(s, "", "  ")
	tmp := StatePath(stateDir) + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, StatePath(stateDir))
}

// RequestApply is how the core (unprivileged) asks the privileged updater to
// run: it drops a request file that a systemd path unit watches.
func RequestApply(stateDir string) error {
	return os.WriteFile(RequestPath(stateDir), []byte(time.Now().UTC().Format(time.RFC3339)+"\n"), 0o644)
}

// NewerThan reports whether a is a newer version string than b using a
// simple dotted-numeric compare on the "vX.Y.Z" prefix; "dev" is never newer.
func NewerThan(a, b string) bool {
	pa, pb := parse(a), parse(b)
	if pa == nil {
		return false
	}
	if pb == nil {
		return true
	}
	for i := 0; i < 3; i++ {
		if pa[i] != pb[i] {
			return pa[i] > pb[i]
		}
	}
	return false
}

func parse(v string) []int {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		v = v[:i]
	}
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return nil
	}
	out := make([]int, 3)
	for i, p := range parts {
		if _, err := fmt.Sscanf(p, "%d", &out[i]); err != nil {
			return nil
		}
	}
	return out
}

// Check fetches the channel and records what is available. It needs no
// privilege beyond writing the state file, so the core can run it on demand
// from the API as well as the timer running the CLI.
func Check(ctx context.Context, c *Client, stateDir, current string) (State, error) {
	st := LoadState(stateDir)
	st.Current = current
	now := time.Now().UTC()
	st.CheckedAt = &now
	m, err := c.Fetch(ctx)
	if err != nil {
		st.LastError = err.Error()
		_ = SaveState(stateDir, st)
		return st, err
	}
	st.Channel = m.Channel
	st.LastError = ""
	st.Notes = m.Notes
	st.Blocked = ""
	if NewerThan(m.Version, current) {
		st.Available = m.Version
		if m.MinUpgradeFrom != "" && NewerThan(m.MinUpgradeFrom, current) {
			// Too big a jump: name the stepping stone instead of trying.
			st.Available = ""
			st.Blocked = m.MinUpgradeFrom
		}
	} else {
		st.Available = ""
	}
	return st, SaveState(stateDir, st)
}
