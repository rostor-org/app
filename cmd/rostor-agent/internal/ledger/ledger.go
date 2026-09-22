// Package ledger records which local Windows accounts the agent created
// (contract §3). The ledger is authoritative: the agent only ever modifies an
// account whose name appears here, so pre-existing local accounts can never be
// touched even if a principal's username happens to collide with one.
package ledger

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Entry is one agent-created account.
type Entry struct {
	Username  string    `json:"username"`
	CreatedAt time.Time `json:"created_at"`
}

type file struct {
	Accounts []Entry `json:"accounts"`
}

// Ledger is a small JSON file guarded by a mutex; the agent handles one logon
// at a time in practice but the pipe server is concurrent.
type Ledger struct {
	path string

	mu      sync.Mutex
	entries map[string]Entry
}

// Open loads the ledger at path, creating an empty one in memory if the file
// does not exist yet. It is written on the first Add.
func Open(path string) (*Ledger, error) {
	l := &Ledger{path: path, entries: map[string]Entry{}}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return l, nil
	}
	if err != nil {
		return nil, err
	}
	var f file
	if len(strings.TrimSpace(string(b))) > 0 {
		if err := json.Unmarshal(b, &f); err != nil {
			return nil, err
		}
	}
	for _, e := range f.Accounts {
		l.entries[normalize(e.Username)] = e
	}
	return l, nil
}

// Path returns the backing file path.
func (l *Ledger) Path() string { return l.path }

// Has reports whether username was created by the agent.
func (l *Ledger) Has(username string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	_, ok := l.entries[normalize(username)]
	return ok
}

// Add records username and persists the ledger. Adding an existing name is a
// no-op so callers can add unconditionally after a successful NetUserAdd.
func (l *Ledger) Add(username string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	key := normalize(username)
	if _, ok := l.entries[key]; ok {
		return nil
	}
	l.entries[key] = Entry{Username: key, CreatedAt: time.Now().UTC()}
	return l.saveLocked()
}

// Usernames returns the ledger contents sorted, for diagnostics.
func (l *Ledger) Usernames() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]string, 0, len(l.entries))
	for k := range l.entries {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (l *Ledger) saveLocked() error {
	var f file
	for _, e := range l.entries {
		f.Accounts = append(f.Accounts, e)
	}
	sort.Slice(f.Accounts, func(i, j int) bool { return f.Accounts[i].Username < f.Accounts[j].Username })
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(l.path), 0o755); err != nil {
		return err
	}
	// Write-then-rename so a crash mid-write cannot leave a truncated ledger,
	// which would silently orphan accounts the agent created.
	tmp := l.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, l.path)
}

// Windows account names are case-insensitive; the ledger must be too.
func normalize(s string) string { return strings.ToLower(strings.TrimSpace(s)) }
