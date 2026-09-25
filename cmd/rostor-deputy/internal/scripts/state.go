package scripts

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Entry is what the deputy remembers per script id: the last version whose
// immediate assignment ran (so a version runs once, whatever its outcome)
// and when its sign-in assignment last ran (diagnostics only; sign-in
// scripts run every time).
type Entry struct {
	ImmediateVersionRan int       `json:"immediate_version_ran"`
	LastSigninAt        time.Time `json:"last_signin_at,omitzero"`
}

type stateFile struct {
	Scripts map[string]Entry `json:"scripts"`
}

// State is scripts.json. It is written after every run, so a crash between
// two scripts loses at most the one that was running — which then runs
// again, the safer failure for a script that never reported.
type State struct {
	path string

	mu      sync.Mutex
	entries map[string]Entry
}

// LoadState reads scripts.json; a missing file is an empty state. A
// corrupt file is an error rather than an empty state, because an empty
// state would rerun every immediate script on the machine.
func LoadState(path string) (*State, error) {
	s := &State{path: path, entries: map[string]Entry{}}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(string(b)) == "" {
		return s, nil
	}
	var f stateFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, err
	}
	for id, e := range f.Scripts {
		s.entries[id] = e
	}
	return s, nil
}

// Path returns the backing file.
func (s *State) Path() string { return s.path }

// Get returns the entry for id (zero when unknown).
func (s *State) Get(id string) Entry {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.entries[id]
}

// MarkImmediate records that version ran and persists.
func (s *State) MarkImmediate(id string, version int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.entries[id]
	e.ImmediateVersionRan = version
	s.entries[id] = e
	return s.saveLocked()
}

// MarkSignin records a sign-in run at t and persists.
func (s *State) MarkSignin(id string, t time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.entries[id]
	e.LastSigninAt = t.UTC()
	s.entries[id] = e
	return s.saveLocked()
}

// Save persists the state (used after edits made through Get/Mark; exported
// for callers that want to create the file eagerly).
func (s *State) Save() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveLocked()
}

func (s *State) saveLocked() error {
	f := stateFile{Scripts: map[string]Entry{}}
	for id, e := range s.entries {
		f.Scripts[id] = e
	}
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	// Write-then-rename: a truncated scripts.json would fail to load and
	// stop every script from running until an admin deletes it.
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}
