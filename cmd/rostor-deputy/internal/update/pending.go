package update

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"
)

// Pending is updates\pending.json: the update whose installer was started
// and whose outcome nobody has reported yet. It is written just before the
// installer starts and removed by whichever deputy comes up afterwards,
// once its report has been accepted.
type Pending struct {
	Version     string    `json:"version"`
	StartedAt   time.Time `json:"started_at"`
	FromVersion string    `json:"from_version"`
}

// LoadPending reads the file at path. A missing file is (nil, nil).
func LoadPending(path string) (*Pending, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var p Pending
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, err
	}
	if p.Version == "" {
		return nil, errors.New("pending.json has no version")
	}
	return &p, nil
}

// SavePending writes the file atomically (write-then-rename): a truncated
// pending.json would make the next deputy report nothing, and the admin
// would never learn how the update went.
func SavePending(path string, p Pending) error {
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// RemovePending deletes the file; a missing file is not an error.
func RemovePending(path string) error {
	err := os.Remove(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
