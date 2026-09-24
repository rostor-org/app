package trust

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"

	"rostor.org/app/cmd/rostor-agent/internal/enroll"
)

// Files is the on-disk layout (contract §4); reused from enroll so both
// writers agree on one source.
type Files = enroll.Files

// Staged paths: a renewed pair is written next to the live one and only
// renamed over it once it has been proven against core.
func stagedKey(f Files) string  { return f.DeviceKey + ".new" }
func stagedCert(f Files) string { return f.DeviceCert + ".new" }

// WriteAtomic writes data to path.new and renames it into place, so a reader
// sees either the old or the new file, never a torn one. os.Rename replaces
// an existing target on both Windows (MOVEFILE_REPLACE_EXISTING) and POSIX.
func WriteAtomic(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".new"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// StagePair writes device.key.new and device.crt.new after checking that
// they belong together. secure, when non-nil, applies the §4 ACL to the
// staged key; the ACL travels with the file through the rename. The live
// pair is untouched.
func StagePair(f Files, keyPEM, certPEM []byte, secure func(path string) error) error {
	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		return fmt.Errorf("renewed certificate does not match key: %w", err)
	}
	DiscardStaged(f)
	if err := os.WriteFile(stagedKey(f), keyPEM, 0o600); err != nil {
		return err
	}
	if secure != nil {
		if err := secure(stagedKey(f)); err != nil {
			DiscardStaged(f)
			return fmt.Errorf("secure staged key: %w", err)
		}
	}
	if err := os.WriteFile(stagedCert(f), certPEM, 0o644); err != nil {
		DiscardStaged(f)
		return err
	}
	return nil
}

// StagedPaths returns where a staged pair lives, for a probe client.
func StagedPaths(f Files) (certPath, keyPath string) {
	return stagedCert(f), stagedKey(f)
}

// HasStagedPair reports whether a complete, matching staged pair exists.
func HasStagedPair(f Files) bool {
	_, err := tls.LoadX509KeyPair(stagedCert(f), stagedKey(f))
	return err == nil
}

// CommitPair renames the staged pair over the live one: key first, then
// certificate. Each rename is atomic; a crash between the two leaves
// device.key already renewed and device.crt.new still present, which
// Recover completes on the next start.
func CommitPair(f Files) error {
	if !HasStagedPair(f) {
		return errors.New("no staged pair to commit")
	}
	if err := os.Rename(stagedKey(f), f.DeviceKey); err != nil {
		return fmt.Errorf("commit key: %w", err)
	}
	if err := os.Rename(stagedCert(f), f.DeviceCert); err != nil {
		return fmt.Errorf("commit certificate: %w", err)
	}
	return nil
}

// DiscardStaged removes any staged files; the live pair is untouched.
func DiscardStaged(f Files) {
	_ = os.Remove(stagedKey(f))
	_ = os.Remove(stagedCert(f))
}

// Recover repairs the aftermath of a crash during CommitPair. It returns
// true when a complete staged pair is still waiting and must be probed by the
// caller (it was never proven, or the proof was lost with the process).
//
//   - device.crt.new alone, matching the live device.key: the key rename
//     happened, the certificate rename did not; finish it.
//   - device.crt.new alone, not matching: stale; remove.
//   - device.key.new alone: stale (keys are renamed first); remove.
//   - both present and matching: leave for the caller to probe.
//   - both present, not matching: remove both.
func Recover(f Files) (staged bool, err error) {
	keyNew, certNew := stagedKey(f), stagedCert(f)
	_, keyErr := os.Stat(keyNew)
	_, certErr := os.Stat(certNew)
	haveKey, haveCert := keyErr == nil, certErr == nil
	switch {
	case !haveKey && !haveCert:
		return false, nil
	case haveKey && haveCert:
		if HasStagedPair(f) {
			return true, nil
		}
		DiscardStaged(f)
		return false, nil
	case haveCert:
		if _, err := tls.LoadX509KeyPair(certNew, f.DeviceKey); err == nil {
			if err := os.Rename(certNew, f.DeviceCert); err != nil {
				return false, fmt.Errorf("finish interrupted commit: %w", err)
			}
			return false, nil
		}
		_ = os.Remove(certNew)
		return false, nil
	default:
		_ = os.Remove(keyNew)
		return false, nil
	}
}

// LoadLeaf reads the live device certificate.
func LoadLeaf(f Files) (*x509.Certificate, error) {
	b, err := os.ReadFile(f.DeviceCert)
	if err != nil {
		return nil, err
	}
	return ParseCert(b)
}

// LoadBundle reads the pinned CA bundle.
func LoadBundle(f Files) ([]*x509.Certificate, error) {
	b, err := os.ReadFile(f.CACert)
	if err != nil {
		return nil, err
	}
	return ParseBundle(b)
}
