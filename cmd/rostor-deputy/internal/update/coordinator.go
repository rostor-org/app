package update

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"rostor.org/app/cmd/rostor-deputy/internal/core"
	"rostor.org/app/cmd/rostor-deputy/internal/paths"
)

// Client is what the coordinator needs from core. *core.Client and
// core.Mock satisfy it; tests use a fake.
type Client interface {
	Update(ctx context.Context) (*core.UpdateResponse, error)
	UpdateBundle(ctx context.Context, w io.Writer) (int64, error)
	ReportUpdate(ctx context.Context, run core.UpdateRun) error
}

// Installer starts the bundle's install.ps1 from dir, detached from this
// process, and returns once it is running. It must not wait: the installer
// stops the service that called it. Tests inject a fake; installer_windows.go
// supplies the real one.
type Installer func(ctx context.Context, dir string) error

// File names inside updates\<version>.
const (
	BundleName    = "rostor-windows-amd64.zip"
	InstallScript = "install.ps1"
	InstallLog    = "install.log"
	// InstallGrace is how long an old deputy waits for the installer it
	// started before reporting the attempt as failed.
	InstallGrace  = 5 * time.Minute
	AttemptedMark = "attempted"
	pendingName   = "pending.json"
)

// TailBytes is how much of install.log is reported.
const TailBytes = 4096

// maxExtracted bounds what a bundle may unpack to; the real one is a few
// megabytes, and a zip that claims more is refused before it fills the disk.
const maxExtracted int64 = 512 << 20

// versionRE is what may become a directory name under updates\: a version
// tag, never a path.
var versionRE = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z._+-]{0,63}$`)

// Coordinator checks, downloads, verifies, unpacks and hands off to the
// installer; and after a restart reports the outcome. A mutex keeps Check
// and ReportPending one at a time, in case a heartbeat overruns.
type Coordinator struct {
	Client Client
	// CAFile is ca.crt; it is read at every check so a rotated bundle
	// applies without a restart, exactly like the mTLS pool does.
	CAFile string
	// Version is the running deputy's version, compared with what core
	// wants and with pending.json to decide "ok" or "failed".
	Version string
	Logger  *log.Logger
	// Busy reports whether a logon is in flight; an update never starts
	// under a person who is mid sign-in. nil means never busy.
	Busy func() bool
	// Installer starts the extracted install.ps1; nil means the platform
	// one (which on non-Windows hosts only returns an error).
	Installer Installer
	// Dir is the updates directory; "" means paths.UpdatesDir.
	Dir string
	// Now is the clock for pending.json; nil means time.Now.
	Now func() time.Time
	// ReportTimeout bounds one report call; 0 means core.Timeout.
	ReportTimeout time.Duration

	mu sync.Mutex
}

// Check asks core whether this device should run another version and, if
// so and nothing stands in the way, downloads, verifies and unpacks the
// bundle, records the attempt, and starts the installer. Fetch failures
// are returned (the heartbeat logs them); a refused bundle is logged and
// nothing runs. The installer is started at most once per version: the
// "attempted" marker is written before it starts and checked first.
func (c *Coordinator) Check(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	resp, err := c.Client.Update(ctx)
	if err != nil {
		return fmt.Errorf("check update: %w", err)
	}
	if resp == nil || resp.Update == nil {
		return nil
	}
	info := *resp.Update
	if !versionRE.MatchString(info.Version) || strings.Contains(info.Version, "..") {
		c.logf("update refused: version %q is not a usable name", info.Version)
		return nil
	}
	if info.Version == c.Version {
		c.logf("update to %s skipped: already running it", info.Version)
		return nil
	}
	dir := filepath.Join(c.dir(), info.Version)
	if _, err := os.Stat(filepath.Join(dir, AttemptedMark)); err == nil {
		c.logf("update to %s skipped: already attempted once (%s)", info.Version, filepath.Join(dir, AttemptedMark))
		return nil
	}
	if c.busy() {
		c.logf("update to %s deferred: a logon is in flight", info.Version)
		return nil
	}
	c.logf("update to %s offered (from %s, %d bytes, signer %s)", info.Version, c.Version, info.Size, info.Signer)

	if err := c.fetch(ctx, info, dir); err != nil {
		c.logf("update to %s refused: %v", info.Version, err)
		return nil
	}
	if err := extract(filepath.Join(dir, BundleName), dir); err != nil {
		c.logf("update to %s refused: unpack: %v", info.Version, err)
		return nil
	}
	if _, err := os.Stat(filepath.Join(dir, InstallScript)); err != nil {
		c.logf("update to %s refused: bundle has no %s", info.Version, InstallScript)
		return nil
	}
	c.logf("update to %s: bundle verified and unpacked in %s", info.Version, dir)

	// Downloading took a while; a person may have started signing in.
	if c.busy() {
		c.logf("update to %s deferred: a logon is in flight", info.Version)
		return nil
	}
	pending := Pending{Version: info.Version, StartedAt: c.now(), FromVersion: c.Version}
	if err := SavePending(c.pendingPath(), pending); err != nil {
		c.logf("update to %s: write pending.json: %v", info.Version, err)
		return nil
	}
	// The marker goes down before the installer starts: whatever happens
	// next, this version is not tried again by this deputy.
	if err := os.WriteFile(filepath.Join(dir, AttemptedMark), []byte(pending.StartedAt.UTC().Format(time.RFC3339)+"\n"), 0o644); err != nil {
		c.logf("update to %s: write attempted marker: %v", info.Version, err)
		_ = RemovePending(c.pendingPath())
		return nil
	}
	c.logf("update to %s: starting installer %s (log %s)", info.Version, filepath.Join(dir, InstallScript), filepath.Join(dir, InstallLog))
	if err := c.installer()(ctx, dir); err != nil {
		// Nothing was stopped, so this deputy is the one to say it failed;
		// waiting for the next start could be weeks.
		c.logf("update to %s: installer did not start: %v", info.Version, err)
		if c.report(ctx, pending, core.RunFailed, "installer did not start: "+err.Error()) {
			_ = RemovePending(c.pendingPath())
		}
		return nil
	}
	c.logf("update to %s: installer started; this service will be stopped by it", info.Version)
	return nil
}

// fetch downloads the bundle to dir and checks its size, digest and
// signature. Anything short of a verified file is removed and reported as
// an error.
func (c *Coordinator) fetch(ctx context.Context, info Info, dir string) (err error) {
	caPEMs, rerr := os.ReadFile(c.CAFile)
	if rerr != nil {
		return fmt.Errorf("read trust bundle: %w", rerr)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	zipPath := filepath.Join(dir, BundleName)
	f, err := os.OpenFile(zipPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			os.Remove(zipPath)
		}
	}()
	h := sha256.New()
	n, derr := c.Client.UpdateBundle(ctx, io.MultiWriter(f, h))
	if cerr := f.Close(); derr == nil {
		derr = cerr
	}
	if derr != nil {
		return fmt.Errorf("download: %w", derr)
	}
	if n != info.Size {
		return fmt.Errorf("size is %d bytes, core announced %d", n, info.Size)
	}
	got := hex.EncodeToString(h.Sum(nil))
	if !strings.EqualFold(got, info.SHA256) {
		return fmt.Errorf("sha256 is %s, core announced %s", got, info.SHA256)
	}
	if err := Verify(info, got, caPEMs); err != nil {
		return err
	}
	return nil
}

// extract unpacks zipPath into dir. Every entry name is checked before a
// byte is written: no absolute paths, no drive letters, no "..", nothing
// that resolves outside dir; symlinks are refused too. One bad entry
// refuses the whole bundle.
func extract(zipPath, dir string) error {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer zr.Close()
	root, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	var total int64
	for _, f := range zr.File {
		target, err := safeTarget(root, f.Name)
		if err != nil {
			return err
		}
		if f.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("entry %q is a symlink", f.Name)
		}
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
			continue
		}
		if total += int64(f.UncompressedSize64); total > maxExtracted {
			return fmt.Errorf("bundle unpacks to more than %d bytes", maxExtracted)
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		if err := writeEntry(f, target); err != nil {
			return fmt.Errorf("entry %q: %w", f.Name, err)
		}
	}
	return nil
}

// safeTarget maps a zip entry name onto a path under root, or refuses it.
func safeTarget(root, name string) (string, error) {
	if name == "" {
		return "", errors.New("entry with empty name")
	}
	if strings.ContainsAny(name, `\:`) || strings.HasPrefix(name, "/") {
		return "", fmt.Errorf("entry %q: unsafe path", name)
	}
	clean := path.Clean(name)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", fmt.Errorf("entry %q: escapes the bundle directory", name)
	}
	for _, part := range strings.Split(clean, "/") {
		if part == ".." {
			return "", fmt.Errorf("entry %q: escapes the bundle directory", name)
		}
	}
	target := filepath.Join(root, filepath.FromSlash(clean))
	if target != root && !strings.HasPrefix(target, root+string(filepath.Separator)) {
		return "", fmt.Errorf("entry %q: escapes the bundle directory", name)
	}
	return target, nil
}

func writeEntry(f *zip.File, target string) error {
	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer rc.Close()
	out, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, io.LimitReader(rc, maxExtracted))
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	return err
}

// ReportPending is called at start (and harmlessly on later heartbeats): if
// pending.json exists, it reports the outcome of that update — "ok" when
// this deputy is the version that was installed, "failed" otherwise — with
// the tail of the installer's log, and removes pending.json once core has
// accepted the report. A report that fails keeps the file so the next call
// retries. Bundle directories of versions other than the running and the
// pending one are then emptied, keeping only the log and the marker.
func (c *Coordinator) ReportPending(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	p, err := LoadPending(c.pendingPath())
	if err != nil {
		return fmt.Errorf("read %s: %w", c.pendingPath(), err)
	}
	keep := map[string]bool{c.Version: true}
	if p != nil {
		keep[p.Version] = true
		status := core.RunFailed
		if p.Version == c.Version {
			status = core.RunOK
		} else if since := c.now().Sub(p.StartedAt); since < InstallGrace {
			// The installer was started moments ago and this is still the old
			// deputy: give it time before calling the attempt failed.
			c.logf("update to %s: installer started %s ago; waiting", p.Version, since.Round(time.Second))
			return nil
		}
		tail := readTail(filepath.Join(c.dir(), p.Version, InstallLog), TailBytes)
		c.logf("update to %s (from %s, started %s): %s, running %s", p.Version, p.FromVersion, p.StartedAt.UTC().Format(time.RFC3339), status, c.Version)
		if !c.report(ctx, *p, status, tail) {
			return fmt.Errorf("report update to %s: not accepted; will retry", p.Version)
		}
		if err := RemovePending(c.pendingPath()); err != nil {
			c.logf("remove %s: %v", c.pendingPath(), err)
		}
		platformCleanup()
	}
	c.cleanup(keep)
	return nil
}

// report sends one run report with its own deadline and says whether core
// accepted it.
func (c *Coordinator) report(ctx context.Context, p Pending, status, tail string) bool {
	timeout := c.ReportTimeout
	if timeout == 0 {
		timeout = core.Timeout
	}
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), timeout)
	defer cancel()
	run := Run{Version: p.Version, Status: status, FromVersion: p.FromVersion, OutputTail: tail}
	if err := c.Client.ReportUpdate(rctx, run); err != nil {
		c.logf("update to %s: report: %v", p.Version, err)
		return false
	}
	c.logf("update to %s: reported %s", p.Version, status)
	return true
}

// cleanup empties every version directory not in keep: the zip and the
// unpacked files go, the installer log and the "attempted" marker stay, so
// the once-per-version rule survives and an admin can still read what
// happened.
func (c *Coordinator) cleanup(keep map[string]bool) {
	entries, err := os.ReadDir(c.dir())
	if err != nil {
		return
	}
	for _, e := range entries {
		if !e.IsDir() || keep[e.Name()] {
			continue
		}
		dir := filepath.Join(c.dir(), e.Name())
		files, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		removed := 0
		for _, f := range files {
			if f.Name() == InstallLog || f.Name() == AttemptedMark {
				continue
			}
			if err := os.RemoveAll(filepath.Join(dir, f.Name())); err != nil {
				c.logf("clean up %s: %v", filepath.Join(dir, f.Name()), err)
				continue
			}
			removed++
		}
		if removed > 0 {
			c.logf("cleaned up update bundle %s", e.Name())
		}
	}
}

// readTail returns the last max bytes of the file at path, "" when it
// cannot be read.
func readTail(path string, max int64) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return ""
	}
	if st.Size() > max {
		if _, err := f.Seek(st.Size()-max, io.SeekStart); err != nil {
			return ""
		}
	}
	b, err := io.ReadAll(io.LimitReader(f, max))
	if err != nil {
		return ""
	}
	return string(b)
}

func (c *Coordinator) dir() string {
	if c.Dir != "" {
		return c.Dir
	}
	return paths.UpdatesDir
}

func (c *Coordinator) pendingPath() string { return filepath.Join(c.dir(), pendingName) }

func (c *Coordinator) busy() bool { return c.Busy != nil && c.Busy() }

func (c *Coordinator) installer() Installer {
	if c.Installer != nil {
		return c.Installer
	}
	return platformInstaller
}

func (c *Coordinator) now() time.Time {
	if c.Now != nil {
		return c.Now().UTC()
	}
	return time.Now().UTC()
}

func (c *Coordinator) logf(format string, args ...any) {
	if c.Logger != nil {
		c.Logger.Printf(format, args...)
	}
}
