package scripts

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"rostor.org/app/cmd/rostor-deputy/internal/core"
)

// RunTimeout is the contract's limit per script.
const RunTimeout = 10 * time.Minute

// TailBytes is how much of the combined output is kept and reported.
const TailBytes = 4096

// ErrStart marks an executor failure to start PowerShell at all, which the
// contract reports as status "error" with exit code -1.
var ErrStart = errors.New("could not start powershell")

// Executor runs the staged .ps1 at path with the given environment (the
// full environment, "K=V" form), writing combined stdout+stderr to out. It
// returns the exit code, or an error: one wrapping ErrStart when the process
// never started, or ctx.Err() when ctx ended first. Tests inject a fake;
// exec_windows.go supplies the real one.
type Executor func(ctx context.Context, path string, env []string, out io.Writer) (int, error)

// Runner stages and runs one script at a time.
type Runner struct {
	// Exec is the executor; nil means the platform one.
	Exec Executor
	// Dir is the staging directory; "" means the OS temp directory.
	Dir string
	// Timeout per script; 0 means RunTimeout.
	Timeout time.Duration
	// Now is the clock; nil means time.Now.
	Now func() time.Time
	// Environ is the base environment; nil means os.Environ.
	Environ func() []string
}

// Run stages the body, runs it and returns the report (PrincipalID left for
// the caller). The staged file is removed whatever happens.
func (r *Runner) Run(ctx context.Context, s Script, env map[string]string) Run {
	now := r.now
	rep := Run{Version: s.Version, Mode: s.Mode, StartedAt: now(), ExitCode: -1, Status: core.RunError}
	tail := &tailWriter{max: TailBytes}

	path, err := r.stage(s)
	if err != nil {
		rep.FinishedAt = now()
		rep.OutputTail = "stage: " + err.Error()
		return rep
	}
	defer os.Remove(path)

	timeout := r.Timeout
	if timeout == 0 {
		timeout = RunTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	exec := r.Exec
	if exec == nil {
		exec = platformExecutor
	}
	code, err := exec(ctx, path, r.environ(env), tail)
	rep.FinishedAt = now()
	rep.OutputTail = tail.String()
	switch {
	case err == nil && code == 0:
		rep.ExitCode, rep.Status = 0, core.RunOK
	case err == nil:
		rep.ExitCode, rep.Status = code, core.RunFailed
	case ctx.Err() != nil && !errors.Is(err, ErrStart):
		// The deadline fired (or the caller cancelled); the exit code of a
		// killed process says nothing, so it is reported as -1.
		rep.ExitCode, rep.Status = -1, core.RunTimeout
	default:
		rep.ExitCode, rep.Status = -1, core.RunError
		if rep.OutputTail == "" {
			rep.OutputTail = err.Error()
		}
	}
	return rep
}

// stage writes the body as a UTF-8 file with a BOM: Windows PowerShell 5.1
// reads a BOM-less .ps1 in the ANSI code page, which would corrupt any
// non-ASCII text in the script.
func (r *Runner) stage(s Script) (string, error) {
	dir := r.Dir
	if dir == "" {
		dir = os.TempDir()
	} else if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	f, err := os.CreateTemp(dir, "rostor-*.ps1")
	if err != nil {
		return "", err
	}
	_, err = f.Write(append([]byte("\xEF\xBB\xBF"), s.Body...))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(f.Name())
		return "", err
	}
	return filepath.Clean(f.Name()), nil
}

// environ merges extra into the base environment. Keys are matched
// case-insensitively because Windows environments are.
func (r *Runner) environ(extra map[string]string) []string {
	base := os.Environ
	if r.Environ != nil {
		base = r.Environ
	}
	var out []string
	for _, kv := range base() {
		k, _, _ := strings.Cut(kv, "=")
		if _, drop := lookupFold(extra, k); !drop {
			out = append(out, kv)
		}
	}
	keys := make([]string, 0, len(extra))
	for k := range extra {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		out = append(out, k+"="+extra[k])
	}
	return out
}

func lookupFold(m map[string]string, key string) (string, bool) {
	for k, v := range m {
		if strings.EqualFold(k, key) {
			return v, true
		}
	}
	return "", false
}

func (r *Runner) now() time.Time {
	if r.Now != nil {
		return r.Now().UTC()
	}
	return time.Now().UTC()
}

// tailWriter keeps the last max bytes written. Output is unbounded in
// principle (a script may loop and print), so the whole stream is never
// held in memory.
type tailWriter struct {
	max int
	buf []byte
}

func (w *tailWriter) Write(p []byte) (int, error) {
	n := len(p)
	if n >= w.max {
		w.buf = append(w.buf[:0], p[n-w.max:]...)
		return n, nil
	}
	if over := len(w.buf) + n - w.max; over > 0 {
		w.buf = append(w.buf[:0], w.buf[over:]...)
	}
	w.buf = append(w.buf, p...)
	return n, nil
}

func (w *tailWriter) String() string { return string(w.buf) }

// describe summarises a run for the log.
func describe(s Script, rep Run) string {
	return fmt.Sprintf("script %s (%q v%d, %s): %s exit %d in %s", s.ID, s.Name, s.Version, s.Mode, rep.Status, rep.ExitCode, rep.FinishedAt.Sub(rep.StartedAt).Round(time.Millisecond))
}
