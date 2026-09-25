//go:build windows

package scripts

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"time"
)

// platformExecutor runs the staged file with the contract's exact command
// line. The service runs as SYSTEM, so the script does too.
func platformExecutor(ctx context.Context, path string, env []string, out io.Writer) (int, error) {
	cmd := exec.CommandContext(ctx, "powershell.exe",
		"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", path)
	cmd.Env = env
	cmd.Stdout = out
	cmd.Stderr = out
	// A child the script left behind (Start-Process without -Wait) keeps
	// the output pipe open; WaitDelay stops Wait from hanging on it after
	// powershell.exe itself has exited or been killed at the deadline.
	cmd.WaitDelay = 5 * time.Second
	if err := cmd.Start(); err != nil {
		return -1, fmt.Errorf("%w: %v", ErrStart, err)
	}
	err := cmd.Wait()
	if err == nil {
		return 0, nil
	}
	if ctx.Err() != nil {
		return -1, ctx.Err()
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return exit.ExitCode(), nil
	}
	return -1, err
}
