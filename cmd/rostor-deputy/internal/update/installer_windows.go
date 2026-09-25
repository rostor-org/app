//go:build windows

package update

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/windows"
)

// platformInstaller runs the bundle's install.ps1 with the contract's exact
// command line, its output appended to install.log beside it, detached from
// this process: its own process group and no console, and not waited on.
// The installer stops this service, so the child must outlive us — an
// exec.CommandContext or a Wait here would be self-defeating. The log file
// is handed over as a raw handle (an *os.File, not a pipe), so no goroutine
// in this process is needed to keep it flowing.
func platformInstaller(_ context.Context, dir string) error {
	logPath := filepath.Join(dir, InstallLog)
	logf, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("open %s: %w", logPath, err)
	}
	defer logf.Close() // the child holds its own inherited handle
	cmd := exec.Command("powershell.exe",
		"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
		"-File", filepath.Join(dir, InstallScript))
	cmd.Dir = dir
	cmd.Stdout = logf
	cmd.Stderr = logf
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: windows.CREATE_NEW_PROCESS_GROUP | windows.DETACHED_PROCESS,
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start powershell: %w", err)
	}
	// Let go of the handle; nobody here will Wait on the installer.
	return cmd.Process.Release()
}
