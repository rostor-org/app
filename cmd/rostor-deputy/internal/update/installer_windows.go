//go:build windows

package update

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

// TaskName is the one-shot scheduled task that runs the installer as SYSTEM.
const TaskName = "RostorDeputyUpdate"

// platformInstaller hands the bundle's install.ps1 to the Task Scheduler
// as a SYSTEM task and runs it at once. A child started straight from this
// service with DETACHED_PROCESS produced no output and never ran the script
// (seen on the ChattLab VM, v0.14.0), whereas a scheduled task gets a full
// environment of its own and outlives the service the installer stops.
// The command line lives in a .cmd beside the bundle so the task needs no
// quoting inside quoting; output goes to install.log.
func platformInstaller(ctx context.Context, dir string) error {
	script := filepath.Join(dir, InstallScript)
	logPath := filepath.Join(dir, InstallLog)
	runner := filepath.Join(dir, "run-update.cmd")
	body := "@echo off\r\n" +
		`powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "` + script + `" >> "` + logPath + `" 2>&1` + "\r\n"
	if err := os.WriteFile(runner, []byte(body), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", runner, err)
	}
	create := exec.CommandContext(ctx, "schtasks.exe", "/Create", "/F", "/TN", TaskName, "/SC", "ONCE", "/ST", "23:59",
		"/RU", "SYSTEM", "/RL", "HIGHEST", "/TR", `cmd.exe /c "`+runner+`"`)
	create.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if out, err := create.CombinedOutput(); err != nil {
		return fmt.Errorf("schtasks create: %w: %s", err, strings.TrimSpace(string(out)))
	}
	run := exec.CommandContext(ctx, "schtasks.exe", "/Run", "/TN", TaskName)
	run.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if out, err := run.CombinedOutput(); err != nil {
		return fmt.Errorf("schtasks run: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// platformCleanup removes the one-shot task once an update has been
// reported; best effort.
func platformCleanup() {
	del := exec.Command("schtasks.exe", "/Delete", "/F", "/TN", TaskName)
	del.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	_, _ = del.CombinedOutput()
}
