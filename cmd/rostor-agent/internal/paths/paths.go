// Package paths fixes the on-disk layout from contract §4. Kept as data so
// the install scripts, the agent and the docs agree on one source.
package paths

import "path/filepath"

const (
	// ProgramData is the agent's state directory.
	ProgramData = `C:\ProgramData\Rostor`
	// InstallDir holds the agent binary.
	InstallDir = `C:\Program Files\Rostor`

	ServiceName        = "RostorAgent"
	ServiceDisplayName = "Rostor Agent"
	PipeName           = `\\.\pipe\rostor-agent`
)

var (
	AgentJSON  = filepath.Join(ProgramData, "agent.json")
	DeviceKey  = filepath.Join(ProgramData, "device.key")
	DeviceCert = filepath.Join(ProgramData, "device.crt")
	CACert     = filepath.Join(ProgramData, "ca.crt")
	Ledger     = filepath.Join(ProgramData, "accounts.json")
	// Scripts is the per-script run state of SPEC-scripts (contract §1.4).
	Scripts = filepath.Join(ProgramData, "scripts.json")
	// ScriptsDir is where script bodies are staged as .ps1 files for the
	// duration of a run. It sits under ProgramData rather than the system
	// temp directory so the staged file inherits the SYSTEM/Administrators
	// ACL and cannot be swapped by a standard user between write and exec.
	ScriptsDir = filepath.Join(ProgramData, "scripts")
	LogDir     = filepath.Join(ProgramData, "logs")
	LogFile    = filepath.Join(LogDir, "agent.log")
)
