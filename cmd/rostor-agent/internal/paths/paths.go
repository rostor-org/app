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
	LogDir     = filepath.Join(ProgramData, "logs")
	LogFile    = filepath.Join(LogDir, "agent.log")
)
