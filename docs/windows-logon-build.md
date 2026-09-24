# Windows logon slice — build, install, verify

Companion to `docs/contracts/windows-logon.md` (the contract). This page only
says how to build the two Windows components, how to install them, and what
has been verified so far.

## Components

| path | what | builds on |
|---|---|---|
| `cmd/rostor-agent/` | Go Windows service `RostorAgent` + CLI (`enroll`, `install-service`, `uninstall-service`, `pipe-test`, `run`) | macOS/Linux cross-compile |
| `windows/credprov/` | C++ Credential Provider `RostorCredProv.dll` | Windows, MSVC Build Tools 2022 |
| `windows/install/` | `install.ps1`, `uninstall.ps1` | run on the workstation, elevated |

## Build

Agent (from the repo root, any OS):

```sh
GOOS=windows GOARCH=amd64 go build -o rostor-agent.exe ./cmd/rostor-agent
go vet ./cmd/rostor-agent/...            # also passes with GOOS=windows
go test ./cmd/rostor-agent/...           # pure-logic tests run on macOS
```

Credential provider (on Windows with Build Tools 2022 + Windows 10 SDK):

```
windows\credprov\build.cmd
```

`build.cmd` calls `vcvars64.bat`, compiles with `/W4 /WX /O2 /MT /guard:cf`
and links `windows\credprov\out\RostorCredProv.dll` (x64 Release). No
`.vcxproj`; the seven `.cpp` files are listed in the script.

The credprov has no third-party code: `json.cpp` is a ~150-line flat-object
parser sufficient for the contract §2 messages.

## Install

Copy `rostor-agent.exe`, `RostorCredProv.dll`, `install.ps1` and
`uninstall.ps1` into one directory on the workstation, then elevated:

```powershell
.\install.ps1                 # real core: enroll first (below), then install
.\install.ps1 -MockCore       # development: identifier "testuser" is ALLOWed with any secret;
                              # badge 1234567890 → ALLOW as testuser, 5555555555 → needs PIN 2468,
                              # any other badge → auth.failed
.\install.ps1 -SkipCredProv   # agent + service only
```

`install.ps1` refuses to register the credential provider unless the agent
service is running and answers the pipe `ui` op. It never touches the
built-in password provider.

Enrollment (once, before a non-mock install, or afterwards followed by
`Restart-Service RostorAgent`):

```powershell
& 'C:\Program Files\Rostor\rostor-agent.exe' enroll --core-url https://core:8443 --token <enrollment token> [--ca-file core-ca.pem | --insecure]
```

Uninstall:

```powershell
.\uninstall.ps1          # removes CP registry keys, DLL, service, Program Files; keeps C:\ProgramData\Rostor
.\uninstall.ps1 -Purge   # also removes C:\ProgramData\Rostor (never local accounts)
```

## Debugging

- Agent log: `C:\ProgramData\Rostor\logs\agent.log`
- Credprov log: `C:\ProgramData\Rostor\logs\credprov.log` (written by LogonUI as SYSTEM)
- Talk to the pipe as an elevated admin:
  `rostor-agent pipe-test --op ui`,
  `rostor-agent pipe-test --op logon --identifier dan --secret ...`,
  `rostor-agent pipe-test --op logon --badge 5555555555 [--pin 2468]`
- Foreground agent: stop the service, then `rostor-agent run [--mock-core]`.

## Verified so far (2026-09-22, Windows 10 Pro N 19045 VM, agent in `--mock-core`)

- `GOOS=windows GOARCH=amd64 go build ./cmd/rostor-agent`, `go vet` (darwin and
  windows), `go test ./cmd/rostor-agent/...` all pass.
- `install.ps1 -MockCore` installs and starts `RostorAgent` (LocalSystem,
  automatic); `pipe-test --op ui` returns the five strings.
- `pipe-test --op logon --identifier testuser --secret x` returns
  `{"ok":true,"local_user":"testuser","local_secret":"<32 chars>"}`;
  `testuser` is created enabled, in `Users` (not `Administrators`), comment
  `Managed by Rostor — do not edit`, full name from the principal, password never
  expires; the returned secret validates against SAM
  (`PrincipalContext.ValidateCredentials`) and the previous secret stops
  validating after the next logon; the ledger `accounts.json` lists it.
- `pipe-test --op logon --identifier nobody --secret x` returns
  `{"ok":false,"code":"auth.failed","message":"Sign-in failed."}`.
- `RostorCredProv.dll` builds cleanly with `/W4 /WX` (x64); exports
  `DllGetClassObject`/`DllCanUnloadNow`; `json_test.exe` passes; `cp_test.exe`
  drives the DLL through `SetUsageScenario(CPUS_LOGON)` → fields →
  `GetSerialization` against the live agent and gets
  `CPGSR_RETURN_CREDENTIAL_FINISHED` with a packed `KERB_INTERACTIVE_UNLOCK_LOGON`
  (domain `.`, user `testuser`, CredProtect-ed secret); the deny path yields
  `CPGSR_NO_CREDENTIAL_FINISHED` + `CPSI_ERROR` + the agent's text.
- `install.ps1` → registry keys + `System32\RostorCredProv.dll` present;
  `uninstall.ps1` removes them (keys first), the service and Program Files, keeps
  ProgramData; a second `install.ps1` restores everything. Pre-existing accounts
  and the built-in password provider untouched throughout.

## Verified 2026-09-24 (badge + PIN, same VM, agent in `--mock-core`)

- `pipe-test --op ui` now also returns `pin_label` and `badge_hint`;
  `--badge 1234567890` → ALLOW as `testuser`; `--badge 5555555555` →
  `{"ok":false,"code":"auth.continue","message":"Enter your PIN.","need":"pin"}`;
  with `--pin 2468` → ALLOW; with `--pin 0000` or an unknown number → `auth.failed`.
- `cp_test.exe <dll> --badge <number> <pin|-> expect-ok|expect-deny|expect-pin`
  drives the DLL through the tap: six fields (a hidden `PIN` password field
  was added), identifier label is the badge hint; a tap on `5555555555`
  yields `CPGSR_NO_CREDENTIAL_NOT_FINISHED` + the agent's prompt, the secret
  field hidden, the PIN field shown and focused, the submit button moved next
  to it (checked through `ICredentialProviderCredentialEvents`), the number
  kept; typing the PIN and submitting packs `testuser` exactly as the password
  path does; a wrong PIN or unknown badge returns the tile to its initial
  form with the identifier cleared. Password paths unchanged.
- `install.ps1` was rerun without `-MockCore` afterwards; the service is back
  on the real core, enrollment files untouched.

Not yet verified: the interactive lock-screen tile itself (needs a console
session — in particular that LogonUI honours the focus move to the PIN field
and that a reader burst lands in the identifier field without a click),
badge Verify against a real core (the core deployed at ChattLab answered HTTP
400 to a badge presentation at the time of writing, which the agent reports as
`agent.core_unreachable`), `CPUS_UNLOCK_WORKSTATION`.
