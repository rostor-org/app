# Windows logon slice — build, install, verify

Companion to `docs/contracts/windows-logon.md` (the contract). This page only
says how to build the two Windows components, how to install them, and what
has been verified so far.

## Components

| path | what | builds on |
|---|---|---|
| `cmd/rostor-agent/` | Go Windows service `RostorAgent` + CLI (`enroll`, `install-service`, `uninstall-service`, `pipe-test`, `trust`, `renew`, `run`) | macOS/Linux cross-compile |
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

## Install from the release bundle (the normal path)

Every GitHub release carries `rostor-windows-amd64.zip` (agent, credential
provider DLL, `install.ps1`, `uninstall.ps1`, `tile.bmp`, `README.txt`); CI
also keeps the same zip as the `rostor-windows-amd64` artifact of every
push (`gh run download --name rostor-windows-amd64`). Mint an enrollment
token in the console, unzip on the workstation, then in an elevated
PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File .\install.ps1 -CoreUrl https://core.example:8443 -Token <enrollment token>
```

That one command enrolls the workstation (`rostor-agent enroll`, run
before the service starts), installs the `RostorAgent` service, sets the
sign-in policies, copies the DLL to `System32` and registers the credential
provider, then prints a summary (core, device id, service state, tile). The
enrollment call has no CA to verify against yet, so it runs with the agent's
`--insecure` for that single call; the CA in the enrollment response is
pinned for everything afterwards. Pass `-CaFile core-ca.pem` (the appliance's
`/var/lib/rostor/ca.crt`) to verify the enrollment call too.

Re-running is safe: when `C:\ProgramData\Rostor\agent.json` already exists
the enrollment step is skipped (the script says so, and warns if the existing
enrollment points at a different core), and the service/DLL/keys are
refreshed. To re-enroll: `.\uninstall.ps1 -Purge`, then install again with a
new token. Other switches:

```powershell
.\install.ps1 -MockCore       # development: identifier "testuser" is ALLOWed with any secret;
                              # badge 1234567890 → ALLOW as testuser, 5555555555 → needs PIN 2468,
                              # any other badge → auth.failed (cannot combine with -CoreUrl)
.\install.ps1 -SkipCredProv   # agent + service only
.\install.ps1 -ExcludeMicrosoftAccount   # hide the "Microsoft account" tile (password tile kept)
.\install.ps1                 # no flags: keeps an existing enrollment, otherwise warns "not enrolled"
```

`install.ps1` refuses to register the credential provider unless the agent
service is running and answers the pipe `ui` op. It never touches the
built-in password provider.

The bundle is assembled by the `windows-bundle` job in
`.github/workflows/ci.yml`: it downloads the DLL built by the `credprov`
job (Windows runner, MSVC), cross-builds the agent with `setup-go`, zips the
six files, uploads the artifact, and on a `v*` tag attaches the zip to the
GitHub release with `gh release upload --clobber` (waiting up to five
minutes for `make release` to create the release; if it still does not
exist the job logs a warning and the zip stays available as the run
artifact). The zip is not in the core's signed update manifest: the
in-product updater is for the core only.

## Install by hand (development)

Copy `rostor-agent.exe`, `RostorCredProv.dll`, `install.ps1`, `uninstall.ps1`
and `tile.bmp` into one directory on the workstation and run `install.ps1`
as above. Manual enrollment (once, before a non-mock install, or afterwards
followed by `Restart-Service RostorAgent`):

```powershell
& 'C:\Program Files\Rostor\rostor-agent.exe' enroll --core-url https://core:8443 --token <enrollment token> [--ca-file core-ca.pem | --insecure]
```

Uninstall:

```powershell
.\uninstall.ps1          # removes CP registry keys, DLL, service, Program Files; keeps C:\ProgramData\Rostor
.\uninstall.ps1 -Purge   # also removes C:\ProgramData\Rostor (never local accounts); machine is stock afterwards
```

## Trust and renewal

The agent pins the core CA bundle (`ca.crt`, all active CAs concatenated)
and holds a 90-day device certificate. Both are kept current by the
`RostorAgent` service itself, per `docs/contracts/console-api.md`
("Certificates and trust"):

- At service start and every 10 minutes the agent calls
  `GET /v1/devices/self/trust`. When `version` differs from `trust_version`
  in `agent.json` it rewrites `ca.crt` (write `ca.crt.new`, rename) and
  reloads its TLS pool without a restart.
- It renews when core says `renew: true`, or locally when the certificate
  expires within 30 days or was not issued by the newest CA in the bundle:
  a fresh P-256 key and CSR go to `POST /v1/devices/self/renew`; the reply
  is written as `device.key.new` + `device.crt.new` (key ACLed like
  `device.key`), *proven* with one `GET trust` over the staged pair, and only
  then renamed over the live pair (key first, then certificate). Any failure
  before that point discards the staged files and keeps the old pair, which
  core accepts for 24 h after issuing the new one. A crash between the two
  renames is repaired at the next start. Log line: `certificate renewed,
  expires <RFC 3339>`.
- A logon `Verify` that fails in the TLS handshake (the usual sign of a CA
  rotation the device slept through) triggers a trust refresh and one retry
  before the credprov sees `agent.core_unreachable`.

Operator commands (elevated):

```powershell
rostor-agent trust        # pinned CA fingerprints, device cert issuer + expiry, last trust version; no network
rostor-agent renew --now  # force a renewal; the service reloads within 10 minutes or on restart
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

## Scripts (SPEC-scripts, contract §1.4)

On every heartbeat (start, then every 10 minutes, after the trust check and
posture) the service fetches `GET /v1/devices/self/scripts`, verifies each
signature against the pinned `ca.crt` (any active CA), and runs the
immediate scripts whose version has not run yet, one at a time in position
order, then reports each run with `POST …/scripts/{id}/runs`. After every
ALLOW the same list is fetched again and the `signin` scripts run in order
with `ROSTOR_USER`, `ROSTOR_PRINCIPAL` and `ROSTOR_LOCAL_ACCOUNT` set, in a
goroutine after the pipe reply, so the lock screen never waits. State lives
in `C:\ProgramData\Rostor\scripts.json` (last immediate version run and
last sign-in time per script id); bodies are staged as UTF-8+BOM files
under `C:\ProgramData\Rostor\scripts\` for the duration of the run and
removed afterwards. A script whose signature does not verify is logged
(`refused`) and never run; a corrupt `scripts.json` disables scripts until
fixed (logged as `scripts disabled`). Runs are one at a time across
heartbeat and sign-ins, 10-minute limit each, last 4 KB of output
reported; a timed-out run reports exit code -1.

## Sign-in policy on the lock screen (v0.11.0)

On every heartbeat (at start and every ten minutes, after posture) the
agent fetches `GET /v1/devices/self/policy` and keeps the last successful
answer; a failed fetch is logged and the previous value stays in force,
and before the first answer the agent behaves as if the default method
were `password`. The `ui` pipe reply carries `default_method` (`password`,
`passkey` or `badge`) beside `strings`. When it is `badge`, `tile_label`
and `username_label` come from the catalog's `tile_label_badge` ("Tap
your badge") and `username_label_badge` ("Badge, or username") entries;
every other string, including `badge_hint`, is unchanged. The credential
provider renders whatever it is given, so a policy change in the console
shows at the next lock without a DLL update. `--mock-core` reports
`password` with badge format `none`. A method the agent does not
recognise is reported and rendered as `password`.
