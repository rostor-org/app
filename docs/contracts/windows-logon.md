# Windows logon slice — component contract (MVP)

Authority: `project/directory-agent-build-spec.md` (v1.3). This document only
fixes the wire shapes between the three components of the first slice. Where it
and the spec disagree, the spec wins.

Components:

1. **core** (`cmd/rostor`) — the Rostor service. Owns principals, bindings,
   grants, sessions, audit. Mints everything. Runs on Dan's Mac for the PoC.
2. **agent** (`cmd/rostor-agent`) — Windows service, a *device principal*
   (spec §5). Enrolls once, then brokers logon between the credential provider
   and core. Owns the derived local Windows accounts.
3. **credprov** (`windows/credprov`) — C++ Credential Provider DLL running
   inside LogonUI as SYSTEM. Collects identifier + secret, hands them to the
   agent over a named pipe, and serializes the *local* credential the agent
   returns. Contains no authorization logic and no user-facing string literals.

Data flow at the lock screen:

    person → credprov ──pipe──▶ agent ──mTLS/HTTPS──▶ core.Verify
                                  │◀── ALLOW/DENY + principal + assurance ──┘
                                  ├─ ALLOW: ensure local account, rotate its
                                  │         random secret, return it
                                  └─ DENY:  disable local account if present,
                                            return reason code + rendered text
            credprov ◀──pipe── {local_user, local_secret} or {denied, text}
            credprov → LogonUI: KERB_INTERACTIVE_UNLOCK_LOGON(".", local_user, local_secret)

The local account is a derived artifact (like a card on a door controller):
created and rotated by the agent, never managed by a human. Its secret is
re-randomised on every successful logon and is never persisted anywhere.

Out of scope for the PoC (explicitly): cached/offline logon, Windows 11
validation. Badge and badge+PIN sign-in is in (§2.3); it is another credential
type in the same `Verify` call.

Two Windows 10 facts the implementation depends on, learned the hard way:
(1) a provider whose credentials implement `ICredentialProviderCredential2`
must also implement `ICredentialProviderSetUserArray` or LogonUI never lists
its credential; (2) on a workgroup machine LogonUI only offers the "Other user"
form, where a credential without a user SID appears, when the
`dontdisplaylastusername` policy is set. The installer sets it. The agent also
hides its derived local accounts from the tile list via
`Winlogon\\SpecialAccounts\\UserList`.

---

## 1. core HTTP API (subset used by this slice)

Base: `https://<core-host>:8443`. JSON bodies. Errors are
`{"code": "<stable.code>", "params": {...}}` — never sentences (spec §9).
Human text is rendered by core from the string catalog when a client asks for it
(`Accept-Language`), returned in a separate `message` field.

### 1.1 Device enrollment (agent, once)

`POST /v1/devices/enroll` — no client cert; authenticated by a single-use
enrollment token minted by an admin.

Request:
```json
{"enrollment_token": "…", "csr_pem": "-----BEGIN CERTIFICATE REQUEST-----…",
 "posture": {"os": "windows", "os_version": "10.0.19045", "hostname": "DESKTOP-UPJD27E"}}
```
Response `201`:
```json
{"device_id": "dev_…", "certificate_pem": "…", "ca_pem": "…",
 "resource": {"type": "workstation", "id": "DESKTOP-UPJD27E"}}
```
Core creates: a Device principal, a `workstation` resource with the same ID,
and issues an X.509 client certificate from the core CA (spec D3). The agent
generates the key locally; the private key never leaves the machine.

### 1.2 Verify (agent, every logon)

`POST /v1/verify` — mTLS; the client certificate identifies the device
principal. This is spec §6.2 `Verify`: credential presentation → principal +
decision, in one motion, audited with credential type + assurance.

Request:
```json
{"credential": {"type": "password", "identifier": "dan", "secret": "…"},
 "action": "logon",
 "resource": {"type": "workstation", "id": "DESKTOP-UPJD27E"},
 "locale": "en"}
```
Response `200` (always 200 when the request is well-formed; the decision is in
the body):
```json
{"decision": "ALLOW",
 "principal": {"id": "usr_…", "username": "dan", "display_name": "Dan Evans"},
 "assurance": "AL1",
 "reason": [{"code": "grant.matched", "params": {"grant_id": "…", "via": "group:members"}}],
 "session": {"token": "…", "expires_at": "…"}}
```
or
```json
{"decision": "DENY",
 "reason": [{"code": "auth.failed", "params": {}}],
 "message": "Sign-in failed."}
```
Reason codes the agent must understand (others are passed through as text):

| code | meaning | agent action |
|---|---|---|
| `auth.failed` | credential did not verify (never says which part) | return text |
| `auth.locked` | cross-method lockout active | return text |
| `principal.suspended` | suspension (evaluated before grants, §3.2) | disable local account, return text |
| `principal.not_active` | lifecycle state ≠ active | disable local account, return text |
| `grant.none` | authenticated but no `logon` grant on this workstation | return text |
| `device.not_trusted` | the calling device is quarantined/retired | return text |

The `password` credential type is the PoC path. A badge presentation
`{"type":"badge","number":"<digits as typed by a reader>","pin":"<optional>"}`
uses this same endpoint (other forms: `uid`, `facility`+`card`; see
`console-api.md`, "Passkeys and badges"). One more decision exists for it:
`{"decision":"CONTINUE","reason":[{"code":"auth.continue","params":{"need":"pin"}}],"message":"Enter your PIN."}`
— the card matched but is PIN-protected and no PIN was sent. Nothing has been
allowed or denied; the caller collects the PIN and repeats the request with it.

### 1.3 Heartbeat / posture (agent, periodic)

`POST /v1/devices/self/posture` — mTLS. Body: `{"agent_version": "…", "os_version": "…"}`.
Response `204`. Not required for logon to work; used so core can show the
workstation as alive.

---

### 1.4 Scripts (agent, on the heartbeat and at sign-in) — SPEC-scripts, v0.9.0

`GET /v1/devices/self/scripts` (mTLS) →

```json
{"scripts":[{"id":"scr_…","name":"Map printers","language":"powershell","version":3,"position":10,
             "mode":"immediate","body":"…","signature":"<base64 ASN.1 DER ECDSA>","signer":"cak_…"}]}
```

Sorted by `position` ascending; the agent runs them **one at a time in
that order**. `mode` is `immediate` (run once per `version`, as soon as
seen) or `signin` (run at every sign-in, after the logon reply). A script
assigned both ways appears twice with different modes. `signature` is
ECDSA P-256 over SHA-256 of the UTF-8 bytes of `id + "\n" + version +
"\n" + body` (version in decimal), made with the CA key named by
`signer` (a `ca_key_id` from the trust bundle). The agent verifies against
the CA certificates in its `ca.crt` and **must not run** a script whose
signature does not verify.

`POST /v1/devices/self/scripts/{id}/runs` (mTLS) →

```json
{"version":3,"mode":"immediate","principal_id":"usr_… or empty","started_at":"RFC3339","finished_at":"RFC3339",
 "exit_code":0,"status":"ok|failed|timeout|error","output_tail":"last 4 KB of stdout+stderr"}
```

→ 201. `status` is `ok` for exit 0, `failed` for any other exit code,
`timeout` after 10 minutes, `error` when PowerShell could not be started
(`exit_code` -1). The core records the run and audits it as `script.run`.

Agent behaviour: keep `scripts.json` beside `agent.json` with, per script
id, the last version run for `immediate` and the last sign-in run time.
Run with `powershell.exe -NoProfile -NonInteractive -ExecutionPolicy
Bypass -File <staged .ps1>` as the service (SYSTEM), 10-minute timeout,
staged file removed afterwards. Sign-in runs receive `ROSTOR_USER`
(identifier), `ROSTOR_PRINCIPAL` (principal id) and
`ROSTOR_LOCAL_ACCOUNT` (the derived local account) in the environment.

## 2. agent ⇄ credprov named-pipe protocol

Pipe: `\\.\pipe\rostor-agent`. Security: DACL grants full access to
`SYSTEM` and `Administrators` only. The agent is the server. Message framing:
one JSON object per request, newline-terminated; one JSON object reply,
newline-terminated; then the client closes. Requests time out at 30 s on the
credprov side, after which it treats the result as `{"ok":false,"code":"agent.timeout"}`.
(SAM writes on a loaded workstation have been measured at 10–20 s; the core
round trip itself is well under a second.)

### 2.1 `ui` — fetch display strings (credprov calls once per LogonUI session)

Request: `{"op":"ui","locale":"en-US"}`

Reply:
```json
{"ok": true,
 "strings": {"tile_label": "Rostor", "username_label": "Username",
             "password_label": "Password", "submit_label": "Sign in",
             "connecting": "Contacting Rostor…",
             "pin_label": "PIN", "badge_hint": "Tap your badge or type your username"}}
```
`badge_hint` is the cue text of the identifier field (LogonUI shows an edit
field's label as its watermark); `pin_label` labels the PIN field that appears
after a badge tap answered `auth.continue` (§2.3).
The credprov has **no** English literals of its own; every visible word comes
from this reply (spec §0.2, no hardcoded user-facing strings). If the agent is
unreachable the credprov shows its tile with empty labels and reports
`agent.unreachable` on submit — it never invents text.

### 2.2 `logon` — authenticate and obtain the local credential

Request:
```json
{"op":"logon","identifier":"dan","secret":"…","locale":"en-US"}
```
Reply on ALLOW:
```json
{"ok": true, "local_user": "dan", "local_secret": "<32 random chars>"}
```
Reply on DENY or failure:
```json
{"ok": false, "code": "principal.suspended", "message": "Your account is suspended."}
```
`message` is already rendered in the requested locale by core (or by the agent's
own bundled catalog for agent-local codes such as `agent.core_unreachable`).
The credprov shows `message` verbatim via `ICredentialProviderCredential::ReportResult`.

Agent-local codes: `agent.core_unreachable`, `agent.not_enrolled`,
`agent.local_account_failed`, `agent.timeout`.

### 2.3 `logon` with a badge — tap, then PIN if asked

A USB keyboard-wedge reader types the card number as digits and ends with
Enter. The credprov has no reader driver: a submit whose identifier field is
digits only (six or more) with an empty secret is treated as a tap and sent as
a badge instead of a password.

Request (tap):
```json
{"op":"logon","badge":{"number":"5555555555"},"locale":"en-US"}
```
Reply on ALLOW and on DENY: exactly as §2.2. One more reply exists:
```json
{"ok": false, "code": "auth.continue", "message": "Enter your PIN.", "need": "pin"}
```
It mirrors core's `CONTINUE` decision: the card is known but PIN-protected.
The credprov keeps the number, switches the tile into PIN mode (secret field
hidden, PIN field shown and focused, submit next to it, `message` in the
large text) and on the next submit repeats the request with the PIN:
```json
{"op":"logon","badge":{"number":"5555555555","pin":"2468"},"locale":"en-US"}
```
On ALLOW the local credential is packed exactly as on the password path. On
any failure the tile returns to its initial form with the identifier cleared.
The agent calls core `Verify` with `{"type":"badge","number":…,"pin":…}` and
never touches a local account on `CONTINUE`; a badge denial with
`principal.suspended`/`principal.not_active` also leaves local accounts alone
because the reply names no username.

Tapping while the tile is not selected: Rostor is the default tile on the
"Other user" form and its identifier field is `CPFIS_FOCUSED`, so on a machine
with `dontdisplaylastusername` set the reader's keystrokes land in that field
without a click. Limits: the lock-screen curtain must already be dismissed
(the first keystroke of a burst only lifts it and the rest is lost — tap
again); if the person has switched to another tile (e.g. the local password
tile under Sign-in options) the burst goes there; and LogonUI ignores input
while a serialization is in flight.

---

## 3. Local account management (agent)

- Local username = the principal's `username` (validated: `^[a-z0-9._-]{1,20}$`
  after lowercasing; anything else is rejected with `agent.local_account_failed`).
- Created with `NetUserAdd` (level 1): flags `UF_SCRIPT | UF_DONT_EXPIRE_PASSWD`,
  comment `Managed by Rostor — do not edit`, full name = `display_name`.
  Added to the local `Users` group. Never to Administrators.
- On every ALLOW: set a fresh 32-char random password (`NetUserSetInfo` level
  1003), clear `UF_ACCOUNTDISABLE`, then return it. The secret lives only in
  memory for the duration of the pipe reply.
- On DENY with `principal.suspended` or `principal.not_active`: set
  `UF_ACCOUNTDISABLE` if the account exists. Never delete accounts (profiles hold
  the person's files).
- The agent keeps a ledger `C:\ProgramData\Rostor\accounts.json` of usernames it
  created, and only ever modifies accounts on that ledger. Pre-existing local
  accounts (e.g. `ChattLab`) are never touched.

---

## 4. Files on the workstation

```
C:\ProgramData\Rostor\
  agent.json          {"core_url": "https://…:8443", "device_id": "…"}
  device.key          PKCS#8, ACL: SYSTEM full, Administrators read
  device.crt          issued client certificate
  ca.crt              core CA to pin
  accounts.json       ledger of agent-created local usernames
  logs\agent.log
C:\Program Files\Rostor\rostor-agent.exe
C:\Windows\System32\RostorCredProv.dll
```

Service name: `RostorAgent`, display name `Rostor Agent`, start automatic,
runs as `LocalSystem`.

Credential provider CLSID: `{7A4C2E10-5B0D-4F4E-9C1B-3E2D7F1A6B01}`.
Registry: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{CLSID}`
`(Default)="RostorCredProv"`; `HKLM\SOFTWARE\Classes\CLSID\{CLSID}\InprocServer32`
`(Default)="RostorCredProv.dll"`, `ThreadingModel="Apartment"`.
The built-in password provider is **not** filtered out, so the local admin can
always sign in if Rostor is down (PoC safety; an offline-logon design replaces
this later).
