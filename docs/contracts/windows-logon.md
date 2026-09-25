# Windows logon slice — component contract (MVP)

Authority: `project/directory-deputy-build-spec.md` (v1.3). This document only
fixes the wire shapes between the three components of the first slice. Where it
and the spec disagree, the spec wins.

Components:

1. **core** (`cmd/rostor`) — the Rostor service. Owns principals, bindings,
   grants, sessions, audit. Mints everything. Runs on Dan's Mac for the PoC.
2. **deputy** (`cmd/rostor-deputy`) — Windows service, a *device principal*
   (spec §5). Enrolls once, then brokers logon between the credential provider
   and core. Owns the derived local Windows accounts.
3. **credprov** (`windows/credprov`) — C++ Credential Provider DLL running
   inside LogonUI as SYSTEM. Collects identifier + secret, hands them to the
   deputy over a named pipe, and serializes the *local* credential the deputy
   returns. Contains no authorization logic and no user-facing string literals.

Data flow at the lock screen:

    person → credprov ──pipe──▶ deputy ──mTLS/HTTPS──▶ core.Verify
                                  │◀── ALLOW/DENY + principal + assurance ──┘
                                  ├─ ALLOW: ensure local account, rotate its
                                  │         random secret, return it
                                  └─ DENY:  disable local account if present,
                                            return reason code + rendered text
            credprov ◀──pipe── {local_user, local_secret} or {denied, text}
            credprov → LogonUI: KERB_INTERACTIVE_UNLOCK_LOGON(".", local_user, local_secret)

The local account is a derived artifact (like a card on a door controller):
created and rotated by the deputy, never managed by a human. Its secret is
re-randomised on every successful logon and is never persisted anywhere.

Out of scope for the PoC (explicitly): cached/offline logon, Windows 11
validation. Badge and badge+PIN sign-in is in (§2.3); it is another credential
type in the same `Verify` call.

Two Windows 10 facts the implementation depends on, learned the hard way:
(1) a provider whose credentials implement `ICredentialProviderCredential2`
must also implement `ICredentialProviderSetUserArray` or LogonUI never lists
its credential; (2) on a workgroup machine LogonUI only offers the "Other user"
form, where a credential without a user SID appears, when the
`dontdisplaylastusername` policy is set. The installer sets it. The deputy also
hides its derived local accounts from the tile list via
`Winlogon\\SpecialAccounts\\UserList`.

---

## 1. core HTTP API (subset used by this slice)

Base: `https://<core-host>:8443`. JSON bodies. Errors are
`{"code": "<stable.code>", "params": {...}}` — never sentences (spec §9).
Human text is rendered by core from the string catalog when a client asks for it
(`Accept-Language`), returned in a separate `message` field.

### 1.1 Device enrollment (deputy, once)

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
and issues an X.509 client certificate from the core CA (spec D3). The deputy
generates the key locally; the private key never leaves the machine.

### 1.2 Verify (deputy, every logon)

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
Reason codes the deputy must understand (others are passed through as text):

| code | meaning | deputy action |
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

### 1.3 Heartbeat / posture (deputy, periodic)

`POST /v1/devices/self/posture` — mTLS. Body: `{"deputy_version": "…", "os_version": "…"}`.
Response `204`. Not required for logon to work; used so core can show the
workstation as alive.

---

### 1.4 Scripts (deputy, on the heartbeat and at sign-in) — SPEC-scripts, v0.9.0

`GET /v1/devices/self/scripts` (mTLS) →

```json
{"scripts":[{"id":"scr_…","name":"Map printers","language":"powershell","version":3,"position":10,
             "mode":"immediate","body":"…","signature":"<base64 ASN.1 DER ECDSA>","signer":"cak_…"}]}
```

Sorted by `position` ascending; the deputy runs them **one at a time in
that order**. `mode` is `immediate` (run once per `version`, as soon as
seen) or `signin` (run at every sign-in, after the logon reply). A script
assigned both ways appears twice with different modes. `signature` is
ECDSA P-256 over SHA-256 of the UTF-8 bytes of `id + "\n" + version +
"\n" + body` (version in decimal), made with the CA key named by
`signer` (a `ca_key_id` from the trust bundle). The deputy verifies against
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

Deputy behaviour: keep `scripts.json` beside `deputy.json` with, per script
id, the last version run for `immediate` and the last sign-in run time.
Run with `powershell.exe -NoProfile -NonInteractive -ExecutionPolicy
Bypass -File <staged .ps1>` as the service (SYSTEM), 10-minute timeout,
staged file removed afterwards. Sign-in runs receive `ROSTOR_USER`
(identifier), `ROSTOR_PRINCIPAL` (principal id) and
`ROSTOR_LOCAL_ACCOUNT` (the derived local account) in the environment.

### 1.5 Effective auth policy (deputy, on the heartbeat) — v0.11.0

`GET /v1/devices/self/policy` (mTLS) →

```json
{"login":{"default_method":"badge"},"badge":{"format":"wiegand26"}}
```

The tenant's auth policy as it applies to **this device**: the tenant-wide
document overridden by any group-scoped override whose group the device
principal is in (nested groups count; when several apply, the newest
override wins). `default_method` is `password`, `passkey` or `badge`.
The deputy fetches it on every heartbeat, keeps the last answer, and uses
it for the `ui` reply below; before the first answer it behaves as
`password`.

### 1.5a Tenant name in the policy (v0.13.0)

`GET /v1/devices/self/policy` also returns `"tenant_name"` (e.g.
`"ChattLab"`), so the tile can name the organisation.

### 1.6 Self-update (deputy, on the heartbeat) — v0.14.0

`GET /v1/devices/self/update` (mTLS) → `{"update":null}` when this device
should stay as it is, otherwise

```json
{"update":{"version":"v0.14.0","sha256":"<hex of the bundle>","signature":"<base64 ASN.1 DER ECDSA>","signer":"cak_…","size":3350420}}
```

The wanted version is always the core's own version: with the tenant
policy `deputy.update` = `auto` every device whose reported
`deputy_version` differs is told to update; with `manual` (the default)
only devices an admin marked (Devices → Update) are. The signature is
ECDSA P-256 over SHA-256 of `bundle\n<version>\n<sha256>` with the CA key
named by `signer`, verified against `ca.crt` like a script. The bundle
itself is `GET /v1/devices/self/update/bundle` (mTLS, `application/zip`,
the same `rostor-windows-amd64.zip` the console offers, cached by the
core).

Deputy behaviour: never start an update while a logon is in flight, and
at most one update attempt per version. Download to
`C:\ProgramData\Rostor\updates\<version>\rostor-windows-amd64.zip`,
check the size and sha256, verify the signature, extract beside it, write
`updates\pending.json` (`{version, started_at}`), then start
`powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File
<extracted>\install.ps1` through a one-shot SYSTEM scheduled task `RostorDeputyUpdate` (v0.14.3: a child started straight from the service ran nothing) (the installer stops this service,
replaces the binary and the DLL, and starts the new service; a re-run
keeps the enrollment) with its output to `updates\<version>\install.log`.
On start, a deputy that finds `pending.json` reports the outcome and
removes it:

`POST /v1/devices/self/update/runs` (mTLS) → 201:

```json
{"version":"v0.14.0","status":"ok|failed","from_version":"v0.13.0","output_tail":"last 4 KB of install.log"}
```

`ok` when the running deputy's version equals `pending.version`;
`failed` otherwise (an older deputy came back up, or the installer
logged an error). The core audits it as `deputy.update`, stores the
result on the device, and clears the admin's mark on success. A failed
attempt is not retried until an admin marks the device again.

## 2. deputy ⇄ credprov named-pipe protocol

Pipe: `\\.\pipe\rostor-deputy`. Security: DACL grants full access to
`SYSTEM` and `Administrators` only. The deputy is the server. Message framing:
one JSON object per request, newline-terminated; one JSON object reply,
newline-terminated; then the client closes. Requests time out at 30 s on the
credprov side, after which it treats the result as `{"ok":false,"code":"deputy.timeout"}`.
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
from this reply (spec §0.2, no hardcoded user-facing strings). If the deputy is
unreachable the credprov shows its tile with empty labels and reports
`deputy.unreachable` on submit — it never invents text.

#### `ui` and the default method (v0.11.0)

The `ui` reply carries `"default_method"` next to `strings`. When it is
`badge`, the deputy already returns badge-first strings (`tile_label`
"Tap your badge", `username_label` "Badge", the
`badge_hint`); the credential provider renders whatever strings it is
given, so a policy change shows at the next lock without a credential
provider update. The credential provider may additionally use
`default_method` to open on the identifier field with the hint visible.

#### Badge-first tile and the organisation name (v0.13.0)

`strings` gains three entries: `heading` (large text above the fields:
"Sign in to ChattLab", or "Tap your badge · ChattLab" when the default
method is badge), `switch_to_username` ("Use username") and
`switch_to_badge` ("Use badge"). All are rendered from the deputy's
catalog with the tenant name from §1.5a; an older deputy that omits them
leaves the provider on its previous labels.

When `default_method` is `badge` the provider shows a **masked** field as
the identifier (a reader burst appears as dots, never as digits), labelled
by `username_label`, with a command link `switch_to_username` that swaps
in the plain username field; in username mode the link reads
`switch_to_badge`. A submit from the masked field sends the text as the
badge number (the `badge` shape of §2.3); a submit from the plain field is
the identifier-first shape of §2.2. PIN handling is unchanged. When
`default_method` is `password` or `passkey` the tile opens on the plain
field with `switch_to_badge` offered.

#### Which tile is the default (v0.13.0)

`GET /v1/devices/self/policy` also carries `"logon":{"default_provider":
"rostor"|"windows"}` and the `ui` reply repeats it as
`"default_provider"`. `rostor` (the default) keeps today's behaviour: the
Rostor tile is selected when the lock screen appears. `windows` makes the
provider report no default (`CREDENTIAL_PROVIDER_NO_DEFAULT`), so Windows
selects its own password tile (local or domain user and password) and the
Rostor tile stays one click away. Tenant-wide or per group, changed from
the console; the deputy applies it at the next lock.

#### Shared session account (v0.13.0)

An ALLOW from `POST /v1/verify` may carry `"session_account":"chattlab"`
(from the device's `logon.session_account` policy). The deputy then
creates or enables **that** local account (owned and rotated like a
derived one) and hands the session to it instead of the person's derived
account; the person is still the one Rostor audited. `GET
/v1/devices/self/policy` also reports it under `logon.session_account`.

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
`message` is already rendered in the requested locale by core (or by the deputy's
own bundled catalog for deputy-local codes such as `deputy.core_unreachable`).
The credprov shows `message` verbatim via `ICredentialProviderCredential::ReportResult`.

Deputy-local codes: `deputy.core_unreachable`, `deputy.not_enrolled`,
`deputy.local_account_failed`, `deputy.timeout`.

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
The deputy calls core `Verify` with `{"type":"badge","number":…,"pin":…}` and
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

## 3. Local account management (deputy)

- Local username = the principal's `username` (validated: `^[a-z0-9._-]{1,20}$`
  after lowercasing; anything else is rejected with `deputy.local_account_failed`).
- Created with `NetUserAdd` (level 1): flags `UF_SCRIPT | UF_DONT_EXPIRE_PASSWD`,
  comment `Managed by Rostor — do not edit`, full name = `display_name`.
  Added to the local `Users` group. Never to Administrators.
- On every ALLOW: set a fresh 32-char random password (`NetUserSetInfo` level
  1003), clear `UF_ACCOUNTDISABLE`, then return it. The secret lives only in
  memory for the duration of the pipe reply.
- On DENY with `principal.suspended` or `principal.not_active`: set
  `UF_ACCOUNTDISABLE` if the account exists. Never delete accounts (profiles hold
  the person's files).
- The deputy keeps a ledger `C:\ProgramData\Rostor\accounts.json` of usernames it
  created, and only ever modifies accounts on that ledger. Pre-existing local
  accounts (e.g. `ChattLab`) are never touched.

---

## 4. Files on the workstation

```
C:\ProgramData\Rostor\
  deputy.json          {"core_url": "https://…:8443", "device_id": "…"}
  device.key          PKCS#8, ACL: SYSTEM full, Administrators read
  device.crt          issued client certificate
  ca.crt              core CA to pin
  accounts.json       ledger of deputy-created local usernames
  logs\deputy.log
C:\Program Files\Rostor\rostor-deputy.exe
C:\Windows\System32\RostorCredProv.dll
```

Service name: `RostorDeputy`, display name `Rostor Deputy`, start automatic,
runs as `LocalSystem`.

Credential provider CLSID: `{7A4C2E10-5B0D-4F4E-9C1B-3E2D7F1A6B01}`.
Registry: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{CLSID}`
`(Default)="RostorCredProv"`; `HKLM\SOFTWARE\Classes\CLSID\{CLSID}\InprocServer32`
`(Default)="RostorCredProv.dll"`, `ThreadingModel="Apartment"`.
The built-in password provider is **not** filtered out, so the local admin can
always sign in if Rostor is down (PoC safety; an offline-logon design replaces
this later).
