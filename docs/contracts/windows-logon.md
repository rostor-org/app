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

Out of scope for the PoC (explicitly): cached/offline logon, badge+PIN (planned;
it is another credential type in the same `Verify` call), account hiding from
the local user picker, Windows 11 validation.

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

The `password` credential type is the PoC path. A later `{"type":"badge","uid":"…","pin":"…"}`
presentation uses this same endpoint unchanged.

### 1.3 Heartbeat / posture (agent, periodic)

`POST /v1/devices/self/posture` — mTLS. Body: `{"agent_version": "…", "os_version": "…"}`.
Response `204`. Not required for logon to work; used so core can show the
workstation as alive.

---

## 2. agent ⇄ credprov named-pipe protocol

Pipe: `\\.\pipe\rostor-agent`. Security: DACL grants full access to
`SYSTEM` and `Administrators` only. The agent is the server. Message framing:
one JSON object per request, newline-terminated; one JSON object reply,
newline-terminated; then the client closes. Requests time out at 10 s on the
credprov side, after which it treats the result as `{"ok":false,"code":"agent.timeout"}`.

### 2.1 `ui` — fetch display strings (credprov calls once per LogonUI session)

Request: `{"op":"ui","locale":"en-US"}`

Reply:
```json
{"ok": true,
 "strings": {"tile_label": "Rostor", "username_label": "Username",
             "password_label": "Password", "submit_label": "Sign in",
             "connecting": "Contacting Rostor…"}}
```
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
