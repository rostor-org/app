# Console API contract (MVP)

The console is a client of the same API as the CLI and agents (spec principle
6). This document fixes the endpoints the React console uses. All admin
endpoints live under `/v1/admin/…`, accept either `Authorization: Bearer
<api token>` or the console session cookie, and are authorised through
`Check(caller, <action>, directory:root)`.

Errors: `{"code":"…","params":{…},"message":"<rendered in caller locale>"}`.
IDs are opaque strings. Times are RFC 3339 UTC. Lists return
`{"items":[…],"total":N}`; `?q=` filters, `?limit=&offset=` page (default 50).

## Static app and catalog

- `GET /` and any non-`/v1` path → the embedded SPA (`index.html`), served
  on the proxy listener (8080) and on 8443.
- `GET /v1/catalog?locale=en` → `{"locale":"en","strings":{code:template}}`.
  The console has **no** string literals; every label is a catalog code
  (`ui.nav.people`, `ui.people.title`, …). Unknown codes render as the code
  so gaps are visible.
- `GET /v1/brand` → `{"tenant_name":"ChattLab","tokens":{"ink":"#14161a",…}}`.

## Console session (identifier-first, §7.6)

- `POST /v1/auth/login` `{"identifier":"dan","method":"password","fields":{"password":"…"}}`
  → `200 {"principal":{…},"assurance":"AL1","expires_at":…}` and sets an
  `HttpOnly; SameSite=Lax; Secure` cookie `rostor_session`. Failure → `200`
  with `{"code":"auth.failed"|"auth.locked"|"principal.suspended"}` (never
  400, never distinguishing unknown user from wrong secret).
- `GET /v1/auth/session` → the current principal, assurance, and the actions
  the caller may perform on `directory:root` (`"permissions":["users.write",…]`
  or `["*"]`), so the console can hide what it cannot do.
- `POST /v1/auth/logout` → 204, revokes the session.
- CSRF: the SPA sends `X-Requested-With: rostor-console` on every mutating
  request; the server rejects cookie-authenticated mutations without it.

## Live events

- `GET /v1/events/stream` (SSE, `text/event-stream`). Each message:
  `event: <type>` (`user.created`, `user.suspended`, `grant.created`,
  `device.enrolled`, `audit.appended`, `update.state`, …),
  `id: <events.id>`, `data: {"type":…,"target_type":…,"target_id":…,"ts":…}`.
  Supports `Last-Event-ID` for replay of missed events. Heartbeat comment
  every 25 s. The console invalidates queries by event type; it never uses
  the payload as data.

## Reads

| Endpoint | Returns |
|---|---|
| `GET /v1/admin/summary` | `{people:{active,suspended,applicants,service_accounts}, groups, grants, devices:{<lifecycle>:n}, offline_points, oldest_snapshot_age_seconds|null}` |
| `GET /v1/admin/users` | items: `{id, username, display_name, state, groups:[{id,name}], methods:[{method,assurance}], last_sign_in:{ts,resource}}` |
| `GET /v1/admin/users/{id}` | `{id,username,kind,display_name,state,attributes,created_at, groups:[{id,name,direct}], bindings:[{id,method,properties,label,state,assurance,created_at,last_used_at}], effective_security:{assurance,bindings,recovery_paths}, recent:[audit rows]}` |
| `GET /v1/admin/groups` | items: `{id,name,display_name,kind,member_count,grant_count}` |
| `GET /v1/admin/groups/{name}` | `{id,name,display_name,kind, members:[{kind,id,name,display_name,state}], grants:[grant rows]}` |
| `GET /v1/admin/grants` | items: `{id, subject:{kind,id,name}, role, resource:{type,id}, condition, condition_class, not_before, expires_at}` |
| `GET /v1/admin/devices` | items: `{id, display_name, resource:{type,id}, lifecycle, last_seen_at, posture, cert_not_after}` |
| `GET /v1/admin/audit?limit=&before=<seq>&q=&include_system=1` | `{"items":[{seq,ts,actor:{kind,id},action,target:{type,id},credential_type,assurance,outcome,detail}],"head":{seq}}` |
| `GET /v1/admin/audit/verify` | `{intact,first_bad_seq}` (existing) |
| `GET /v1/admin/why?principal=&action=&resource_type=&resource_id=` | existing: decision, reason chain, groups→paths, candidates with per-condition results, as_of |
| `GET /v1/admin/updates` | existing state; `POST /v1/admin/updates/apply` |
| `GET /v1/admin/system` | `{version, tenant:{id,name}, db:{size_bytes}, uptime_seconds, ca:{subject,not_after}, release_key_fingerprint, profile:"standard"}` |
| `GET /v1/admin/plugins` | `{"items":[]}` for now; shape `{id,name,publisher,version,type,runtime,masters:[…],scopes:[…],state}` |

## Writes (existing, unchanged)

`POST /v1/admin/users`, `POST /v1/admin/users/{id}/state`,
`POST /v1/admin/users/{id}/bindings`, `POST /v1/admin/groups`,
`POST|DELETE /v1/admin/groups/{name}/members`, `POST /v1/admin/grants`,
`DELETE /v1/admin/grants/{id}`, `POST /v1/admin/enrollment-tokens`,
`POST /v1/admin/updates/apply`. New: `DELETE /v1/admin/users/{id}/bindings/{bid}` (revoke).

## Reason rendering

`reason[]` entries are `{code, params}` without `message`; the console renders
them with `t(code, params)`. Every code the engine emits is in the catalog
(`make lint-strings` enforces it).

## Not yet in the API (console shows "not available yet")

CSV import, badge enrollment, password-reset ceremonies, audit export, the
plugin registry, key rotation, policy counts on groups.

## Passkeys and badges (added with v0.1.3)

- `GET /v1/admin/settings/auth` → `{"webauthn":{"rp_id","display_name","origins":[…],"enrolled_passkeys":N}}`;
  `PUT` the same shape (without `enrolled_passkeys`) to set it. It writes the
  tenant-wide auth policy. **Changing `rp_id` after passkeys exist orphans
  them**; the console must warn when `enrolled_passkeys > 0`.
- `POST /v1/auth/passkeys/register/begin` (session; no body) → `{"ceremony_id","options"}`
  where `options` is the `PublicKeyCredentialCreationOptions` wrapper for
  `navigator.credentials.create` (base64url fields; use the WebAuthn JSON
  helpers `PublicKeyCredential.parseCreationOptionsFromJSON` when available).
  `POST …/register/finish` `{"ceremony_id","label","response":<credential.toJSON()>}` → `201` binding.
  Errors: `auth.passkeys_unconfigured` (400), `auth.passkey_rejected` (400).
- `POST /v1/auth/login/passkey/begin` `{}` or `{"identifier":"dan"}` → `{"ceremony_id","options"}`
  (`PublicKeyCredentialRequestOptions` wrapper; empty allowCredentials means
  discoverable — pass `mediation: "conditional"` for autofill).
  `POST …/login/passkey/finish` `{"ceremony_id","response":<assertion.toJSON()>}` →
  the same 200 shapes as `/v1/auth/login` (session view, or `{code,message}`).
- Badge enrollment uses the existing bindings endpoint:
  `POST /v1/admin/users/{id}/bindings` `{"method":"badge","label":"…","fields":{"number":"<as typed by a reader>","pin":"1234"}}`.
  `fields` may instead carry `uid`, `printed`, or `facility`+`card`; every
  form is derived and indexed. A card already registered → `409 request.conflict`.
- Badge sign-in: `POST /v1/auth/login` `{"method":"badge","fields":{"number":"…","pin":"…"}}`
  with no identifier. If the badge has a PIN and none was sent the reply is
  `{code:"auth.continue", params:{need:"pin"}}` (200): ask for the PIN and
  resend with it.
- `Verify` accepts `{"type":"badge","number":"…","pin":"…"}` (or `uid` /
  `facility`+`card`); a missing PIN on a PIN-protected badge returns
  `decision: "CONTINUE"` with reason `auth.continue`.
- Person detail bindings now include method `webauthn` (label = the manager
  or key name) and `badge`; both are revocable via `DELETE …/bindings/{bid}`.
- `POST /v1/admin/updates/check` (v0.1.3) → fetches the channel now and returns
  the update state; the server also emits an `update.state` event. "Check
  now" calls this; `GET /v1/admin/updates` only reads the last recorded state.

## First administrator, My account, self-service (v0.3.0)

- `GET /v1/auth/setup` (public) → `{"needed": bool}`. While true, the sign-in
  page offers "Set up the first administrator".
- `POST /v1/auth/setup` `{"bootstrap_token","username","display_name","password"}`
  → `201` session view and cookie (the person is created, given a password,
  added to `directory-admins`, signed in). Errors: `setup.token_invalid`
  (401), `setup.already_done` (400).
- Admin rights come from membership of the built-in group `directory-admins`
  (grant: role `admin` on `directory:root`). Show it like any group.
- Self-service rule: a signed-in person may `GET /v1/admin/users/{self}` and
  manage their own sign-in methods without admin permissions. `{id}` may be
  the principal id or the username.
- `POST /v1/admin/users/{id}/password` `{"current","new"}` → 204. Self must
  send `current` (checked, counts toward lockout); an admin resetting someone
  else omits it. Audited as `password.change` / `password.reset`.
- `POST /v1/admin/users/{id}/bindings/{bid}/pin` `{"pin"}` → 204 (badge
  bindings only; empty pin removes it). Audited as `binding.pin_set`.
- Person detail `groups[]` entries carry `direct: bool` (direct vs inherited).
- Roles for the grant form: `GET /v1/admin/roles` → `{"items":[{resource_type,name,permissions}]}`.
- Pickers for the grant form (v0.6.0): `GET /v1/admin/resources` →
  `{"items":[{type,id,parent:{type,id}|null}], "total", "permissions":{<type>:[action…]}}`.
  `permissions` lists what is known per type: for `directory` every action the
  admin API checks plus `*`; for `workstation(s)` the device actions; for any
  type, whatever existing roles already use. `POST /v1/admin/roles`
  `{resource_type,name,permissions}` defines a role (roles.write) and is what
  the form's "New role…" calls before creating the grant.
- Deputy updates (v0.14.0). Tenant policy `deputy.update`: `GET/PUT
  /v1/admin/settings/devices` (system.read / policies.write) →
  `{deputy:{update:"auto"|"manual"}}`; `auto` tells every device whose
  reported `deputy_version` differs from the core's version to update on
  its next heartbeat, `manual` (default) only devices marked. Marking:
  `POST /v1/admin/devices/{id}/update` (devices.write) → 202, and `POST
  /v1/admin/devices/update-all` → `{marked:n}` for every trusted device
  on an older version. Device rows carry `deputy_version` (from posture),
  `update:{wanted:bool, status:"ok"|"failed"|null, at, from_version,
  output_tail}` (the last reported attempt). Devices fetch
  `GET /v1/devices/self/update` and the bundle, and report with `POST
  /v1/devices/self/update/runs`; audit `deputy.update` (by the device) and
  `device.update_marked` (by the admin). The wanted version is always the
  core's own.
- Lock-screen default (v0.13.0): `PUT /v1/admin/settings/auth` accepts
  `logon:{default_provider:"rostor"|"windows"}` (echoed by GET under
  `logon`), and an override may set the same key; `windows` leaves the
  Windows password tile selected on the lock screen with Rostor one click
  away, `rostor` (default) selects the Rostor tile. Devices read it at
  `GET /v1/devices/self/policy` under `logon.default_provider`.
- Sign-in overrides by group (v0.11.0). The tenant-wide auth policy
  (`PUT /v1/admin/settings/auth`) can be overridden per group for
  `login.default_method`, and the override applies to people *and* to
  devices in that group (a workstation group set to `badge` opens its lock
  screens on the badge). `GET /v1/admin/settings/auth/overrides`
  (system.read) → `{items:[{group:{id,name}, login:{default_method},
  created_at}]}`; `PUT /v1/admin/settings/auth/overrides/{group}`
  (policies.write) `{login:{default_method}?, logon:{session_account}?}` →
  the item (creates or replaces; the policy is named `auth:<group>`; at
  least one of the two must be given). `logon.session_account` (v0.13.0,
  lowercase, ≤ 20 chars) makes every session on the group's devices run as
  that shared local account, for a workstation whose software is licensed
  to one account; the person who signed in is still the one in the audit,
  and the verify reply to the deputy carries `session_account`. `DELETE
  /v1/admin/settings/auth/overrides/{group}` → 204. When a principal is in
  several overridden groups the newest override wins. Devices read their
  effective policy at `GET /v1/devices/self/policy`. Audit:
  `policy.update` / `policy.delete` with the group in the detail.
- Portal (v0.10.0, SPEC-portal). `GET /v1/portal` (no session needed) →
  `{signed_in, tiles:[{id, kind:"screen"|"link", href, category, order,
  icon, title, description, public, builtin, requires, grants}]}`: the
  tiles the caller may see. A built-in screen tile shows to whoever holds
  its `requires` permission on the directory (`session` = any signed-in
  principal; a directory admin sees all); a link tile shows to whoever a
  grant of role `viewer` on `portal.tile:<id>` (or on `portal:root`)
  allows. The built-in group `everyone` is implicit for every principal
  and stands for anonymous visitors: a `viewer` grant to it makes a tile
  public. Admin: `GET /v1/admin/portal/tiles` (system.read); `POST
  /v1/admin/portal/tiles {id?, title, description?, href, category?,
  icon?, order?, public?}` (system.write; href must be http(s) or a
  console path; id defaults to a slug of the title); `PUT …/{id}` (built-in
  tiles accept only category, order, public); `DELETE …/{id}` (links only;
  revokes their grants). Audit: `tile.create|update|delete`. Titles of
  built-in tiles are catalog strings `ui.tile.<id>`.
- Scripts (v0.9.0, SPEC-scripts). Permissions `scripts.read` and
  `scripts.write`; every write additionally needs an AL2 session
  (403 `request.assurance_required` `{required:"AL2"}` otherwise).
  `GET /v1/admin/scripts` → `{items:[script], total}`, sorted by
  `position`; script = `{id, name, description, language, position,
  version, updated_at, updated_by:{id,name}, assignments:[{id,
  target:{kind:"all"|"group", id, name}, mode:"immediate"|"signin"}],
  last_run:{at, exit_code, status, device:{id,name}}|null}` (no body in
  the list). `POST /v1/admin/scripts {name, description?, language?,
  body}` → 201 script with `body`; `GET /v1/admin/scripts/{id}` → script
  with `body` and `runs` (last 50, see below); `PUT /v1/admin/scripts/{id}
  {name?, description?, body?}` → script (version increments when the body
  changes); `DELETE /v1/admin/scripts/{id}` → 204; `PUT
  /v1/admin/scripts/order {ids:[…]}` → 204 (positions follow the list).
  `POST /v1/admin/scripts/{id}/assignments {target_kind:"all"|"group",
  target:"workstation"|<group name>, mode}` → 201 assignment; `DELETE
  /v1/admin/scripts/{id}/assignments/{aid}` → 204. `GET
  /v1/admin/scripts/{id}/runs?limit=` → `{items:[{id, device:{id,name},
  principal:{id,name}|null, version, mode, started_at, finished_at,
  exit_code, status, output_tail}]}` newest first. Language is
  `powershell` only. Audit: `script.create|update|delete|order|assign|
  unassign` by the admin, `script.run` by the device.
- Badge number format (v0.8.0): `GET/PUT /v1/admin/settings/auth` carry
  `badge.format`: `none` (default; every form a card is seen in is kept and
  matched) or `wiegand26` (every reading, whether full UID hex/decimal,
  printed 24-bit number, or facility:card, is reduced to facility:card and
  the badge is saved as that one form; a byte-reversed UID is tried at
  presentation). Person detail badge bindings carry `forms: [{kind,value}]`.
  `POST /v1/admin/badges/read {number|uid|facility,card}` (any signed-in
  principal) → `{format, stored:{kind:value}, wiegand26?, facility?, card?,
  value24?}`: how a reading is understood, nothing stored (v0.8.2).
- Agents (v0.7.0, SPEC-agents). A principal of kind `agent` with an owner
  (`attributes.owner_id`, a person). Check ANDs the agent's decision with the
  owner's; a denial for that reason is `owner.denied` with the owner's own
  reason in `params.reason`, and Why carries the owner's leg as `owner`.
  An agent's assurance is its credential's, capped at the strongest its
  owner has enrolled. Routes admit an admin or the agent's owner:
  `POST /v1/admin/agents {username, display_name, owner?}` (non-admins own
  what they create), `GET /v1/admin/agents[?owner=]` (non-admins see their
  own), `GET /v1/admin/agents/{id}` → row + `grants` + `grantable` (the
  owner's held rights), `POST|DELETE /v1/admin/agents/{id}/token` (issue or
  rotate, shown once / revoke), `POST /v1/admin/agents/{id}/state`,
  `POST /v1/admin/agents/{id}/grants {role, resource_type, resource_id,
  condition?, expires_at?}` (owners only for rights they hold:
  `agent.grant_not_held`), `DELETE /v1/admin/agents/{id}/grants/{gid}`.
  People rows of kind `agent` carry `owner {id,name}`; audit rows by an
  agent carry `actor.owner_id` and `actor.owner_name`. A bearer principal
  may read its own `/v1/admin/users/{id}`.
  Who may have agents (v0.7.1): the permission `agents.own` on
  `directory:root`, bundled in the built-in role `agent-owner`, granted to
  the built-in group `agent-owners`, which starts empty. Creating an agent,
  issuing its token and handing it a right need it (`agent.not_allowed`
  otherwise); listing, revoking and suspending stay open to the owner. An
  owner without it stops every agent they own: Check denies with
  `owner.denied` / `params.reason = agent.not_allowed`. Admins (role
  `admin`, `*`) always have it. The session's `permissions` include
  `agents.own`, which is what shows the Agents panel.
- MCP (v0.7.0, SPEC-agents): `POST /mcp` speaks MCP over streamable HTTP
  with JSON responses (no server stream yet; `GET /mcp` is 405). The bearer
  token is the caller's identity, an agent's typically. `initialize`,
  `ping`, `tools/list`, `tools/call`, `resources/list`, `resources/read`
  (`rostor://me`, `rostor://catalog`). Every tool is one API call
  dispatched through the same router under that credential, so it meets
  the same Check, attenuation and audit; each call also writes `mcp.call`
  (target `tool:<name>`, outcome ok/deny/error). Tool descriptions are
  catalog strings `mcp.tool.<name>`.
- Audit default view (v0.6.0): rows whose actor kind is `system` or `device`
  are omitted unless `include_system=1`; the console's "Show system activity"
  tick sets it.
- Audit rows (v0.3.0): `actor.name` and `target.name` are present when the
  actor/target is a known principal, group or device; `detail.principal_name`
  accompanies `detail.principal_id`. Lead with names; show IDs on demand.
- Sign-in default (v0.4.0): `GET /v1/auth/setup` also returns
  `default_method` (`password|passkey|badge`) so the sign-in page opens on it
  (badge mode focuses the reader field). Set via `login.default_method` in
  `PUT /v1/admin/settings/auth` (also echoed by GET under `login`).

## Certificates and trust (v0.5.0)

Device side (mutual TLS):
- `GET /v1/devices/self/trust` → `{"version","ca_pems":[…],"renew":bool,"cert_not_after"}`.
  The deputy replaces its pinned `ca.crt` with all `ca_pems` when `version`
  changes, and renews when `renew` is true (expiry within 30 days, issuing CA
  no longer newest, or presenting a superseded certificate).
- `POST /v1/devices/self/renew` `{"csr_pem"}` → `{"certificate_pem","not_after","ca_pems","trust_version"}`.
  The previous certificate stays valid for 24 h so a lost reply never locks
  the device out. Device certificates now live 90 days.

Admin:
- `GET /v1/admin/ca` → `{"items":[{id,subject,not_after,created_at,retired_at?,newest,devices,fingerprint}],"trust_version","devices":{"total","on_older_bundle"}}`.
- `POST /v1/admin/ca/rotate` → 201 the new CA (typed confirmation in the console).
- `POST /v1/admin/ca/{id}/retire` `{"force":bool}` → 204; `ca.in_use` (400, params.devices) unless forced; `ca.last_active` (400).
- Device rows: `cert_not_after` (existing), plus `ca_key_id`, `trust_version`, `cert_renewed_at` on `GET /v1/admin/devices` (v0.5.0).

## Downloads (v0.5.0)

- `GET /v1/admin/downloads` → `{"windows":{name,version,cached,size?,fetched_at?}}`.
- `GET /v1/admin/downloads/windows` → the `rostor-windows-amd64.zip` for the
  running version as an attachment (fetched from the release and cached on
  first request; prefetched after start). `download.unavailable` (502) when
  the release host cannot be reached and nothing is cached. The console's
  Devices screen offers the link next to a ready command:
  `powershell -ExecutionPolicy Bypass -File .\install.ps1 -CoreUrl <https://host:8443> -Token <enr_…>`
  where the token comes from `POST /v1/admin/enrollment-tokens` and the core
  URL is the devices endpoint (`GET /v1/admin/system` gains `device_url`).
