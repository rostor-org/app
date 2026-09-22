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
| `GET /v1/admin/audit?limit=&before=<seq>&q=` | `{"items":[{seq,ts,actor:{kind,id},action,target:{type,id},credential_type,assurance,outcome,detail}],"head":{seq}}` |
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
