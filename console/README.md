# Rostor console

React + TypeScript single-page admin console, embedded into the `rostor`
binary. It is a client of the API in `../docs/contracts/console-api.md` and
nothing else: no endpoint is called that the contract does not list.

## Develop

```sh
npm ci
npm run dev          # http://localhost:5173, proxies /v1 to http://localhost:8080
npm run dev:mock     # same, but served from the in-memory mock (no backend)
```

Mock mode is `VITE_MOCK=1` at build/dev time or `?mock=1` on any URL
(sticky for the tab; `?mock=0` clears it). The mock implements the same
`Api` interface as the HTTP client (`src/api/types.ts`), with the mockup's
data, a fake event stream that appends an audit row every few seconds, and
the update check/install flow. Everyone's password is `demo` until they change
it. Admin rights come from the `directory-admins` group: `dan` is in it
(full rail); `maria` is on the `board`, which holds the read-only `auditor`
role (rail, read-mostly); `dana` and `priya` are plain members and see only
My account with the minimal top bar; `sam` is suspended. Group nesting:
`board` and `staff` are members of `members`, so those show as inherited
("via") chips. Badge sign-in: `0004A211` (priya, no PIN), `0004A1F3` (dana,
PIN `1234`, so the mock answers `auth.continue` first), `0004A1D9` (sam,
suspended). "Use a passkey" signs in as `dan`; passkey ceremonies resolve at
once without touching `navigator.credentials` (see `src/auth/webauthn.ts`).
First-administrator setup is offered on the sign-in page until it has been
done in the tab; the bootstrap token is `rostor-bootstrap`. Writes (add
person, set/change/reset password, set/remove PIN, register badge, add
passkey, groups, members, grants, enrollment tokens, sign-in settings,
update check) mutate the in-memory data and emit the matching events;
audit rows carry names beside ids as the server does.

## Build

```sh
npm ci
npm run build        # typecheck, then vite build → dist/ (index.html + hashed assets, relative paths)
npm run typecheck
npm run strings      # every ui.* code used in src/ must exist in catalog.en.json
```

`dist/` is ignored by git; the Makefile copies it to `internal/console/dist`
for embedding. The app is served at the root (`base: '/'`) with history
routing; the Go server falls back to `index.html` for unknown paths so deep
links work. Build with `VITE_ROUTER=hash` for a host that cannot rewrite.

## Where strings live

Components contain no user-facing string literals. Every label is a
catalog code rendered through `useT()` (`src/i18n/catalog.tsx`), which loads
`GET /v1/catalog?locale=<navigator.language>` on boot; unknown codes render
as the code so gaps are visible. `catalog.en.json` at the root of this
folder is the English source for every `ui.*` code the console uses and is
merged into the server catalog (`internal/catalog/en.json`). Reason codes in
Why chains and login errors use the server's rendered `message` and fall
back to the same catalog.

## Layout

- `src/api/` — contract types, HTTP client (fetch + SSE reader with
  `Last-Event-ID` and backoff), mock, and the `VITE_MOCK` switch.
- `src/auth/` — session query, `can(action)` from the session's permissions.
- `src/live/` — event stream → TanStack Query invalidations by event type.
- `src/components/` — shell (rail, nav, live indicator), drawer, pills,
  toast, Why chain.
- `src/screens/` — one file per route: MyAccount (the landing page for
  everyone), People, Groups, Access, Devices, Audit, Plugins, System, Login
  (with first-administrator setup). `components/PersonPanel.tsx` is the
  person record shared by My account and the People drawer;
  `components/AuditEvent.tsx` the name-first audit row.
- `src/styles.css` — tokens and rules from the approved mockup; dark by
  default whatever the OS prefers, light via `data-theme="light"`.
- `src/lib/theme.ts` — the viewer's dark/light choice (System → Appearance),
  kept per browser in localStorage and applied before first render, so it
  also covers the sign-in screen. Not a tenant setting.
