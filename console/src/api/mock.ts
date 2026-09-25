// In-memory implementation of the console API for development without the
// backend (VITE_MOCK=1 or ?mock=1). Data mirrors the approved mockup.
import type { LoginMethod,
  Api, AuditRow, AuthSettings, CA, CAList, Device, Downloads, Explanation, Grant, Group, GroupDetail, LiveEvent, LiveHandlers, LoginOK, LoginResponse,
  LiveState, Member, Plugin, Role, Session, Summary, SystemInfo, UpdateState, User, UserDetail, Binding, Reason, ResourceNode, Agent, AgentDetail, HeldRight,
} from './types'
import catalogEn from '../../catalog.en.json'

const SESSION_KEY = 'rostor-console-mock-session'
const SETUP_KEY = 'rostor-console-mock-setup-done'
/** The bootstrap token the mock accepts for first-administrator setup. */
const BOOTSTRAP_TOKEN = 'rostor-bootstrap'
/** Every mock person signs in with this password until they change it. */
const DEFAULT_PASSWORD = 'demo'

const now = Date.now()
const min = 60_000, hour = 3_600_000, day = 86_400_000
const today = (h: number, m: number, s = 0) => { const d = new Date(now); d.setHours(h, m, s, 0); return d.toISOString() }
const daysAgo = (n: number, h: number, m: number) => { const d = new Date(now - n * day); d.setHours(h, m, 0, 0); return d.toISOString() }
const iso = (t: number) => new Date(t).toISOString()

const groupRefs = {
  admins: { id: 'grp_admins', name: 'directory-admins' },
  agentOwners: { id: 'grp_agent_owners', name: 'agent-owners' },
  members: { id: 'grp_members', name: 'members' },
  board: { id: 'grp_board', name: 'board' },
  laser: { id: 'grp_laser', name: 'laser-certified' },
  staff: { id: 'grp_staff', name: 'staff' },
  guests: { id: 'grp_guests_a', name: 'guests-from-a' },
}

// Group nesting: a member of `board` or `staff` is a member of `members` too.
// `u.groups` holds direct memberships; effectiveGroups() expands them.
const nested: Record<string, Array<{ id: string; name: string }>> = {
  grp_board: [groupRefs.members],
  grp_staff: [groupRefs.members],
}
function effectiveGroups(u: User): Array<{ id: string; name: string; direct: boolean }> {
  const out: Array<{ id: string; name: string; direct: boolean }> = u.groups.map((g) => ({ ...g, direct: true }))
  const seen = new Set(out.map((g) => g.id))
  const queue = [...u.groups]
  while (queue.length) {
    const g = queue.shift()!
    for (const parent of nested[g.id] ?? []) {
      if (seen.has(parent.id)) continue
      seen.add(parent.id); out.push({ ...parent, direct: false }); queue.push(parent)
    }
  }
  return out
}
const inGroup = (u: User, name: string) => effectiveGroups(u).some((g) => g.name === name)

const users: User[] = [
  { id: 'usr_f40101ae', kind: 'user', username: 'dan', display_name: 'Dan Evans', state: 'active',
    groups: [groupRefs.admins, groupRefs.board], methods: [{ method: 'password', assurance: 'AL1' }],
    last_sign_in: { ts: today(13, 59), resource: 'workstation:DESKTOP-UPJD27E' } },
  { id: 'usr_9b2c11d0', kind: 'user', username: 'dana', display_name: 'Dana Whitfield', state: 'active',
    groups: [groupRefs.staff, groupRefs.laser], methods: [{ method: 'badge', assurance: 'AL1' }, { method: 'password', assurance: 'AL1' }],
    last_sign_in: { ts: daysAgo(1, 19, 12), resource: 'door:exterior-alley' } },
  { id: 'usr_2d8e6f10', kind: 'user', username: 'maria', display_name: 'Maria Castellanos', state: 'active',
    groups: [groupRefs.board], methods: [{ method: 'password', assurance: 'AL1' }],
    last_sign_in: { ts: daysAgo(3, 9, 14), resource: 'workstation:DESKTOP-UPJD27E' } },
  { id: 'usr_41aa72ef', kind: 'user', username: 'sam', display_name: 'Sam Okafor', state: 'suspended',
    groups: [groupRefs.members], methods: [{ method: 'badge', assurance: 'AL1' }],
    last_sign_in: { ts: daysAgo(8, 10, 5), resource: 'door:exterior-alley' } },
  { id: 'usr_c0de5a19', kind: 'user', username: 'priya', display_name: 'Priya Raman', state: 'active',
    groups: [groupRefs.guests], methods: [{ method: 'badge', assurance: 'AL1' }],
    last_sign_in: { ts: daysAgo(2, 16, 40), resource: 'door:interior-hallway' } },
  { id: 'usr_77f1b3c2', kind: 'user', username: 'jo', display_name: 'Jo Lindqvist', state: 'applicant',
    groups: [], methods: [], last_sign_in: null },
  { id: 'svc_3e9a0c44', kind: 'service', username: 'frontdesk-agent', display_name: 'Front-desk agent', state: 'active',
    groups: [], methods: [{ method: 'api_token', assurance: 'AL1' }],
    last_sign_in: { ts: today(14, 20), resource: 'api' } },
]

const bindings: Record<string, Binding[]> = {
  usr_f40101ae: [{ id: 'bnd_01', method: 'password', properties: ['knowledge'], label: 'Password', assurance: 'AL1', created_at: today(9, 2), last_used_at: today(13, 59), state: 'active' }],
  usr_9b2c11d0: [
    { id: 'bnd_02', method: 'badge', properties: ['possession', 'knowledge', 'multi_factor'], label: 'Badge 0004A1F3', assurance: 'AL2', created_at: daysAgo(40, 11, 0), last_used_at: daysAgo(1, 19, 12), state: 'active' },
    { id: 'bnd_03', method: 'password', properties: ['knowledge'], label: 'Password', assurance: 'AL1', created_at: daysAgo(40, 11, 5), last_used_at: daysAgo(3, 8, 30), state: 'active' },
  ],
  usr_2d8e6f10: [{ id: 'bnd_07', method: 'password', properties: ['knowledge'], label: 'Password', assurance: 'AL1', created_at: daysAgo(60, 10, 0), last_used_at: daysAgo(3, 9, 14), state: 'active' }],
  usr_41aa72ef: [{ id: 'bnd_04', method: 'badge', properties: ['possession'], label: 'Badge 0004A1D9', assurance: 'AL1', created_at: daysAgo(90, 12, 0), last_used_at: daysAgo(8, 10, 5), state: 'active' }],
  usr_c0de5a19: [{ id: 'bnd_05', method: 'badge', properties: ['possession'], label: 'Badge 0004A211', assurance: 'AL1', created_at: daysAgo(12, 12, 0), last_used_at: daysAgo(2, 16, 40), state: 'active' }],
  usr_77f1b3c2: [],
  svc_3e9a0c44: [{ id: 'bnd_06', method: 'api_token', properties: ['possession'], label: 'API token', assurance: 'AL1', created_at: daysAgo(5, 9, 0), last_used_at: today(14, 20), state: 'active' }],
}

// Card number (as a reader types it) → binding. Dana's card has a PIN, so
// badge sign-in without one answers auth.continue, like the server.
const badges: Record<string, { user: string; binding: string; pin?: string }> = {
  '0004A1F3': { user: 'usr_9b2c11d0', binding: 'bnd_02', pin: '1234' },
  '0004A1D9': { user: 'usr_41aa72ef', binding: 'bnd_04' },
  '0004A211': { user: 'usr_c0de5a19', binding: 'bnd_05' },
}

// Passwords, by principal id. Everyone starts with the demo password.
const passwords: Record<string, string> = {}
const passwordOf = (id: string) => passwords[id] ?? DEFAULT_PASSWORD

// Tenant sign-in settings (the tenant-wide auth policy). enrolled_passkeys is
// derived from the bindings.
let webauthn = { rp_id: 'localhost', display_name: 'ChattLab', origins: ['https://localhost:5173'] }
let defaultMethod: LoginMethod = 'password'
const enrolledPasskeys = () => Object.values(bindings).flat().filter((b) => b.method === 'webauthn' && b.state === 'active').length
const authSettings = (): AuthSettings => ({ webauthn: { ...webauthn, origins: [...webauthn.origins], enrolled_passkeys: enrolledPasskeys() }, login: { default_method: defaultMethod } })

// Pending passkey ceremonies: id → the principal it was begun for ('' = discoverable).
const ceremonies = new Map<string, string>()
const b64url = (n: number) => { const a = crypto.getRandomValues(new Uint8Array(n)); let s = ''; for (const b of a) s += String.fromCharCode(b); return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '') }

const groups: Group[] = [
  { id: 'grp_admins', name: 'directory-admins', display_name: 'Administrators of this directory (built-in)', kind: 'static', member_count: 1, grant_count: 1 },
  { id: 'grp_agent_owners', name: 'agent-owners', display_name: 'May own agents (built-in)', kind: 'static', member_count: 0, grant_count: 1 },
  { id: 'grp_members', name: 'members', display_name: 'Current dues-paying members', kind: 'static', member_count: 124, grant_count: 3 },
  { id: 'grp_board', name: 'board', display_name: 'Elected board, electorate for admissions', kind: 'static', member_count: 5, grant_count: 1 },
  { id: 'grp_laser', name: 'laser-certified', display_name: 'Completed laser training', kind: 'dynamic', member_count: 41, grant_count: 1 },
  { id: 'grp_staff', name: 'staff', display_name: 'Keyholders; stays in door snapshots when degraded', kind: 'static', member_count: 7, grant_count: 2 },
  { id: 'grp_guests_a', name: 'guests-from-a', display_name: 'Mastered by partner-sync: Makerspace A', kind: 'synced', member_count: 12, grant_count: 1 },
]

const grants: Grant[] = [
  { id: 'grt_338b6e29', subject: { kind: 'group', id: 'grp_members', name: 'members' }, role: 'user', resource: { type: 'workstations', id: 'all' }, condition: '', condition_class: 'offline', not_before: null, expires_at: null },
  { id: 'grt_9a01c3d4', subject: { kind: 'group', id: 'grp_members', name: 'members' }, role: 'enter', resource: { type: 'door', id: 'exterior-alley' }, condition: 'now.hour >= 7 && now.hour < 23', condition_class: 'offline', not_before: null, expires_at: null },
  { id: 'grt_5be7720a', subject: { kind: 'group', id: 'grp_staff', name: 'staff' }, role: 'enter', resource: { type: 'door', id: '*' }, condition: '', condition_class: 'offline', not_before: null, expires_at: null },
  { id: 'grt_e1f4a88b', subject: { kind: 'group', id: 'grp_laser', name: 'laser-certified' }, role: 'operate', resource: { type: 'equipment', id: 'laser-cutter-2' }, condition: 'assurance >= 1', condition_class: 'offline', not_before: null, expires_at: null },
  { id: 'grt_0c2d9e71', subject: { kind: 'group', id: 'grp_members', name: 'members' }, role: 'operate', resource: { type: 'equipment', id: 'cnc-mill' }, condition: 'assurance >= 2', condition_class: 'offline', not_before: null, expires_at: null },
  { id: 'grt_77aa1b02', subject: { kind: 'user', id: 'usr_9b2c11d0', name: 'dana' }, role: 'steward', resource: { type: 'equipment', id: 'laser-cutter-2' }, condition: '', condition_class: 'online', not_before: null, expires_at: '2026-12-31T00:00:00Z' },
  { id: 'grt_c4d5e6f7', subject: { kind: 'group', id: 'grp_admins', name: 'directory-admins' }, role: 'admin', resource: { type: 'directory', id: 'root' }, condition: '', condition_class: 'offline', not_before: null, expires_at: null },
  { id: 'grt_a0b1c2d3', subject: { kind: 'group', id: 'grp_agent_owners', name: 'agent-owners' }, role: 'agent-owner', resource: { type: 'directory', id: 'root' }, condition: '', condition_class: 'offline', not_before: null, expires_at: null },
  { id: 'grt_1a2b3c4d', subject: { kind: 'group', id: 'grp_board', name: 'board' }, role: 'auditor', resource: { type: 'directory', id: 'root' }, condition: '', condition_class: 'offline', not_before: null, expires_at: null },
]

// SPEC-agents: owned principals. dan owns one; the audit shows it acting for him.
const agents: Agent[] = [
  { id: 'agt_5e1f0c2a', username: 'inventory-bot', kind: 'agent', display_name: 'Inventory bot', state: 'active',
    owner: { id: 'usr_f40101ae', name: 'Dan Evans' }, token: { active: true, issued_at: iso(Date.now() - 2 * 24 * 3600 * 1000) }, grant_count: 0, created_at: iso(Date.now() - 3 * 24 * 3600 * 1000) },
]
/** The (resource, role) pairs a person holds directly or through groups. */
function heldBy(ownerId: string): HeldRight[] {
  const u = users.find((x) => x.id === ownerId)
  if (!u) return []
  const groupIds = new Set(u.groups.map((g) => g.id))
  const out: HeldRight[] = []
  for (const g of grants) {
    const mine = (g.subject.kind === 'principal' && g.subject.id === u.id) || (g.subject.kind === 'group' && groupIds.has(g.subject.id))
    if (mine && !out.some((h) => h.role === g.role && h.resource_type === g.resource.type && h.resource_id === g.resource.id)) {
      out.push({ resource_type: g.resource.type, resource_id: g.resource.id, role: g.role, via: g.subject.kind === 'group' ? `group:${g.subject.name}` : 'direct' })
    }
  }
  return out
}

const roles: Role[] = [
  { resource_type: 'directory', name: 'admin', permissions: ['*'] },
  { resource_type: 'directory', name: 'agent-owner', permissions: ['agents.own'] },
  { resource_type: 'directory', name: 'auditor', permissions: ['users.read', 'groups.read', 'grants.read', 'audit.read', 'authz.read', 'updates.read'] },
  { resource_type: 'door', name: 'enter', permissions: ['enter'] },
  { resource_type: 'workstations', name: 'user', permissions: ['logon'] },
  { resource_type: 'workstation', name: 'user', permissions: ['logon'] },
  { resource_type: 'equipment', name: 'operate', permissions: ['operate'] },
  { resource_type: 'equipment', name: 'steward', permissions: ['operate', 'certify'] },
]

// ---- certificates and trust (v0.5.0) ---------------------------------------
// Two CAs: the newest one from a rotation three days ago, and the original
// one that two devices still hold certificates from. The trust version is
// the bundle devices pin; a device on an older bundle has not checked in
// since the rotation.
const hex = (n: number) => { let s = ''; for (let i = 0; i < n; i++) s += Math.floor(Math.random() * 16).toString(16); return s }
const cas: CA[] = [
  { id: 'cak_7c1d9e2a', subject: 'Rostor CA (chattlab) 2026-09', not_after: iso(now + 3650 * day), created_at: iso(now - 3 * day), newest: true, devices: 0, fingerprint: 'a7c1d9e24f0b8d3e6c5a2b1f9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d' },
  { id: 'cak_3f0a5b7e', subject: 'Rostor CA (chattlab)', not_after: '2036-09-22T00:00:00Z', created_at: iso(now - 400 * day), newest: false, devices: 0, fingerprint: '3f0a5b7e9c2d4e6f8a1b3c5d7e9f0a2b4c6d8e0f1a3b5c7d9e1f2a4b6c8d0e2f' },
]
let trustVersion = 'tv_0002'
const OLD_TRUST = 'tv_0001'
const caList = (): CAList => {
  for (const ca of cas) ca.devices = devices.filter((d) => d.ca_key_id === ca.id).length
  const enrolled = devices.filter((d) => d.lifecycle === 'trusted' || d.lifecycle === 'enrolled')
  return { items: clone(cas), trust_version: trustVersion, devices: { total: enrolled.length, on_older_bundle: enrolled.filter((d) => d.trust_version !== trustVersion).length } }
}
/** Devices renew onto the newest CA one at a time, as the agents would on their next check-in. */
function renewOnto(caId: string, from?: string) {
  const due = devices.filter((d) => d.ca_key_id !== caId && (!from || d.ca_key_id === from))
  due.forEach((d, i) => setTimeout(() => {
    d.ca_key_id = caId; d.trust_version = trustVersion; d.cert_renewed_at = iso(Date.now()); d.cert_not_after = iso(Date.now() + 90 * day)
    append(`device:${d.id}`, 'device.renew', `device:${d.id}`, 'mtls', '', 'ok', { ca: caId, not_after: d.cert_not_after })
    emit('device.renewed')
  }, 2500 + i * 2000))
}

const devices: Device[] = [
  { id: 'dev_12ce4c4b9f0a', display_name: 'DESKTOP-UPJD27E', resource: { type: 'workstation', id: 'DESKTOP-UPJD27E' }, lifecycle: 'trusted', last_seen_at: iso(now - 1 * min),
    posture: { os: 'Windows 10.0.19045', agent: '0.1.0', via: 'heartbeat' }, cert_not_after: iso(now + 87 * day), ca_key_id: 'cak_7c1d9e2a', trust_version: trustVersion, cert_renewed_at: iso(now - 3 * day) },
  { id: 'dev_a91c0b3e7d21', display_name: 'Front door controller', resource: { type: 'door', id: 'front' }, lifecycle: 'trusted', last_seen_at: iso(now - 3 * min),
    posture: { model: 'WG2004', snapshot: 'v418', doors_wired: '2 of 4', cards: 432, managed: 124 }, cert_not_after: iso(now + 21 * day), ca_key_id: 'cak_3f0a5b7e', trust_version: OLD_TRUST, cert_renewed_at: null },
  { id: 'dev_77e0f5a2c318', display_name: 'Laser interlock', resource: { type: 'interlock', id: 'laser-cutter-2' }, lifecycle: 'degraded', last_seen_at: iso(now - 26 * hour),
    posture: { model: 'ESP32', snapshot: 'v402', ladder: 'staff-only' }, cert_not_after: iso(now + 60 * day), ca_key_id: 'cak_3f0a5b7e', trust_version: trustVersion, cert_renewed_at: iso(now - 30 * day) },
]

// ---- downloads (v0.5.0) ------------------------------------------------------
// The bundle is "not cached yet" until the first download; the console asks
// for the status again after a download, so the second status call reports it
// cached. An applied update starts over for the new version.
let downloadsAsked = 0
const WINDOWS_BUNDLE = 'rostor-windows-amd64.zip'
const downloads = (): Downloads => {
  const cached = downloadsAsked > 1
  return { windows: { name: WINDOWS_BUNDLE, version: system.version, cached, ...(cached ? { size: 24_117_248, fetched_at: iso(Date.now() - 5000) } : {}) } }
}
/** An empty zip (just the end-of-central-directory record): a link with `download` saves it like the real bundle. */
const FAKE_BUNDLE_URL = 'data:application/zip;base64,UEsFBgAAAAAAAAAAAAAAAAAAAAAAAA=='

let seq = 1184
const audit: AuditRow[] = [
  row(today(14, 31, 7), 'device:dev_12ce4c4b9f0a', 'verify', 'workstation:DESKTOP-UPJD27E', 'password', 'AL1', 'allow', { identifier: 'dan', principal_id: 'usr_f40101ae' }),
  row(today(14, 20, 41), 'service:svc_3e9a0c44', 'grant.create', 'grant:grt_0c2d9e71', 'api_token', 'AL1', 'ok', { subject: 'members', role: 'operate', resource: 'equipment:cnc-mill' }),
  row(today(14, 20, 39), 'service:svc_3e9a0c44', 'binding.enroll', 'principal:usr_77f1b3c2', 'api_token', 'AL1', 'ok', { method: 'badge', label: '0004A1F7', identifier: 'jo' }),
  row(today(13, 59, 35), 'device:dev_12ce4c4b9f0a', 'verify', 'workstation:DESKTOP-UPJD27E', 'password', 'AL1', 'allow', { identifier: 'dan', principal_id: 'usr_f40101ae' }),
  row(today(13, 49, 7), 'device:dev_12ce4c4b9f0a', 'verify', 'workstation:DESKTOP-UPJD27E', 'password', '', 'deny', { identifier: 'dan', reason: 'auth.failed' }),
  row(today(13, 24, 14), 'service:svc_3e9a0c44', 'principal.state', 'principal:usr_f40101ae', 'api_token', 'AL1', 'ok', { from: 'active', to: 'suspended', identifier: 'dan' }),
  row(today(13, 20, 2), 'user:usr_f40101ae', 'group.member_add', 'group:grp_laser', 'session', 'AL1', 'ok', { member: 'dana' }),
  row(today(13, 24, 14), 'device:dev_12ce4c4b9f0a', 'verify', 'workstation:DESKTOP-UPJD27E', 'password', '', 'deny', { identifier: 'dan', reason: 'principal.suspended' }),
  row(today(12, 16, 26), 'system:enroll', 'device.enroll', 'device:dev_12ce4c4b9f0a', 'enrollment_token', '', 'ok', { display_name: 'DESKTOP-UPJD27E' }),
].reverse().map((r, i) => ({ ...r, seq: seq - 8 + i })).reverse()

function ref(s: string): [string, string] { const i = s.indexOf(':'); return i < 0 ? [s, ''] : [s.slice(0, i), s.slice(i + 1)] }
function row(ts: string, actor: string, action: string, target: string, credential_type: string, assurance: string, outcome: string, detail: Record<string, unknown>): AuditRow {
  const [ak, aid] = ref(actor)
  const [tt, tid] = ref(target)
  return { seq: 0, ts, actor: { kind: ak, id: aid }, action, target: { type: tt, id: tid }, credential_type, assurance, outcome, detail, correlation_id: 'cor_' + Math.random().toString(16).slice(2, 10) }
}

// Like the server's nameAudit: names for principals, groups and devices sit
// beside the ids, and detail.principal_id gets a detail.principal_name.
function nameOf(kind: string, id: string): string | undefined {
  switch (kind) {
    case 'principal': case 'user': case 'service': { const u = users.find((x) => x.id === id); return u ? String(u.display_name || u.username) : undefined }
    case 'group': return groups.find((g) => g.id === id)?.name
    case 'device': return devices.find((d) => d.id === id)?.display_name
    default: return undefined
  }
}
function named(r: AuditRow): AuditRow {
  const out = clone(r)
  const an = nameOf(out.actor.kind, out.actor.id); if (an) out.actor.name = an
  const tn = nameOf(out.target.type, out.target.id); if (tn) out.target.name = tn
  const pid = out.detail?.principal_id
  if (typeof pid === 'string') { const n = nameOf('principal', pid); if (n && out.detail) out.detail.principal_name = n }
  return out
}

function append(actor: string, action: string, target: string, credential_type: string, assurance: string, outcome: string, detail: Record<string, unknown>) {
  seq++
  audit.unshift({ ...row(iso(Date.now()), actor, action, target, credential_type, assurance, outcome, detail), seq })
  emit('audit.appended')
}

let updateState: UpdateState = { channel: 'stable', current: 'v0.1.0', checked_at: today(14, 32), apply_requested: false, notes: 'First appliance release.' }
let updateChecks = 0
const UPDATE_NOTES = 'Console: passkeys, badges, sign-in settings; agent: badge+PIN.'

const system: SystemInfo = {
  version: 'v0.1.0', tenant: { id: 'tnt_chattlab', name: 'ChattLab' },
  db: { size_bytes: 18_874_368, engine: 'PostgreSQL 15' }, uptime_seconds: 2 * 3600 + 6 * 60,
  ca: { subject: 'Rostor CA (chattlab)', not_after: '2036-09-22T00:00:00Z' },
  release_key_fingerprint: 'f63294b2c1a04e9d7b3f5a6c8d2e1f0a4b76', profile: 'standard',
  device_url: 'https://rostor.chattlab.org:8443',
}

const plugins: Plugin[] = []

// ---- live -----------------------------------------------------------------
const listeners = new Set<LiveHandlers>()
let eventId = 5000
function emit(type: string) {
  const e: LiveEvent = { id: String(++eventId), type }
  for (const l of listeners) l.onEvent(e)
}
let ticker: ReturnType<typeof setInterval> | null = null
function ensureTicker() {
  if (ticker) return
  ticker = setInterval(() => {
    if (listeners.size === 0 || Math.random() < 0.5) return
    const who = (['dana', 'priya', 'maria', 'sam'] as const)[Math.floor(Math.random() * 4)] ?? 'dana'
    const u = byId(who)
    append('device:dev_a91c0b3e7d21', 'verify', 'door:exterior-alley', 'badge', 'AL1', 'allow', u ? { identifier: who, principal_id: u.id } : { identifier: who })
  }, 4000)
}

// ---- session --------------------------------------------------------------
function loadSession(): Session | null {
  try { const s = sessionStorage.getItem(SESSION_KEY); return s ? (JSON.parse(s) as Session) : null } catch { return null }
}
function saveSession(s: Session | null) {
  try { s ? sessionStorage.setItem(SESSION_KEY, JSON.stringify(s)) : sessionStorage.removeItem(SESSION_KEY) } catch { /* ignore */ }
}
let session: Session | null = loadSession()
let failedAttempts = 0
// First-administrator setup stays offered until it has been done in this tab.
let setupDone = (() => { try { return sessionStorage.getItem(SETUP_KEY) === '1' } catch { return false } })()

const delay = (ms = 120) => new Promise<void>((r) => setTimeout(r, ms))
const clone = <T,>(v: T): T => JSON.parse(JSON.stringify(v)) as T
const byId = (id: string) => users.find((u) => u.id === id || u.username === id)

function filter<T>(items: T[], q: string | undefined, pick: (t: T) => string): T[] {
  if (!q) return items
  const s = q.toLowerCase()
  return items.filter((t) => pick(t).toLowerCase().includes(s))
}

function summary(): Summary {
  return {
    people: { active: 124, suspended: users.filter((u) => u.state === 'suspended').length, applicants: users.filter((u) => u.state === 'applicant').length,
      service_accounts: users.filter((u) => u.kind === 'service').length },
    groups: groups.length, grants: grants.length,
    devices: { trusted: devices.filter((d) => d.lifecycle === 'trusted').length, quarantined: 0, degraded: devices.filter((d) => d.lifecycle === 'degraded').length },
    offline_points: 2,
    oldest_snapshot_age_seconds: 2 * 3600 + 4 * 60,
  }
}

function why(principal: string, action: string, rtype: string, rid: string): Explanation {
  const u = byId(principal)
  const as_of = iso(Date.now())
  const resource = `${rtype}:${rid}`
  if (!u) return { decision: 'DENY', reason: [{ code: 'principal.not_found', params: {} }], as_of, principal, action, resource, groups: {}, candidates: [] }
  const eff = effectiveGroups(u)
  const memberOf = Object.fromEntries(eff.map((g) => [g.name, g.direct ? [u.username, g.name] : [u.username, ...u.groups.filter((d) => (nested[d.id] ?? []).some((p) => p.id === g.id)).map((d) => d.name), g.name]]))
  const cands = grants.filter((g) => g.subject.kind === 'group' ? eff.some((m) => m.name === g.subject.name) : g.subject.id === u.id)
    .filter((g) => g.role === action || (action === 'logon' && g.role === 'user'))
    .filter((g) => g.resource.type === rtype || (g.resource.type === 'workstations' && rtype === 'workstation'))
  const toCand = (g: Grant, matched: boolean, condition_result?: string) => ({
    grant: { id: g.id, subject_kind: g.subject.kind, subject_id: g.subject.id, role: g.role, resource_type: g.resource.type, resource_id: g.resource.id, condition: g.condition, condition_class: g.condition_class, not_before: g.not_before, expires_at: g.expires_at },
    via: g.subject.kind === 'group' ? g.subject.name : 'direct', matched, ...(condition_result ? { condition_result } : {}),
  })
  if (u.state !== 'active') {
    return { decision: 'DENY', reason: [{ code: 'principal.suspended', params: {} }], as_of, principal: u.username, action, resource, groups: memberOf, candidates: cands.map((g) => toCand(g, false)) }
  }
  if (cands.length === 0) {
    return { decision: 'DENY', reason: [{ code: 'grant.none', params: { resource_type: rtype } }], as_of, principal: u.username, action, resource, groups: memberOf, candidates: [] }
  }
  const first = cands[0]!
  if (first.condition.startsWith('assurance >= 2')) {
    return { decision: 'DENY', reason: [{ code: 'grant.condition_failed', params: { condition: first.condition, presented: 'AL1' } }], as_of, principal: u.username, action, resource, groups: memberOf,
      candidates: cands.map((g, i) => toCand(g, false, i === 0 ? 'false' : undefined)) }
  }
  const reasons: Reason[] = [{ code: 'grant.matched', params: { role: first.role, via: first.subject.name } }]
  return { decision: 'ALLOW', reason: reasons, grant_id: first.id, as_of, principal: u.username, action, resource, groups: memberOf,
    candidates: cands.map((g, i) => toCand(g, i === 0, g.condition ? 'true' : undefined)) }
}

export function createMockApi(_opts: { onUnauthorized?: () => void } = {}): Api {
  return {
    async catalog(locale) { await delay(30); return { locale, strings: { ...serverCodes, ...(catalogEn as Record<string, string>) } } },
    async brand() { await delay(20); return { tenant_name: 'ChattLab', tokens: { ink: '#14161a', paper: '#f4f2ee', signal: '#e07a24' } } },
    async login(req) {
      await delay(400)
      if (failedAttempts >= 5) return { code: 'auth.locked', params: { minutes: 15 }, message: 'Too many failed attempts. Try again in 15 minutes.' }
      if (req.method === 'badge') {
        const card = badges[req.fields.number.trim().toUpperCase()]
        const u = card && byId(card.user)
        if (!u) { failedAttempts++; return { code: 'auth.failed', params: {}, message: 'Sign-in failed.' } }
        if (card.pin && !req.fields.pin) return { code: 'auth.continue', params: { need: 'pin' }, message: serverCodes['auth.continue'] ?? '' }
        if (card.pin && req.fields.pin !== card.pin) { failedAttempts++; return { code: 'auth.failed', params: {}, message: 'Sign-in failed.' } }
        return signIn(u, 'badge', card.pin ? 'AL2' : 'AL1')
      }
      const u = users.find((x) => x.username === req.identifier)
      if (!u || req.fields.password !== passwordOf(u.id)) { failedAttempts++; return { code: 'auth.failed', params: {}, message: 'Sign-in failed.' } }
      return signIn(u, 'password', 'AL1')
    },
    async session() { await delay(60); return session ? clone(session) : null },
    async logout() { await delay(60); session = null; saveSession(null) },
    async setupStatus() { await delay(40); return { needed: !setupDone, default_method: defaultMethod } },
    async setup(body) {
      await delay(400)
      if (setupDone) throw mockErr(400, 'setup.already_done')
      if (body.bootstrap_token.trim() !== BOOTSTRAP_TOKEN) throw mockErr(401, 'setup.token_invalid')
      const username = body.username.trim()
      if (!username) throw mockErr(400, 'request.malformed', { field: 'username' })
      if (users.some((u) => u.username === username)) throw mockErr(409, 'request.conflict', { field: 'username' })
      if (body.password.length < 8) throw mockErr(400, 'request.malformed', { field: 'password' })
      const u: User = { id: 'usr_' + Math.random().toString(16).slice(2, 10), kind: 'user', username, display_name: body.display_name.trim() || username,
        state: 'active', groups: [groupRefs.admins], methods: [{ method: 'password', assurance: 'AL1' }], last_sign_in: null }
      users.push(u)
      passwords[u.id] = body.password
      bindings[u.id] = [{ id: 'bnd_' + Math.random().toString(16).slice(2, 8), method: 'password', properties: ['knowledge'], label: 'Password', assurance: 'AL1', created_at: iso(Date.now()), last_used_at: null, state: 'active' }]
      const g = groups.find((x) => x.id === groupRefs.admins.id); if (g) g.member_count++
      setupDone = true
      try { sessionStorage.setItem(SETUP_KEY, '1') } catch { /* ignore */ }
      append('service:svc_bootstrap', 'setup.first_admin', `principal:${u.id}`, 'api_token', 'AL1', 'ok', { identifier: username })
      emit('user.created')
      const r = signIn(u, 'password', 'AL1')
      if ('code' in r) throw mockErr(400, r.code, r.params)
      return r
    },

    async passkeyRegisterBegin() {
      await delay(150)
      if (!session) throw mockErr(401, 'request.unauthorized')
      if (!webauthn.rp_id) throw mockErr(400, 'auth.passkeys_unconfigured', {})
      const id = 'cer_' + Math.random().toString(16).slice(2, 10)
      ceremonies.set(id, session.principal.id)
      const exclude = (bindings[session.principal.id] ?? []).filter((b) => b.method === 'webauthn').map(() => ({ type: 'public-key' as const, id: b64url(16) }))
      return { ceremony_id: id, options: { publicKey: {
        rp: { id: webauthn.rp_id, name: webauthn.display_name }, user: { id: b64url(16), name: session.principal.username ?? '', displayName: String(session.principal.display_name ?? '') },
        challenge: b64url(32), pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }], timeout: 60_000,
        authenticatorSelection: { residentKey: 'preferred', userVerification: 'preferred' }, excludeCredentials: exclude, attestation: 'none',
      } } }
    },
    async passkeyRegisterFinish(body) {
      await delay(250)
      const pid = ceremonies.get(body.ceremony_id)
      ceremonies.delete(body.ceremony_id)
      if (!session || pid !== session.principal.id) throw mockErr(400, 'auth.passkey_rejected', {})
      const u = byId(pid)!
      const b: Binding = { id: 'bnd_' + Math.random().toString(16).slice(2, 8), method: 'webauthn', properties: ['possession', 'phishing_resistant', 'multi_factor'],
        label: body.label || 'Passkey', assurance: 'AL2', created_at: iso(Date.now()), last_used_at: null, state: 'active' }
      bindings[u.id] = [...(bindings[u.id] ?? []), b]
      u.methods = (bindings[u.id] ?? []).map((x) => ({ method: x.method, assurance: x.assurance ?? 'AL1' }))
      append(`user:${u.id}`, 'binding.enroll', `principal:${u.id}`, 'session', 'AL1', 'ok', { method: 'webauthn', label: b.label, identifier: u.username })
      emit('user.updated')
      return clone(b)
    },
    async passkeyLoginBegin(body = {}) {
      await delay(150)
      if (!webauthn.rp_id) throw mockErr(400, 'auth.passkeys_unconfigured', {})
      const id = 'cer_' + Math.random().toString(16).slice(2, 10)
      const u = body.identifier ? users.find((x) => x.username === body.identifier) : undefined
      ceremonies.set(id, u?.id ?? '')
      const allow = u ? (bindings[u.id] ?? []).filter((b) => b.method === 'webauthn').map(() => ({ type: 'public-key' as const, id: b64url(16) })) : []
      return { ceremony_id: id, options: { publicKey: { rpId: webauthn.rp_id, challenge: b64url(32), timeout: 60_000, userVerification: 'preferred', allowCredentials: allow } } }
    },
    async passkeyLoginFinish(body) {
      await delay(300)
      if (!ceremonies.has(body.ceremony_id)) return { code: 'auth.failed', params: {}, message: 'Sign-in failed.' }
      const pid = ceremonies.get(body.ceremony_id) ?? ''
      ceremonies.delete(body.ceremony_id)
      // A discoverable assertion names the person through its user handle; the mock picks the admin.
      const u = byId(pid) ?? byId('dan')!
      return signIn(u, 'webauthn', 'AL2')
    },

    async summary() { await delay(); return summary() },
    async users(q) {
      await delay()
      const it = filter(users, q, (u) => `${u.display_name} ${u.username} ${effectiveGroups(u).map((g) => g.name).join(' ')}`)
      return { items: it.map((u) => ({ ...clone(u), groups: effectiveGroups(u).map(({ id, name }) => ({ id, name })) })), total: 130 }
    },
    async user(id) {
      await delay()
      const u = byId(id)
      if (!u) throw mockErr(404, 'request.not_found')
      const b = bindings[u.id] ?? []
      const recent = audit.filter((r) => r.actor.id === u.id || r.target.id === u.id || r.detail?.identifier === u.username || r.detail?.principal_id === u.id).slice(0, 6).map(named)
      const top = b.some((x) => x.assurance === 'AL2') ? 'AL2' : b.length ? 'AL1' : 'AL0'
      const d: UserDetail = { ...clone(u), groups: effectiveGroups(u), bindings: clone(b).map((x) => ({ ...x, assurance: x.assurance ?? 'AL1' })), effective_security: { assurance: top, bindings: b.length, recovery_paths: 0 }, recent: clone(recent) }
      return d
    },
    async createUser(body) {
      await delay(250)
      const username = body.username.trim()
      if (!username || users.some((u) => u.username === username)) throw mockErr(409, 'request.conflict', { field: 'username' })
      const u: User = { id: 'usr_' + Math.random().toString(16).slice(2, 10), kind: 'user', username, display_name: body.display_name['en'] || username,
        state: body.state ?? 'active', groups: [], methods: [], last_sign_in: null }
      users.push(u); bindings[u.id] = []
      append(`user:${session?.principal.id ?? ''}`, 'user.create', `principal:${u.id}`, 'session', 'AL1', 'ok', { identifier: username })
      emit('user.created')
      return { id: u.id, kind: 'user', username, display_name: u.display_name, state: u.state }
    },
    async enrollBinding(id, body) {
      await delay(250)
      const u = byId(id)
      if (!u) throw mockErr(404, 'request.not_found')
      if (body.method === 'password' && (body.fields['password'] ?? '').length < 8) throw mockErr(400, 'request.malformed', { field: 'password' })
      let b: Binding
      if (body.method === 'badge') {
        const number = (body.fields['number'] ?? body.fields['uid'] ?? body.fields['printed'] ?? '').trim().toUpperCase()
        const pin = body.fields['pin']
        if (!number) throw mockErr(400, 'request.malformed', { field: 'number' })
        if (badges[number]) throw mockErr(409, 'request.conflict', { field: 'number' })
        if (pin !== undefined && pin !== '' && !/^\d{4,}$/.test(pin)) throw mockErr(400, 'request.malformed', { field: 'pin' })
        b = { id: 'bnd_' + Math.random().toString(16).slice(2, 8), method: 'badge', properties: pin ? ['possession', 'knowledge', 'multi_factor'] : ['possession'],
          label: body.label || `Badge ${number}`, assurance: pin ? 'AL2' : 'AL1', created_at: iso(Date.now()), last_used_at: null, state: 'active' }
        badges[number] = { user: u.id, binding: b.id, ...(pin ? { pin } : {}) }
        bindings[u.id] = [...(bindings[u.id] ?? []), b]
      } else {
        b = { id: 'bnd_' + Math.random().toString(16).slice(2, 8), method: body.method, properties: ['knowledge'], label: body.label || 'Password',
          assurance: 'AL1', created_at: iso(Date.now()), last_used_at: null, state: 'active' }
        bindings[u.id] = [...(bindings[u.id] ?? []).filter((x) => x.method !== body.method), b]
      }
      u.methods = (bindings[u.id] ?? []).map((x) => ({ method: x.method, assurance: x.assurance ?? 'AL1' }))
      append(`user:${session?.principal.id ?? ''}`, 'binding.enroll', `principal:${u.id}`, 'session', 'AL1', 'ok', { method: body.method, label: b.label, identifier: u.username })
      emit('user.updated')
      return clone(b)
    },
    async setUserState(id, state) {
      await delay(200)
      const u = byId(id)
      if (!u) throw mockErr(404, 'request.not_found')
      const from = u.state
      u.state = state
      append(`user:${session?.principal.id ?? 'usr_f40101ae'}`, 'principal.state', `principal:${u.id}`, 'session', 'AL1', 'ok', { from, to: state, identifier: u.username })
      emit(state === 'suspended' ? 'user.suspended' : 'user.updated')
    },
    async revokeBinding(id, bid) {
      await delay(200)
      const u = byId(id)
      if (!u) throw mockErr(404, 'request.not_found')
      bindings[u.id] = (bindings[u.id] ?? []).filter((b) => b.id !== bid)
      for (const [n, c] of Object.entries(badges)) if (c.binding === bid) delete badges[n]
      u.methods = (bindings[u.id] ?? []).map((b) => ({ method: b.method, assurance: b.assurance ?? 'AL1' }))
      append(`user:${session?.principal.id ?? ''}`, 'binding.revoke', `principal:${u.id}`, 'session', 'AL1', 'ok', { binding: bid, identifier: u.username })
      emit('user.updated')
    },
    async changePassword(id, body) {
      await delay(300)
      const u = byId(id)
      if (!u) throw mockErr(404, 'request.not_found')
      const self = session?.principal.id === u.id
      if (self) {
        if (failedAttempts >= 5) throw mockErr(429, 'auth.locked', { minutes: 15 })
        if ((body.current ?? '') !== passwordOf(u.id)) { failedAttempts++; throw mockErr(401, 'auth.failed') }
      }
      if (body.new.length < 8) throw mockErr(400, 'request.malformed', { field: 'password' })
      failedAttempts = 0
      passwords[u.id] = body.new
      const b: Binding = { id: 'bnd_' + Math.random().toString(16).slice(2, 8), method: 'password', properties: ['knowledge'], label: 'Password', assurance: 'AL1', created_at: iso(Date.now()), last_used_at: null, state: 'active' }
      bindings[u.id] = [...(bindings[u.id] ?? []).filter((x) => x.method !== 'password'), b]
      u.methods = (bindings[u.id] ?? []).map((x) => ({ method: x.method, assurance: x.assurance ?? 'AL1' }))
      append(`user:${session?.principal.id ?? ''}`, self ? 'password.change' : 'password.reset', `principal:${u.id}`, 'session', 'AL1', 'ok', { identifier: u.username })
      emit('user.updated')
    },
    async setPin(id, bid, pin) {
      await delay(250)
      const u = byId(id)
      if (!u) throw mockErr(404, 'request.not_found')
      const b = (bindings[u.id] ?? []).find((x) => x.id === bid)
      if (!b) throw mockErr(404, 'request.not_found', { type: 'binding' })
      if (b.method !== 'badge') throw mockErr(400, 'auth.method_unavailable', { method: 'badge' })
      if (pin !== '' && !/^\d{4,}$/.test(pin)) throw mockErr(400, 'request.malformed', { field: 'pin' })
      b.properties = pin ? ['possession', 'knowledge', 'multi_factor'] : ['possession']
      b.assurance = pin ? 'AL2' : 'AL1'
      for (const c of Object.values(badges)) if (c.binding === bid) { if (pin) c.pin = pin; else delete c.pin }
      u.methods = (bindings[u.id] ?? []).map((x) => ({ method: x.method, assurance: x.assurance ?? 'AL1' }))
      append(`user:${session?.principal.id ?? ''}`, 'binding.pin_set', `principal:${u.id}`, 'session', 'AL1', 'ok', { binding: bid, identifier: u.username, removed: pin === '' })
      emit('user.updated')
    },
    async groups(q) { await delay(); return { items: clone(filter(groups, q, (g) => `${g.name} ${g.display_name}`)), total: groups.length } },
    async group(name) {
      await delay()
      const g = groups.find((x) => x.name === name || x.id === name)
      if (!g) throw mockErr(404, 'request.not_found')
      const members: Member[] = [
        ...Object.entries(nested).filter(([, parents]) => parents.some((p) => p.id === g.id)).map(([id]) => groups.find((x) => x.id === id)).filter((x): x is Group => !!x)
          .map((x) => ({ kind: 'group', id: x.id, name: x.name, display_name: x.display_name })),
        ...users.filter((u) => u.groups.some((m) => m.name === g.name)).map((u) => ({ kind: 'principal', id: u.id, name: u.username, display_name: u.display_name })),
      ]
      const d: GroupDetail = { ...clone(g), members, grants: clone(grants.filter((gr) => gr.subject.kind === 'group' && gr.subject.name === g.name)) }
      return d
    },
    async createGroup(body) {
      await delay(250)
      const name = body.name.trim()
      if (!name || groups.some((g) => g.name === name)) throw mockErr(409, 'request.conflict', { field: 'name' })
      const g: Group = { id: 'grp_' + name.replace(/[^a-z0-9]/gi, '_'), name, display_name: body.display_name['en'] || name, kind: 'static', member_count: 0, grant_count: 0 }
      groups.push(g)
      append(`user:${session?.principal.id ?? ''}`, 'group.create', `group:${g.id}`, 'session', 'AL1', 'ok', { name })
      emit('group.created')
      return clone(g)
    },
    async addMember(name, body) {
      await delay(200)
      const g = groups.find((x) => x.name === name)
      if (!g) throw mockErr(404, 'request.not_found')
      if (body.member_kind !== 'principal') throw mockErr(400, 'request.malformed', { field: 'member_kind' })
      const u = byId(body.member)
      if (!u) throw mockErr(404, 'principal.not_found')
      if (!u.groups.some((m) => m.id === g.id)) { u.groups.push({ id: g.id, name: g.name }); g.member_count++ }
      append(`user:${session?.principal.id ?? ''}`, 'group.member_add', `group:${g.id}`, 'session', 'AL1', 'ok', { member: u.username })
      emit('group.updated')
    },
    async removeMember(name, body) {
      await delay(200)
      const g = groups.find((x) => x.name === name)
      if (!g) throw mockErr(404, 'request.not_found')
      const u = byId(body.member)
      if (!u) throw mockErr(404, 'principal.not_found')
      if (u.groups.some((m) => m.id === g.id)) { u.groups = u.groups.filter((m) => m.id !== g.id); g.member_count-- }
      append(`user:${session?.principal.id ?? ''}`, 'group.member_remove', `group:${g.id}`, 'session', 'AL1', 'ok', { member: u.username })
      emit('group.updated')
    },
    async grants(q) { await delay(); return { items: clone(filter(grants, q, (g) => `${g.subject.name} ${g.role} ${g.resource.type}:${g.resource.id}`)), total: grants.length } },
    async roles() { await delay(); return { items: clone(roles), total: roles.length } },
    async resources() {
      await delay()
      const items: ResourceNode[] = [
        { type: 'directory', id: 'root', parent: null },
        { type: 'workstations', id: 'all', parent: null },
        ...devices.map((d): ResourceNode => ({ type: d.resource.type, id: d.resource.id, parent: d.resource.type === 'workstation' ? { type: 'workstations', id: 'all' } : null })),
        { type: 'equipment', id: 'laser-1', parent: null },
      ]
      const permissions: Record<string, string[]> = {
        directory: ['*', 'audit.read', 'authz.read', 'credentials.write', 'devices.read', 'devices.write', 'grants.read', 'grants.write', 'groups.read', 'groups.write', 'plugins.read', 'policies.write', 'resources.write', 'roles.write', 'system.read', 'system.write', 'updates.read', 'updates.write', 'users.read', 'users.write'],
        workstation: ['logon'], workstations: ['logon'],
      }
      for (const r of roles) permissions[r.resource_type] = [...new Set([...(permissions[r.resource_type] ?? []), ...r.permissions])].sort()
      for (const it of items) permissions[it.type] ??= []
      return { items, total: items.length, permissions }
    },
    async agents(owner) {
      await delay()
      const me = session?.principal.id ?? ''
      const admin = session?.permissions.includes('*')
      const items = agents.filter((a) => admin ? (!owner || a.owner?.id === owner || a.owner?.name === owner) : a.owner?.id === me)
      return { items: clone(items), total: items.length }
    },
    async agent(id) {
      await delay()
      const a = agents.find((x) => x.id === id || x.username === id)
      if (!a) throw mockErr(404, 'principal.not_found')
      const detail: AgentDetail = { ...clone(a), grants: clone(grants.filter((g) => g.subject.kind === 'principal' && g.subject.id === a.id)), grantable: heldBy(a.owner?.id ?? '') }
      return detail
    },
    async createAgent(body) {
      await delay(250)
      if (!/^[a-z][a-z0-9._-]{1,31}$/.test(body.username)) throw mockErr(400, 'request.malformed', { field: 'username' })
      if (users.some((u) => u.username === body.username) || agents.some((a) => a.username === body.username)) throw mockErr(409, 'request.conflict', { field: 'username' })
      const admin = session?.permissions.includes('*')
      const ownerRef = body.owner ? byId(body.owner) : byId(session?.principal.id ?? '')
      if (body.owner && !admin && ownerRef?.id !== session?.principal.id) throw mockErr(403, 'agent.not_owned')
      if (!ownerRef) throw mockErr(400, 'agent.owner_invalid', { owner: body.owner ?? '' })
      const a: Agent = { id: 'agt_' + Math.random().toString(16).slice(2, 10), username: body.username, kind: 'agent', display_name: body.display_name?.en || body.username,
        state: 'active', owner: { id: ownerRef.id, name: ownerRef.display_name }, token: { active: false }, grant_count: 0, created_at: iso(Date.now()) }
      agents.push(a)
      append(`user:${session?.principal.id ?? ''}`, 'principal.create', `principal:${a.id}`, 'session', 'AL1', 'ok', { username: a.username, kind: 'agent', owner_id: ownerRef.id })
      emit('user.created')
      return clone(a)
    },
    async agentToken(id) {
      await delay(250)
      const a = agents.find((x) => x.id === id || x.username === id)
      if (!a) throw mockErr(404, 'principal.not_found')
      const issued_at = iso(Date.now())
      a.token = { active: true, issued_at }
      append(`user:${session?.principal.id ?? ''}`, 'api_token.create', `principal:${a.id}`, 'session', 'AL1', 'ok', { principal_id: a.id })
      return { token: 'rst_' + Math.random().toString(16).slice(2).padEnd(48, 'a'), issued_at }
    },
    async agentTokenRevoke(id) {
      await delay(200)
      const a = agents.find((x) => x.id === id || x.username === id)
      if (!a) throw mockErr(404, 'principal.not_found')
      a.token = { active: false }
      append(`user:${session?.principal.id ?? ''}`, 'api_token.revoke', `principal:${a.id}`, 'session', 'AL1', 'ok', { principal_id: a.id })
    },
    async agentState(id, state) {
      await delay(200)
      const a = agents.find((x) => x.id === id || x.username === id)
      if (!a) throw mockErr(404, 'principal.not_found')
      a.state = state
      append(`user:${session?.principal.id ?? ''}`, 'principal.state', `principal:${a.id}`, 'session', 'AL1', 'ok', { state })
      emit('user.updated')
    },
    async agentGrant(id, body) {
      await delay(250)
      const a = agents.find((x) => x.id === id || x.username === id)
      if (!a) throw mockErr(404, 'principal.not_found')
      const admin = session?.permissions.includes('*')
      if (!admin && !heldBy(a.owner?.id ?? '').some((h) => h.role === body.role && h.resource_type === body.resource_type && h.resource_id === body.resource_id)) {
        throw mockErr(403, 'agent.grant_not_held', { role: body.role, resource: `${body.resource_type}:${body.resource_id}` })
      }
      const g: Grant = { id: 'grt_' + Math.random().toString(16).slice(2, 10), subject: { kind: 'principal', id: a.id, name: a.username }, role: body.role,
        resource: { type: body.resource_type, id: body.resource_id }, condition: body.condition ?? '', condition_class: 'offline', not_before: null, expires_at: body.expires_at ?? null }
      grants.push(g); a.grant_count++
      append(`user:${session?.principal.id ?? ''}`, 'grant.create', `grant:${g.id}`, 'session', 'AL1', 'ok', { subject: a.username, role: g.role, resource: `${g.resource.type}:${g.resource.id}` })
      emit('grant.created')
      return clone(g)
    },
    async agentGrantRevoke(id, gid) {
      await delay(200)
      const a = agents.find((x) => x.id === id || x.username === id)
      const i = grants.findIndex((g) => g.id === gid && g.subject.id === a?.id)
      if (!a || i < 0) throw mockErr(404, 'request.not_found')
      grants.splice(i, 1); a.grant_count--
      append(`user:${session?.principal.id ?? ''}`, 'grant.revoke', `grant:${gid}`, 'session', 'AL1', 'ok', { subject: a.username })
      emit('grant.revoked')
    },
    async upsertRole(body) {
      await delay(200)
      if (!body.resource_type || !body.name || body.permissions.length === 0) throw mockErr(400, 'request.malformed', { field: 'role' })
      const i = roles.findIndex((r) => r.resource_type === body.resource_type && r.name === body.name)
      const role = { resource_type: body.resource_type, name: body.name, permissions: [...body.permissions] }
      if (i >= 0) roles[i] = role; else roles.push(role)
      append(`user:${session?.principal.id ?? ''}`, 'role.upsert', `role:${role.resource_type}:${role.name}`, 'session', 'AL1', 'ok', { permissions: role.permissions })
      return clone(role)
    },
    async createGrant(body) {
      await delay(250)
      let subject: Grant['subject']
      if (body.subject_kind === 'group') {
        const g = groups.find((x) => x.name === body.subject || x.id === body.subject)
        if (!g) throw mockErr(404, 'request.not_found', { field: 'subject' })
        subject = { kind: 'group', id: g.id, name: g.name }; g.grant_count++
      } else {
        const u = byId(body.subject)
        if (!u) throw mockErr(404, 'principal.not_found')
        subject = { kind: 'principal', id: u.id, name: u.username }
      }
      const g: Grant = { id: 'grt_' + Math.random().toString(16).slice(2, 10), subject, role: body.role, resource: { type: body.resource_type, id: body.resource_id },
        condition: body.condition ?? '', condition_class: body.condition && /now\./.test(body.condition) ? 'online' : 'offline', not_before: null, expires_at: body.expires_at ?? null }
      grants.push(g)
      append(`user:${session?.principal.id ?? ''}`, 'grant.create', `grant:${g.id}`, 'session', 'AL1', 'ok', { subject: subject.name, role: g.role, resource: `${g.resource.type}:${g.resource.id}` })
      emit('grant.created')
      return clone(g)
    },
    async revokeGrant(id) {
      await delay(200)
      const i = grants.findIndex((g) => g.id === id)
      if (i < 0) throw mockErr(404, 'request.not_found')
      const [g] = grants.splice(i, 1)
      append(`user:${session?.principal.id ?? ''}`, 'grant.revoke', `grant:${id}`, 'session', 'AL1', 'ok', { subject: g?.subject.name, role: g?.role })
      emit('grant.revoked')
    },
    async devices(q) { await delay(); return { items: clone(filter(devices, q, (d) => `${d.display_name} ${d.resource.type} ${d.id}`)), total: devices.length } },
    async enrollmentToken(resource_type, ttl) {
      await delay(200)
      append(`user:${session?.principal.id ?? ''}`, 'enrollment_token.mint', `resource_type:${resource_type}`, 'session', 'AL1', 'ok', { ttl_seconds: ttl })
      return { enrollment_token: 'enr_' + Math.random().toString(36).slice(2, 14), expires_in: ttl }
    },
    async audit(q = {}) {
      await delay()
      let it = audit
      if (q.before) it = it.filter((r) => r.seq < q.before!)
      if (!q.include_system) it = it.filter((r) => r.actor.kind !== 'system' && r.actor.kind !== 'device')
      it = filter(it, q.q, (r) => `${r.actor.id} ${r.action} ${r.target.type}:${r.target.id} ${r.outcome} ${JSON.stringify(r.detail)}`)
      return { items: it.slice(0, q.limit ?? 50).map(named), head: { seq } }
    },
    async auditVerify() { await delay(600); return { intact: true, first_bad_seq: 0 } },
    async why(q) {
      await delay(250)
      const ex = why(q.principal, q.action, q.resource_type, q.resource_id)
      append(`user:${session?.principal.id ?? ''}`, 'why', `principal:${byId(q.principal)?.id ?? q.principal}`, 'session', 'AL1', 'ok', { action: q.action, resource: ex.resource, identifier: ex.principal })
      return ex
    },
    async updates() { await delay(); return clone(updateState) },
    async checkUpdates() {
      await delay(700)
      updateChecks++
      if (updateChecks === 1 && !updateState.available && updateState.current === 'v0.1.0') {
        updateState = { ...updateState, available: 'v0.1.3', checked_at: iso(Date.now()), notes: UPDATE_NOTES }
      } else {
        updateState = { ...updateState, checked_at: iso(Date.now()) }
      }
      emit('update.state')
      return clone(updateState)
    },
    async applyUpdate() {
      await delay(200)
      const target = updateState.available
      if (!target) throw mockErr(409, 'request.conflict', { reason: 'no_update_available' })
      updateState = { ...updateState, apply_requested: true }
      append(`user:${session?.principal.id ?? ''}`, 'update.apply_requested', `release:${target}`, 'session', 'AL1', 'ok', { from: updateState.current, to: target })
      setTimeout(() => { emit('update.state') }, 800)
      setTimeout(() => {
        updateState = { channel: 'stable', current: target, applied_at: iso(Date.now()), checked_at: iso(Date.now()), apply_requested: false, notes: UPDATE_NOTES }
        system.version = target
        downloadsAsked = 0 // a new version means a new bundle to fetch
        append('system:updater', 'update.applied', `release:${target}`, '', '', 'ok', { channel: 'stable', signature: 'verified' })
        emit('update.state')
      }, 3200)
      return clone(updateState)
    },
    async system() { await delay(); return clone(system) },
    async plugins() { await delay(); return { items: clone(plugins), total: plugins.length } },
    async cas() { await delay(); return caList() },
    async rotateCA() {
      await delay(600)
      const stamp = new Date().toISOString().slice(0, 7)
      const ca: CA = { id: 'cak_' + hex(8), subject: `Rostor CA (chattlab) ${stamp}`, not_after: iso(Date.now() + 3650 * day), created_at: iso(Date.now()), newest: true, devices: 0, fingerprint: hex(64) }
      for (const c of cas) c.newest = false
      cas.unshift(ca)
      trustVersion = 'tv_' + String(Number(trustVersion.slice(3)) + 1).padStart(4, '0')
      append(`user:${session?.principal.id ?? ''}`, 'ca.rotate', `ca:${ca.id}`, 'session', 'AL1', 'ok', { subject: ca.subject, trust_version: trustVersion })
      emit('device.trust')
      renewOnto(ca.id)
      return clone(ca)
    },
    async retireCA(id, force) {
      await delay(300)
      const i = cas.findIndex((c) => c.id === id)
      const ca = cas[i]
      if (!ca) throw mockErr(404, 'request.not_found')
      if (ca.newest || cas.length === 1) throw mockErr(400, 'ca.last_active')
      const dependents = devices.filter((d) => d.ca_key_id === id).length
      if (dependents > 0 && !force) throw mockErr(400, 'ca.in_use', { devices: dependents })
      cas.splice(i, 1) // the list endpoint only returns active CAs
      append(`user:${session?.principal.id ?? ''}`, 'ca.retire', `ca:${id}`, 'session', 'AL1', 'ok', { subject: ca.subject, forced: force, devices: dependents })
      emit('device.trust')
      // Forced: the devices it issued re-enroll onto the newest CA (mock stand-in for the operator doing so).
      const newest = cas.find((c) => c.newest)
      if (dependents > 0 && newest) renewOnto(newest.id, id)
    },
    async downloads() { await delay(); downloadsAsked++; return downloads() },
    downloadUrl: () => FAKE_BUNDLE_URL,
    async authSettings() { await delay(); return authSettings() },
    async setAuthSettings(body) {
      await delay(300)
      const rp_id = body.webauthn.rp_id.trim().toLowerCase()
      if (rp_id.includes('/') || rp_id.includes(':')) throw mockErr(400, 'request.malformed', { field: 'webauthn.rp_id' })
      const origins = body.webauthn.origins.map((o) => o.trim()).filter(Boolean)
      if (origins.some((o) => !o.startsWith('https://'))) throw mockErr(400, 'request.malformed', { field: 'webauthn.origins' })
      webauthn = { rp_id, display_name: body.webauthn.display_name.trim(), origins }
      if (body.login) defaultMethod = body.login.default_method
      append(`user:${session?.principal.id ?? ''}`, 'policy.update', 'policy:tenant-auth', 'session', 'AL1', 'ok', { 'webauthn.rp_id': rp_id, 'webauthn.origins': origins, 'login.default_method': defaultMethod })
      return authSettings()
    },

    stream(h, _lastEventId) {
      let state: LiveState = 'connecting'
      h.onState(state)
      const t = setTimeout(() => { state = 'connected'; h.onState(state); h.onReady?.({ version: system.version }); listeners.add(h); ensureTicker() }, 300)
      return () => { clearTimeout(t); listeners.delete(h); h.onState('off') }
    },
  }
}

/** Mint the mock session for a person who just authenticated, or explain why not. */
function signIn(u: User, method: string, assurance: string): LoginResponse {
  if (u.state !== 'active') return { code: 'principal.suspended', params: {}, message: 'This account is suspended.' }
  failedAttempts = 0
  // Admin rights come from directory-admins (role admin on directory:root);
  // board holds the read-only auditor role; everyone else is a plain member.
  const permissions = inGroup(u, 'directory-admins') ? ['*']
    : inGroup(u, 'board') ? [...(roles.find((r) => r.resource_type === 'directory' && r.name === 'auditor')?.permissions ?? []), 'agents.own']
    : inGroup(u, 'agent-owners') ? ['agents.own']
    : []
  session = { principal: { id: u.id, kind: u.kind, username: u.username, display_name: u.display_name, state: u.state }, assurance, permissions }
  saveSession(session)
  append(`user:${u.id}`, 'session.create', `principal:${u.id}`, method, assurance, 'allow', { identifier: u.username, client: 'console' })
  const ok: LoginOK = { principal: session.principal, assurance, expires_at: iso(Date.now() + 8 * hour) }
  return ok
}

function mockErr(status: number, code: string, params: Record<string, unknown> = {}) {
  const e = new Error(code) as Error & { status: number; body: { code: string; params: Record<string, unknown>; message?: string } }
  e.status = status
  // Like the server: the rendered message carries the params.
  const tpl = serverCodes[code]
  e.body = { code, params, message: tpl?.replace(/\{(\w+)\}/g, (m, k: string) => (params[k] === undefined ? m : String(params[k]))) }
  return e
}

// Codes the server catalog already renders (internal/catalog/en.json) that
// the console shows verbatim through t(): reason codes in Why chains.
const serverCodes: Record<string, string> = {
  'auth.failed': 'Sign-in failed.',
  'auth.locked': 'Too many failed attempts. Try again in {minutes} minutes.',
  'auth.continue': 'Enter your PIN to finish signing in.',
  'auth.method_unavailable': 'That sign-in method is not available for this account.',
  'auth.passkey_rejected': 'That passkey could not be registered.',
  'auth.passkeys_unconfigured': 'Passkeys are not set up for this organisation yet.',
  'auth.pin_required': 'This account requires a PIN with the badge.',
  'setup.already_done': 'This organisation already has an administrator.',
  'setup.token_invalid': 'That bootstrap token is not valid.',
  'request.malformed': 'The request could not be understood.',
  'request.unauthorized': 'Authentication is required.',
  'principal.suspended': 'This account is suspended.',
  'principal.not_active': 'This account is not active.',
  'principal.not_found': 'No account matches that identifier.',
  'grant.none': 'You do not have access to this {resource_type}.',
  'grant.matched': 'Allowed by {role} via {via}.',
  'grant.condition_failed': 'A condition on your access was not met.',
  'request.forbidden': 'You are not allowed to do that.',
  'request.not_found': 'Not found.',
  'request.conflict': 'That is already registered.',
  'internal.error': 'Something went wrong on the server.',
  'ca.in_use': '{devices} devices still hold certificates from this authority. Wait for them to renew, or force the retirement.',
  'ca.last_active': 'The last active certificate authority cannot be retired.',
  'download.unavailable': 'The installer for this version could not be fetched from the release host.',
}
