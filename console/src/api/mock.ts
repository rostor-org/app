// In-memory implementation of the console API for development without the
// backend (VITE_MOCK=1 or ?mock=1). Data mirrors the approved mockup.
import type {
  Api, AuditRow, Device, Explanation, Grant, Group, GroupDetail, LiveEvent, LiveHandlers,
  LiveState, Member, Plugin, Session, Summary, SystemInfo, UpdateState, User, UserDetail, Binding, Reason,
} from './types'
import catalogEn from '../../catalog.en.json'

const SESSION_KEY = 'rostor-console-mock-session'

const now = Date.now()
const min = 60_000, hour = 3_600_000, day = 86_400_000
const today = (h: number, m: number, s = 0) => { const d = new Date(now); d.setHours(h, m, s, 0); return d.toISOString() }
const daysAgo = (n: number, h: number, m: number) => { const d = new Date(now - n * day); d.setHours(h, m, 0, 0); return d.toISOString() }
const iso = (t: number) => new Date(t).toISOString()

const groupRefs = {
  members: { id: 'grp_members', name: 'members' },
  board: { id: 'grp_board', name: 'board' },
  laser: { id: 'grp_laser', name: 'laser-certified' },
  staff: { id: 'grp_staff', name: 'staff' },
  guests: { id: 'grp_guests_a', name: 'guests-from-a' },
}

const users: User[] = [
  { id: 'usr_f40101ae', kind: 'user', username: 'dan', display_name: 'Dan Evans', state: 'active',
    groups: [groupRefs.members, groupRefs.board], methods: [{ method: 'password', assurance: 'AL1' }],
    last_sign_in: { ts: today(13, 59), resource: 'workstation:DESKTOP-UPJD27E' } },
  { id: 'usr_9b2c11d0', kind: 'user', username: 'dana', display_name: 'Dana Whitfield', state: 'active',
    groups: [groupRefs.members, groupRefs.laser], methods: [{ method: 'badge', assurance: 'AL1' }, { method: 'password', assurance: 'AL1' }],
    last_sign_in: { ts: daysAgo(1, 19, 12), resource: 'door:exterior-alley' } },
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
  usr_f40101ae: [{ id: 'bnd_01', method: 'password', properties: ['knowledge'], label: 'Password', created_at: today(9, 2), last_used_at: today(13, 59), state: 'active' }],
  usr_9b2c11d0: [
    { id: 'bnd_02', method: 'badge', properties: ['possession'], label: 'Badge 0004A1F3', created_at: daysAgo(40, 11, 0), last_used_at: daysAgo(1, 19, 12), state: 'active' },
    { id: 'bnd_03', method: 'password', properties: ['knowledge'], label: 'Password', created_at: daysAgo(40, 11, 5), last_used_at: daysAgo(3, 8, 30), state: 'active' },
  ],
  usr_41aa72ef: [{ id: 'bnd_04', method: 'badge', properties: ['possession'], label: 'Badge 0004A1D9', created_at: daysAgo(90, 12, 0), last_used_at: daysAgo(8, 10, 5), state: 'active' }],
  usr_c0de5a19: [{ id: 'bnd_05', method: 'badge', properties: ['possession'], label: 'Badge 0004A211', created_at: daysAgo(12, 12, 0), last_used_at: daysAgo(2, 16, 40), state: 'active' }],
  usr_77f1b3c2: [],
  svc_3e9a0c44: [{ id: 'bnd_06', method: 'api_token', properties: ['possession'], label: 'API token', created_at: daysAgo(5, 9, 0), last_used_at: today(14, 20), state: 'active' }],
}

const groups: Group[] = [
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
  { id: 'grt_c4d5e6f7', subject: { kind: 'service', id: 'svc_admin_cli', name: 'admin-cli' }, role: 'admin', resource: { type: 'directory', id: 'root' }, condition: '', condition_class: 'offline', not_before: null, expires_at: null },
]

const devices: Device[] = [
  { id: 'dev_12ce4c4b9f0a', display_name: 'DESKTOP-UPJD27E', resource: { type: 'workstation', id: 'DESKTOP-UPJD27E' }, lifecycle: 'trusted', last_seen_at: iso(now - 1 * min),
    posture: { os: 'Windows 10.0.19045', agent: '0.1.0', via: 'heartbeat' }, cert_not_after: '2027-09-22T00:00:00Z' },
  { id: 'dev_a91c0b3e7d21', display_name: 'Front door controller', resource: { type: 'door', id: 'front' }, lifecycle: 'trusted', last_seen_at: iso(now - 3 * min),
    posture: { model: 'WG2004', snapshot: 'v418', doors_wired: '2 of 4', cards: 432, managed: 124 }, cert_not_after: '2027-06-01T00:00:00Z' },
  { id: 'dev_77e0f5a2c318', display_name: 'Laser interlock', resource: { type: 'interlock', id: 'laser-cutter-2' }, lifecycle: 'degraded', last_seen_at: iso(now - 26 * hour),
    posture: { model: 'ESP32', snapshot: 'v402', ladder: 'staff-only' }, cert_not_after: '2027-03-14T00:00:00Z' },
]

let seq = 1184
const audit: AuditRow[] = [
  row(today(14, 31, 7), 'user:usr_f40101ae', 'verify', 'workstation:DESKTOP-UPJD27E', 'password', 'AL1', 'allow', { identifier: 'dan' }),
  row(today(14, 20, 41), 'service:svc_3e9a0c44', 'grant.create', 'grant:grt_0c2d9e71', 'api_token', 'AL1', 'ok', { subject: 'members', role: 'operate', resource: 'equipment:cnc-mill' }),
  row(today(14, 20, 39), 'service:svc_3e9a0c44', 'binding.enroll', 'principal:usr_77f1b3c2', 'api_token', 'AL1', 'ok', { method: 'badge', label: '0004A1F7', identifier: 'jo' }),
  row(today(13, 59, 35), 'user:usr_f40101ae', 'verify', 'workstation:DESKTOP-UPJD27E', 'password', 'AL1', 'allow', { identifier: 'dan' }),
  row(today(13, 49, 7), 'device:dev_12ce4c4b9f0a', 'verify', 'workstation:DESKTOP-UPJD27E', 'password', '', 'deny', { identifier: 'dan', reason: 'auth.failed' }),
  row(today(13, 24, 14), 'service:svc_admin_cli', 'principal.state', 'principal:usr_f40101ae', 'api_token', 'AL1', 'ok', { from: 'active', to: 'suspended', identifier: 'dan' }),
  row(today(13, 24, 14), 'device:dev_12ce4c4b9f0a', 'verify', 'workstation:DESKTOP-UPJD27E', 'password', '', 'deny', { identifier: 'dan', reason: 'principal.suspended' }),
  row(today(12, 16, 26), 'system:enroll', 'device.enroll', 'device:dev_12ce4c4b9f0a', 'enrollment_token', '', 'ok', { display_name: 'DESKTOP-UPJD27E' }),
].reverse().map((r, i) => ({ ...r, seq: seq - 7 + i })).reverse()

function ref(s: string): [string, string] { const i = s.indexOf(':'); return i < 0 ? [s, ''] : [s.slice(0, i), s.slice(i + 1)] }
function row(ts: string, actor: string, action: string, target: string, credential_type: string, assurance: string, outcome: string, detail: Record<string, unknown>): AuditRow {
  const [ak, aid] = ref(actor)
  const [tt, tid] = ref(target)
  return { seq: 0, ts, actor: { kind: ak, id: aid }, action, target: { type: tt, id: tid }, credential_type, assurance, outcome, detail }
}

function append(actor: string, action: string, target: string, credential_type: string, assurance: string, outcome: string, detail: Record<string, unknown>) {
  seq++
  audit.unshift({ ...row(iso(Date.now()), actor, action, target, credential_type, assurance, outcome, detail), seq })
  emit('audit.appended')
}

let updateState: UpdateState = { channel: 'stable', current: 'v0.1.0', checked_at: today(14, 32), apply_requested: false, notes: 'First appliance release.' }
let updateChecks = 0

const system: SystemInfo = {
  version: 'v0.1.0', tenant: { id: 'tnt_chattlab', name: 'ChattLab' },
  db: { size_bytes: 18_874_368, engine: 'PostgreSQL 15' }, uptime_seconds: 2 * 3600 + 6 * 60,
  ca: { subject: 'Rostor CA (chattlab)', not_after: '2036-09-22T00:00:00Z' },
  release_key_fingerprint: 'f63294b2c1a04e9d7b3f5a6c8d2e1f0a4b76', profile: 'standard',
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
    const who = (['dana', 'priya', 'maria', 'tom'] as const)[Math.floor(Math.random() * 4)] ?? 'dana'
    append('device:dev_a91c0b3e7d21', 'verify', 'door:exterior-alley', 'badge', 'AL1', 'allow', { identifier: who })
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
  const memberOf = Object.fromEntries(u.groups.map((g) => [g.name, [u.username, g.name]]))
  const cands = grants.filter((g) => g.subject.kind === 'group' ? u.groups.some((m) => m.name === g.subject.name) : g.subject.id === u.id)
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
      const u = users.find((x) => x.username === req.identifier)
      if (failedAttempts >= 5) return { code: 'auth.locked', params: { minutes: 15 }, message: 'Too many failed attempts. Try again in 15 minutes.' }
      if (!u || req.fields.password !== 'demo') { failedAttempts++; return { code: 'auth.failed', params: {}, message: 'Sign-in failed.' } }
      if (u.state !== 'active') return { code: 'principal.suspended', params: {}, message: 'This account is suspended.' }
      failedAttempts = 0
      session = { principal: { id: u.id, kind: u.kind, username: u.username, display_name: u.display_name, state: u.state }, assurance: 'AL1',
        permissions: u.username === 'dan' ? ['*'] : ['users.read', 'audit.read', 'authz.read', 'updates.read'] }
      saveSession(session)
      append(`user:${u.id}`, 'session.create', `principal:${u.id}`, 'password', 'AL1', 'allow', { identifier: u.username, client: 'console' })
      return { principal: session.principal, assurance: 'AL1', expires_at: iso(Date.now() + 8 * hour) }
    },
    async session() { await delay(60); return session ? clone(session) : null },
    async logout() { await delay(60); session = null; saveSession(null) },

    async summary() { await delay(); return summary() },
    async users(q) { await delay(); const it = filter(users, q, (u) => `${u.display_name} ${u.username} ${u.groups.map((g) => g.name).join(' ')}`); return { items: clone(it), total: 130 } },
    async user(id) {
      await delay()
      const u = byId(id)
      if (!u) throw mockErr(404, 'request.not_found')
      const b = bindings[u.id] ?? []
      const recent = audit.filter((r) => r.actor.id === u.id || r.target.id === u.id || r.detail?.identifier === u.username).slice(0, 6)
      const d: UserDetail = { ...clone(u), bindings: clone(b).map((x) => ({ ...x, assurance: 'AL1' })), effective_security: { assurance: b.length ? 'AL1' : 'AL0', bindings: b.length, recovery_paths: 0 }, recent: clone(recent) }
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
      const b: Binding = { id: 'bnd_' + Math.random().toString(16).slice(2, 8), method: body.method, properties: ['knowledge'], label: body.label || 'Password',
        assurance: 'AL1', created_at: iso(Date.now()), last_used_at: null, state: 'active' }
      bindings[u.id] = [...(bindings[u.id] ?? []).filter((x) => x.method !== body.method), b]
      u.methods = (bindings[u.id] ?? []).map((x) => ({ method: x.method, assurance: 'AL1' }))
      append(`user:${session?.principal.id ?? ''}`, 'binding.enroll', `principal:${u.id}`, 'session', 'AL1', 'ok', { method: body.method, identifier: u.username })
      emit('user.updated')
      return b
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
      u.methods = (bindings[u.id] ?? []).map((b) => ({ method: b.method, assurance: 'AL1' }))
      append(`user:${session?.principal.id ?? ''}`, 'binding.revoke', `principal:${u.id}`, 'session', 'AL1', 'ok', { binding: bid, identifier: u.username })
      emit('user.updated')
    },
    async groups(q) { await delay(); return { items: clone(filter(groups, q, (g) => `${g.name} ${g.display_name}`)), total: groups.length } },
    async group(name) {
      await delay()
      const g = groups.find((x) => x.name === name || x.id === name)
      if (!g) throw mockErr(404, 'request.not_found')
      const members: Member[] = users.filter((u) => u.groups.some((m) => m.name === g.name)).map((u) => ({ kind: 'principal', id: u.id, name: u.username, display_name: u.display_name }))
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
      it = filter(it, q.q, (r) => `${r.actor.id} ${r.action} ${r.target.type}:${r.target.id} ${r.outcome} ${JSON.stringify(r.detail)}`)
      return { items: clone(it.slice(0, q.limit ?? 50)), head: { seq } }
    },
    async auditVerify() { await delay(600); return { intact: true, first_bad_seq: 0 } },
    async why(q) {
      await delay(250)
      const ex = why(q.principal, q.action, q.resource_type, q.resource_id)
      append(`user:${session?.principal.id ?? ''}`, 'why', `principal:${ex.principal}`, 'session', 'AL1', 'ok', { action: q.action, resource: ex.resource })
      return ex
    },
    async updates() {
      await delay(500)
      updateChecks++
      if (updateChecks > 1 && !updateState.available && updateState.current === 'v0.1.0') {
        updateState = { ...updateState, available: 'v0.1.1', checked_at: iso(Date.now()), notes: 'Console: live audit, Why panel; agent: badge+PIN.' }
      } else {
        updateState = { ...updateState, checked_at: iso(Date.now()) }
      }
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
        updateState = { channel: 'stable', current: target, applied_at: iso(Date.now()), checked_at: iso(Date.now()), apply_requested: false, notes: 'Console: live audit, Why panel; agent: badge+PIN.' }
        system.version = target
        append('system:updater', 'update.applied', `release:${target}`, '', '', 'ok', { channel: 'stable', signature: 'verified' })
        emit('update.state')
      }, 3200)
      return clone(updateState)
    },
    async system() { await delay(); return clone(system) },
    async plugins() { await delay(); return { items: clone(plugins), total: plugins.length } },

    stream(h, _lastEventId) {
      let state: LiveState = 'connecting'
      h.onState(state)
      const t = setTimeout(() => { state = 'connected'; h.onState(state); listeners.add(h); ensureTicker() }, 300)
      return () => { clearTimeout(t); listeners.delete(h); h.onState('off') }
    },
  }
}

function mockErr(status: number, code: string, params: Record<string, unknown> = {}) {
  const e = new Error(code) as Error & { status: number; body: { code: string; params: Record<string, unknown> } }
  e.status = status
  e.body = { code, params }
  return e
}

// Codes the server catalog already renders (internal/catalog/en.json) that
// the console shows verbatim through t(): reason codes in Why chains.
const serverCodes: Record<string, string> = {
  'auth.failed': 'Sign-in failed.',
  'auth.locked': 'Too many failed attempts. Try again in {minutes} minutes.',
  'principal.suspended': 'This account is suspended.',
  'principal.not_active': 'This account is not active.',
  'principal.not_found': 'No account matches that identifier.',
  'grant.none': 'You do not have access to this {resource_type}.',
  'grant.matched': 'Allowed by {role} via {via}.',
  'grant.condition_failed': 'A condition on your access was not met.',
  'request.forbidden': 'You are not allowed to do that.',
  'request.not_found': 'Not found.',
  'request.conflict': 'That already exists.',
  'internal.error': 'Something went wrong on the server.',
}
