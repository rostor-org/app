// Types for app/docs/contracts/console-api.md. Field names follow the
// contract; where the contract only describes a shape in prose the chosen
// names are marked ASSUMED so the server side can align.

export interface ApiErrorBody {
  code: string
  params?: Record<string, unknown>
  message?: string
}

export interface Catalog {
  locale: string
  strings: Record<string, string>
}

export interface Brand {
  tenant_name: string
  tokens: Record<string, string>
}

export interface Principal {
  id: string
  kind?: string // user | service
  username?: string
  display_name?: string | Record<string, string>
  state?: string
}

export interface LoginRequest {
  identifier: string
  method: 'password'
  fields: { password: string }
}

export interface LoginOK {
  principal: Principal
  assurance: string
  expires_at: string
}
export type LoginResponse = LoginOK | ApiErrorBody

export interface Session {
  principal: Principal
  assurance: string
  permissions: string[] // e.g. ["users.write"] or ["*"]
}

export interface Summary {
  people: { active: number; suspended: number; applicants: number; service_accounts: number }
  groups: number
  grants: number
  devices: Record<string, number> // by lifecycle
  offline_points: number
  oldest_snapshot_age_seconds: number | null
}

export interface List<T> {
  items: T[]
  total: number
}

export interface GroupRef {
  id: string
  name: string
}
export interface MethodRef {
  method: string
  assurance: string
}
export interface LastSignIn {
  ts: string
  resource: string
}

export interface User {
  id: string
  kind?: string // user | service (not in contract; optional)
  username: string
  display_name: string
  state: string
  groups: GroupRef[]
  methods: MethodRef[]
  last_sign_in: LastSignIn | null
}

export interface Binding {
  id: string
  method: string
  properties: string[]
  label: string
  assurance?: string
  created_at: string
  last_used_at: string | null
  state: string
}

export interface EffectiveSecurity {
  assurance: string
  bindings: number
  recovery_paths: number
}

// The detail body omits the list's `methods` and `last_sign_in`; bindings and
// `recent` carry that information instead.
export interface UserDetail extends Omit<User, 'methods' | 'last_sign_in' | 'groups'> {
  groups: Array<GroupRef & { direct?: boolean }>
  methods?: MethodRef[]
  last_sign_in?: LastSignIn | null
  bindings: Binding[]
  effective_security: EffectiveSecurity
  recent: AuditRow[]
}

export interface Group {
  id: string
  name: string
  display_name: string
  kind: string // static | dynamic | synced
  member_count: number
  grant_count: number
}

export interface Member {
  kind: string // principal | group
  id: string
  username?: string
  name?: string
  display_name?: string
  state?: string
}

export interface GroupDetail extends Omit<Group, 'member_count' | 'grant_count'> {
  member_count?: number
  grant_count?: number
  members: Member[]
  grants: Grant[]
}

export interface Subject {
  kind: string // user | service | group
  id: string
  name: string
}
export interface ResourceRef {
  type: string
  id: string
}

export interface Grant {
  id: string
  subject: Subject
  role: string
  resource: ResourceRef
  condition: string
  condition_class: string
  not_before: string | null
  expires_at: string | null
}

export interface Device {
  id: string
  display_name: string
  resource: ResourceRef
  lifecycle: string
  last_seen_at: string | null
  posture: Record<string, unknown> | null
  cert_not_after: string | null
}

export interface AuditRow {
  seq: number
  ts: string
  actor: { kind: string; id: string }
  action: string
  target: { type: string; id: string }
  credential_type: string
  assurance: string
  outcome: string
  detail: Record<string, unknown> | null
  correlation_id?: string
}

export interface AuditPage {
  items: AuditRow[]
  head: { seq: number }
}

export interface AuditQuery {
  limit?: number
  before?: number
  q?: string
}

export interface AuditVerify {
  intact: boolean
  first_bad_seq: number
}

export interface Reason {
  code: string
  params?: Record<string, unknown>
  message?: string
}

export interface DirectoryGrant {
  id: string
  subject_kind: string
  subject_id: string
  role: string
  resource_type: string
  resource_id: string
  condition?: string
  condition_class: string
  not_before?: string | null
  expires_at?: string | null
}

export interface Candidate {
  grant: DirectoryGrant
  via: string
  matched: boolean
  condition_result?: string
}

export interface Explanation {
  decision: 'ALLOW' | 'DENY'
  reason: Reason[]
  grant_id?: string
  as_of: string
  principal: string
  action: string
  resource: string
  groups: Record<string, string[]>
  candidates: Candidate[]
}

export interface WhyQuery {
  principal: string
  action: string
  resource_type: string
  resource_id: string
}

export interface UpdateState {
  channel: string
  current: string
  available?: string
  checked_at?: string
  applied_at?: string
  last_error?: string
  apply_requested: boolean
  notes?: string
}

export interface SystemInfo {
  version: string
  tenant: { id: string; name: string }
  listeners?: Array<string | { name?: string; addr: string }> // not emitted yet
  db: { size_bytes: number; engine?: string }
  uptime_seconds: number
  ca: { subject: string; not_after: string }
  release_key_fingerprint: string
  profile: string
}

export interface Plugin {
  id: string
  name: string
  publisher: string
  version: string
  type: string
  runtime: string
  masters: string[]
  scopes: string[]
  state: string
}

// ---- write bodies (internal/api/handlers.go) --------------------------------

export interface CreateUser {
  username: string
  display_name: Record<string, string> // {en: "…"}
  state?: string
}
export interface EnrollBinding {
  method: string // "password"
  label?: string
  fields: Record<string, string>
}
export interface CreateGroup {
  name: string
  display_name: Record<string, string>
}
export interface MemberChange {
  member_kind: 'principal' | 'group'
  member: string // username, principal id, or group name
}
export interface CreateGrant {
  subject_kind: 'principal' | 'group'
  subject: string
  role: string
  resource_type: string
  resource_id: string
  condition?: string
  expires_at?: string | null
}

export interface EnrollmentToken {
  enrollment_token: string
  expires_in: number
}

export type EventType =
  | `user.${string}`
  | `grant.${string}`
  | `group.${string}`
  | `device.${string}`
  | 'audit.appended'
  | 'update.state'
  | (string & {})

export interface LiveEvent {
  id: string
  type: EventType
}

export type LiveState = 'off' | 'connecting' | 'connected' | 'reconnecting'

export interface LiveHandlers {
  onEvent: (e: LiveEvent) => void
  onState: (s: LiveState) => void
}

/** The single fetch interface both the HTTP client and the mock implement. */
export interface Api {
  catalog(locale: string): Promise<Catalog>
  brand(): Promise<Brand>
  login(req: LoginRequest): Promise<LoginResponse>
  session(): Promise<Session | null> // null on 401
  logout(): Promise<void>

  summary(): Promise<Summary>
  users(q?: string): Promise<List<User>>
  user(id: string): Promise<UserDetail>
  createUser(body: CreateUser): Promise<Principal>
  setUserState(id: string, state: string): Promise<void>
  enrollBinding(id: string, body: EnrollBinding): Promise<Binding>
  revokeBinding(id: string, bid: string): Promise<void>
  groups(q?: string): Promise<List<Group>>
  group(name: string): Promise<GroupDetail>
  createGroup(body: CreateGroup): Promise<Group>
  addMember(name: string, body: MemberChange): Promise<void>
  removeMember(name: string, body: MemberChange): Promise<void>
  grants(q?: string): Promise<List<Grant>>
  createGrant(body: CreateGrant): Promise<Grant>
  revokeGrant(id: string): Promise<void>
  devices(q?: string): Promise<List<Device>>
  enrollmentToken(resourceType: string, ttlSeconds: number): Promise<EnrollmentToken>
  audit(q?: AuditQuery): Promise<AuditPage>
  auditVerify(): Promise<AuditVerify>
  why(q: WhyQuery): Promise<Explanation>
  updates(): Promise<UpdateState>
  applyUpdate(): Promise<UpdateState>
  system(): Promise<SystemInfo>
  plugins(): Promise<List<Plugin>>

  /** Open the live stream. Returns a function that closes it. */
  stream(h: LiveHandlers, lastEventId: string | null): () => void
}
