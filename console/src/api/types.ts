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

export interface PasswordLogin {
  identifier: string
  method: 'password'
  fields: { password: string }
}
/** Credential-identified sign-in (no identifier): the card names the person. */
export interface BadgeLogin {
  method: 'badge'
  fields: { number: string; pin?: string }
}
export type LoginRequest = PasswordLogin | BadgeLogin

export interface LoginOK {
  principal: Principal
  assurance: string
  expires_at: string
}
/** `{code:"auth.continue", params:{need:"pin"}}`: the ceremony needs one more field. */
export interface LoginContinue extends ApiErrorBody {
  code: 'auth.continue'
  params?: { need?: string } & Record<string, unknown>
}
export type LoginResponse = LoginOK | LoginContinue | ApiErrorBody

// ---- passkeys (WebAuthn) ---------------------------------------------------
// `options` is what the server's WebAuthn library emits: go-webauthn wraps the
// JSON options as {"publicKey": {...}}; a bare options object is accepted too.

export type CreationOptionsJSON = PublicKeyCredentialCreationOptionsJSON
export type RequestOptionsJSON = PublicKeyCredentialRequestOptionsJSON
export type OptionsWrapper<O> = { publicKey: O } | O

export interface PasskeyCeremony<O> {
  ceremony_id: string
  options: OptionsWrapper<O>
}
export interface PasskeyRegisterFinish {
  ceremony_id: string
  label: string
  response: PublicKeyCredentialJSON
}
export interface PasskeyLoginBegin {
  identifier?: string
}
export interface PasskeyLoginFinish {
  ceremony_id: string
  response: PublicKeyCredentialJSON
}

// ---- tenant sign-in settings (GET/PUT /v1/admin/settings/auth) --------------

export interface WebAuthnSettings {
  rp_id: string
  display_name: string
  origins: string[]
}
export type LoginMethod = 'password' | 'passkey' | 'badge'
/** Badge number format (auth policy badge.format): keep every form, or reduce every reading to Wiegand-26 facility:card. */
export type BadgeFormat = 'none' | 'wiegand26'
/** Which tile a Windows lock screen selects: the Rostor tile, or Windows' own sign-in with Rostor one click away. */
export type DefaultProvider = 'rostor' | 'windows'
export interface AuthSettings {
  webauthn: WebAuthnSettings & { enrolled_passkeys: number }
  login: { default_method: LoginMethod }
  badge: { format: BadgeFormat }
  logon: { default_provider: DefaultProvider }
}
export interface AuthSettingsUpdate {
  webauthn: WebAuthnSettings
  login?: { default_method: LoginMethod }
  badge?: { format: BadgeFormat }
  logon?: { default_provider: DefaultProvider }
}
/**
 * A per-group override of the tenant's login.default_method
 * (GET /v1/admin/settings/auth/overrides). Applies to people and to devices
 * in the group; when several apply, the newest wins.
 */
export interface AuthOverride {
  group: GroupRef
  login: { default_method: LoginMethod | '' }
  /** A shared local account every session on the group's devices runs as (licensed workstations); empty when none. */
  logon: { session_account: string; default_provider: DefaultProvider | '' }
  created_at: string
}
export interface AuthOverrideUpdate {
  login?: { default_method: LoginMethod }
  logon?: { session_account?: string; default_provider?: DefaultProvider }
}

export interface Session {
  principal: Principal
  assurance: string
  permissions: string[] // e.g. ["users.write"] or ["*"]; [] for a member without admin rights
}

// ---- first administrator (GET/POST /v1/auth/setup) --------------------------

export interface SetupStatus {
  needed: boolean
  default_method?: LoginMethod
}
export interface SetupRequest {
  bootstrap_token: string
  username: string
  display_name: string
  password: string
}

/** A role definable on a resource type (GET /v1/admin/roles). */
export interface Role {
  resource_type: string
  name: string
  permissions: string[]
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
  owner?: { id: string; name: string } // agents only
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
  /** Badges: the forms the card is known by (uid, printed, wiegand26 as facility:card). */
  forms?: { kind: string; value: string }[]
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
  /** v0.5.0: the CA that issued the current certificate, the trust bundle the device holds, and its last renewal. */
  ca_key_id?: string
  trust_version?: string
  cert_renewed_at?: string | null
  /** v0.14.0: the deputy's reported version and the last self-update attempt. */
  deputy_version?: string
  update?: { wanted: boolean; status: 'ok' | 'failed' | null; version?: string; at?: string; from_version?: string; output_tail?: string }
}
export type DeputyUpdatePolicy = 'auto' | 'manual'
export interface DeviceSettings {
  deputy: { update: DeputyUpdatePolicy }
}

// ---- certificates and trust (GET /v1/admin/ca, v0.5.0) ----------------------

export interface CA {
  id: string
  subject: string
  not_after: string
  created_at: string
  retired_at?: string | null
  newest: boolean
  /** Devices whose current certificate this CA issued. */
  devices: number
  fingerprint: string
}
export interface CAList {
  items: CA[]
  trust_version: string
  devices: { total: number; on_older_bundle: number }
}

// ---- downloads (GET /v1/admin/downloads, v0.5.0) ---------------------------

export interface DownloadStatus {
  name: string
  version: string
  cached: boolean
  size?: number
  fetched_at?: string
  error?: string
}
export interface Downloads {
  windows: DownloadStatus
}

export interface AuditRow {
  seq: number
  ts: string
  actor: { kind: string; id: string; name?: string; owner_id?: string; owner_name?: string } // name when known; owner for agents
  action: string
  target: { type: string; id: string; name?: string }
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
  /** Also show what the appliance and devices did (actor kinds system and device); hidden by default. */
  include_system?: boolean
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
  /** v0.5.0: the address devices enroll against (the mTLS listener), for the install command. */
  device_url?: string
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
/** POST /v1/admin/badges/read: how a reader's output is understood under the tenant's badge format. */
export interface BadgeReading {
  format: BadgeFormat
  stored: Record<string, string>
  wiegand26?: string
  facility?: number
  card?: number
  value24?: number
}

export interface EnrollBinding {
  method: string // "password" | "badge"
  label?: string
  fields: Record<string, string> // password: {password}; badge: {number, pin?} (or uid / printed / facility+card)
}
export interface CreateGroup {
  name: string
  display_name: Record<string, string>
}
export interface MemberChange {
  member_kind: 'principal' | 'group'
  member: string // username, principal id, or group name
}
/** GET /v1/admin/resources: every resource with its parent, plus the permissions known per type (for defining roles). */
export interface ResourceNode {
  type: string
  id: string
  parent: { type: string; id: string } | null
}
export interface ResourceCatalog {
  items: ResourceNode[]
  total: number
  permissions: Record<string, string[]>
}

// ---- agents (SPEC-agents) ------------------------------------------------------
export interface Agent {
  id: string
  username: string
  kind: 'agent'
  display_name: string
  state: string
  owner: { id: string; name: string } | null
  token: { active: boolean; issued_at?: string }
  grant_count: number
  created_at: string
}
export interface HeldRight {
  resource_type: string
  resource_id: string
  role: string
  via: string
}
export interface AgentDetail extends Agent {
  grants: Grant[]
  /** What the owner holds, so exactly what may be handed to this agent. */
  grantable: HeldRight[]
}
export interface CreateAgent {
  username: string
  display_name?: Record<string, string>
  owner?: string
}
export interface AgentGrant {
  role: string
  resource_type: string
  resource_id: string
  condition?: string
  expires_at?: string | null
}

// ---- scripts (SPEC-scripts, v0.9.0) -----------------------------------------
// Text pushed to workstations and run by the agent in position order. Every
// write needs scripts.write and an AL2 session (403 request.assurance_required).

export type ScriptMode = 'immediate' | 'signin'
export type ScriptTargetKind = 'all' | 'group'
/** How a run ended; the agent reports one of these (others render as their code). */
export type ScriptRunStatus = 'ok' | 'failed' | 'timeout' | 'error' | (string & {})
export interface ScriptAssignment {
  id: string
  /** `all` targets every device of a resource type (id "workstation"); `group` names a device group. */
  target: { kind: ScriptTargetKind; id: string; name: string }
  mode: ScriptMode
}
export interface ScriptLastRun {
  at: string
  exit_code: number
  status: ScriptRunStatus
  device: { id: string; name: string }
}
export interface Script {
  id: string
  name: string
  description: string
  language: string // powershell only in this slice
  position: number
  version: number
  updated_at: string
  updated_by: { id: string; name: string }
  assignments: ScriptAssignment[]
  last_run: ScriptLastRun | null
}
export interface ScriptRun {
  id: string
  device: { id: string; name: string }
  /** The person signing in, for sign-in runs; null for immediate runs. */
  principal: { id: string; name: string } | null
  version: number
  mode: ScriptMode
  started_at: string
  finished_at: string
  exit_code: number
  status: ScriptRunStatus
  /** Last 4 KB of stdout+stderr. */
  output_tail: string
}
/** GET /v1/admin/scripts/{id}: the list row plus the body and the last 50 runs, newest first. */
export interface ScriptDetail extends Script {
  body: string
  runs: ScriptRun[]
}
export interface CreateScript {
  name: string
  description?: string
  language?: string
  body: string
}
export interface UpdateScript {
  name?: string
  description?: string
  body?: string
}
export interface AssignScript {
  target_kind: ScriptTargetKind
  /** "workstation" for `all`, the group name for `group`. */
  target: string
  mode: ScriptMode
}

// ---- portal (SPEC-portal) ------------------------------------------------------
export interface Tile {
  id: string
  kind: 'screen' | 'link'
  href: string
  category: string
  order: number
  icon: string
  title: string
  description: string
  public: boolean
  builtin: boolean
  requires: string
  grants: number
}
export interface Portal {
  signed_in: boolean
  tiles: Tile[]
}
export interface TileInput {
  id?: string
  title?: string
  description?: string
  href?: string
  category?: string
  icon?: string
  order?: number
  public?: boolean
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

/** POST /v1/admin/users/{id}/password: `current` is required when changing one's own. */
export interface PasswordChange {
  current?: string
  new: string
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
  /** The stream's opening frame: which build is serving, on every (re)connect. */
  onReady?: (info: { version: string }) => void
}

/** The single fetch interface both the HTTP client and the mock implement. */
export interface Api {
  catalog(locale: string): Promise<Catalog>
  brand(): Promise<Brand>
  login(req: LoginRequest): Promise<LoginResponse>
  session(): Promise<Session | null> // null on 401
  logout(): Promise<void>
  /** Public: whether the install still needs its first human administrator. */
  setupStatus(): Promise<SetupStatus>
  /** Creates the first administrator and signs them in (201 sets the session cookie). */
  setup(body: SetupRequest): Promise<LoginOK>
  /** Self-service passkey enrollment for the signed-in person. */
  passkeyRegisterBegin(): Promise<PasskeyCeremony<CreationOptionsJSON>>
  passkeyRegisterFinish(body: PasskeyRegisterFinish): Promise<Binding>
  /** Passkey sign-in; `{}` is a discoverable request (pass mediation "conditional" for autofill). */
  passkeyLoginBegin(body?: PasskeyLoginBegin): Promise<PasskeyCeremony<RequestOptionsJSON>>
  passkeyLoginFinish(body: PasskeyLoginFinish): Promise<LoginResponse>

  summary(): Promise<Summary>
  users(q?: string): Promise<List<User>>
  user(id: string): Promise<UserDetail>
  createUser(body: CreateUser): Promise<Principal>
  setUserState(id: string, state: string): Promise<void>
  enrollBinding(id: string, body: EnrollBinding): Promise<Binding>
  /** The tiles the caller may see; works without a session (public tiles only). */
  portal(): Promise<Portal>
  tiles(): Promise<List<Tile>>
  createTile(body: TileInput): Promise<Tile>
  updateTile(id: string, body: TileInput): Promise<Tile>
  deleteTile(id: string): Promise<void>
  /** Deputy self-update policy (system.read / policies.write). */
  deviceSettings(): Promise<DeviceSettings>
  setDeviceSettings(body: DeviceSettings): Promise<DeviceSettings>
  /** Marks one device, or every outdated one, to update to the core's version on its next heartbeat (devices.write). */
  markDeviceUpdate(id: string): Promise<void>
  markAllDeviceUpdates(): Promise<{ marked: number }>
  /** Explains a badge reading without storing it (any signed-in principal). */
  badgeRead(fields: Record<string, string>): Promise<BadgeReading>
  revokeBinding(id: string, bid: string): Promise<void>
  /** Self (with `current`) or admin reset (without). */
  changePassword(id: string, body: PasswordChange): Promise<void>
  /** Sets, changes (non-empty) or removes (empty) the PIN on a badge binding. */
  setPin(id: string, bid: string, pin: string): Promise<void>
  groups(q?: string): Promise<List<Group>>
  group(name: string): Promise<GroupDetail>
  createGroup(body: CreateGroup): Promise<Group>
  addMember(name: string, body: MemberChange): Promise<void>
  removeMember(name: string, body: MemberChange): Promise<void>
  grants(q?: string): Promise<List<Grant>>
  roles(): Promise<List<Role>>
  /** Resources and per-type permissions for the grant form's pickers (grants.read). */
  resources(): Promise<ResourceCatalog>
  /** Defines or redefines a role (roles.write). */
  upsertRole(body: Role): Promise<Role>
  /** Agents: admins see all (or one owner's); everyone else their own. */
  agents(owner?: string): Promise<List<Agent>>
  agent(id: string): Promise<AgentDetail>
  createAgent(body: CreateAgent): Promise<Agent>
  /** Issues a fresh token (shown once); any earlier token stops working. */
  agentToken(id: string): Promise<{ token: string; issued_at: string }>
  agentTokenRevoke(id: string): Promise<void>
  agentState(id: string, state: 'active' | 'suspended'): Promise<void>
  agentGrant(id: string, body: AgentGrant): Promise<Grant>
  agentGrantRevoke(id: string, gid: string): Promise<void>
  createGrant(body: CreateGrant): Promise<Grant>
  revokeGrant(id: string): Promise<void>
  devices(q?: string): Promise<List<Device>>
  enrollmentToken(resourceType: string, ttlSeconds: number): Promise<EnrollmentToken>
  /** Scripts in position order, without bodies (scripts.read). */
  scripts(): Promise<List<Script>>
  script(id: string): Promise<ScriptDetail>
  /** Writes need scripts.write and an AL2 session. Create and update answer with the script (body included). */
  createScript(body: CreateScript): Promise<Script & { body?: string }>
  /** The version increments when the body changes. */
  updateScript(id: string, body: UpdateScript): Promise<Script & { body?: string }>
  deleteScript(id: string): Promise<void>
  /** Positions follow the order of `ids`. */
  orderScripts(ids: string[]): Promise<void>
  assignScript(id: string, body: AssignScript): Promise<ScriptAssignment>
  unassignScript(id: string, aid: string): Promise<void>
  /** Run history, newest first; the detail already carries the last 50. */
  scriptRuns(id: string, limit?: number): Promise<{ items: ScriptRun[] }>
  audit(q?: AuditQuery): Promise<AuditPage>
  auditVerify(): Promise<AuditVerify>
  why(q: WhyQuery): Promise<Explanation>
  updates(): Promise<UpdateState>
  /** Fetches the channel now (POST /v1/admin/updates/check) and returns the fresh state. */
  checkUpdates(): Promise<UpdateState>
  applyUpdate(): Promise<UpdateState>
  system(): Promise<SystemInfo>
  plugins(): Promise<List<Plugin>>
  /** Certificate authorities and the trust bundle devices hold (system.read). */
  cas(): Promise<CAList>
  /** Adds a new CA alongside the current one (system.write); devices renew onto it by themselves. */
  rotateCA(): Promise<CA>
  /** Retires a non-newest CA; `ca.in_use` unless forced, `ca.last_active` for the only one. */
  retireCA(id: string, force: boolean): Promise<void>
  /** Cache state of the installer bundles the appliance serves (devices.read). */
  downloads(): Promise<Downloads>
  /** Cookie-authenticated GET for the bundle, used as a plain link with `download`. */
  downloadUrl(name: 'windows'): string
  authSettings(): Promise<AuthSettings>
  setAuthSettings(body: AuthSettingsUpdate): Promise<AuthSettings>
  /** Sign-in overrides by group (system.read). */
  authOverrides(): Promise<List<AuthOverride>>
  /** Creates or replaces the override for a group, by name (policies.write). */
  setAuthOverride(group: string, body: AuthOverrideUpdate): Promise<AuthOverride>
  deleteAuthOverride(group: string): Promise<void>

  /** Open the live stream. Returns a function that closes it. */
  stream(h: LiveHandlers, lastEventId: string | null): () => void
}
