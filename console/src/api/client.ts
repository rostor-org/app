import type {
  Api, ApiErrorBody, AuditPage, AuditQuery, AuditVerify, AuthSettings, Binding, Brand, Catalog, CreationOptionsJSON, Device,
  EnrollmentToken, Explanation, Grant, Group, GroupDetail, List, LiveHandlers,
  LoginRequest, LoginResponse, PasskeyCeremony, Plugin, Principal, RequestOptionsJSON, Session, Summary, SystemInfo, UpdateState,
  User, UserDetail, WhyQuery,
} from './types'

export class ApiError extends Error {
  constructor(public status: number, public body: ApiErrorBody) {
    super(body.message ?? body.code)
  }
}

const CSRF_HEADER: Record<string, string> = { 'X-Requested-With': 'rostor-console' }

export interface ClientOptions {
  base?: string
  onUnauthorized?: () => void
}

function qs(params: Record<string, string | number | undefined>): string {
  const u = new URLSearchParams()
  for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== '') u.set(k, String(v))
  const s = u.toString()
  return s ? `?${s}` : ''
}

export function createHttpApi(opts: ClientOptions = {}): Api {
  const base = opts.base ?? ''

  async function call<T>(method: string, path: string, body?: unknown, allow401 = false): Promise<T> {
    const headers: Record<string, string> = { Accept: 'application/json' }
    if (method !== 'GET') Object.assign(headers, CSRF_HEADER)
    if (body !== undefined) headers['Content-Type'] = 'application/json'
    const res = await fetch(base + path, {
      method, headers, credentials: 'same-origin',
      body: body === undefined ? undefined : JSON.stringify(body),
    })
    if (res.status === 401) {
      if (allow401) return null as T
      opts.onUnauthorized?.()
    }
    if (res.status === 204) return undefined as T
    const text = await res.text()
    let data: unknown = null
    if (text) {
      try { data = JSON.parse(text) } catch { data = null }
    }
    if (!res.ok) {
      const err = (data && typeof data === 'object' && 'code' in data)
        ? (data as ApiErrorBody)
        : { code: `http.${res.status}` }
      throw new ApiError(res.status, err)
    }
    return data as T
  }

  return {
    catalog: (locale) => call<Catalog>('GET', `/v1/catalog${qs({ locale })}`),
    brand: () => call<Brand>('GET', '/v1/brand'),
    login: (req: LoginRequest) => call<LoginResponse>('POST', '/v1/auth/login', req),
    session: () => call<Session | null>('GET', '/v1/auth/session', undefined, true),
    logout: () => call<void>('POST', '/v1/auth/logout'),
    passkeyRegisterBegin: () => call<PasskeyCeremony<CreationOptionsJSON>>('POST', '/v1/auth/passkeys/register/begin'),
    passkeyRegisterFinish: (body) => call<Binding>('POST', '/v1/auth/passkeys/register/finish', body),
    passkeyLoginBegin: (body = {}) => call<PasskeyCeremony<RequestOptionsJSON>>('POST', '/v1/auth/login/passkey/begin', body),
    passkeyLoginFinish: (body) => call<LoginResponse>('POST', '/v1/auth/login/passkey/finish', body),

    summary: () => call<Summary>('GET', '/v1/admin/summary'),
    users: (q) => call<List<User>>('GET', `/v1/admin/users${qs({ q })}`),
    user: (id) => call<UserDetail>('GET', `/v1/admin/users/${encodeURIComponent(id)}`),
    createUser: (body) => call<Principal>('POST', '/v1/admin/users', body),
    setUserState: (id, state) => call<void>('POST', `/v1/admin/users/${encodeURIComponent(id)}/state`, { state }),
    enrollBinding: (id, body) => call<Binding>('POST', `/v1/admin/users/${encodeURIComponent(id)}/bindings`, body),
    revokeBinding: (id, bid) => call<void>('DELETE', `/v1/admin/users/${encodeURIComponent(id)}/bindings/${encodeURIComponent(bid)}`),
    groups: (q) => call<List<Group>>('GET', `/v1/admin/groups${qs({ q })}`),
    group: (name) => call<GroupDetail>('GET', `/v1/admin/groups/${encodeURIComponent(name)}`),
    createGroup: (body) => call<Group>('POST', '/v1/admin/groups', body),
    addMember: (name, body) => call<void>('POST', `/v1/admin/groups/${encodeURIComponent(name)}/members`, body),
    removeMember: (name, body) => call<void>('DELETE', `/v1/admin/groups/${encodeURIComponent(name)}/members`, body),
    grants: (q) => call<List<Grant>>('GET', `/v1/admin/grants${qs({ q })}`),
    createGrant: (body) => call<Grant>('POST', '/v1/admin/grants', body),
    revokeGrant: (id) => call<void>('DELETE', `/v1/admin/grants/${encodeURIComponent(id)}`),
    devices: (q) => call<List<Device>>('GET', `/v1/admin/devices${qs({ q })}`),
    enrollmentToken: (resource_type, ttl_seconds) =>
      call<EnrollmentToken>('POST', '/v1/admin/enrollment-tokens', { resource_type, ttl_seconds }),
    audit: (q: AuditQuery = {}) => call<AuditPage>('GET', `/v1/admin/audit${qs({ limit: q.limit, before: q.before, q: q.q })}`),
    auditVerify: () => call<AuditVerify>('GET', '/v1/admin/audit/verify'),
    why: (q: WhyQuery) => call<Explanation>('GET', `/v1/admin/why${qs({ ...q })}`),
    updates: () => call<UpdateState>('GET', '/v1/admin/updates'),
    checkUpdates: () => call<UpdateState>('POST', '/v1/admin/updates/check'),
    applyUpdate: () => call<UpdateState>('POST', '/v1/admin/updates/apply'),
    system: () => call<SystemInfo>('GET', '/v1/admin/system'),
    plugins: () => call<List<Plugin>>('GET', '/v1/admin/plugins'),
    authSettings: () => call<AuthSettings>('GET', '/v1/admin/settings/auth'),
    setAuthSettings: (body) => call<AuthSettings>('PUT', '/v1/admin/settings/auth', body),

    stream: (h, lastEventId) => openStream(base + '/v1/events/stream', h, lastEventId, opts.onUnauthorized),
  }
}

// ---- SSE over fetch: lets us send Last-Event-ID, back off, and report state.

function openStream(url: string, h: LiveHandlers, lastId: string | null, onUnauthorized?: () => void): () => void {
  let closed = false
  let attempt = 0
  let ctrl: AbortController | null = null
  let timer: ReturnType<typeof setTimeout> | null = null

  async function connect() {
    if (closed) return
    ctrl = new AbortController()
    h.onState(attempt === 0 ? 'connecting' : 'reconnecting')
    try {
      const headers: Record<string, string> = { Accept: 'text/event-stream' }
      if (lastId) headers['Last-Event-ID'] = lastId
      const res = await fetch(url, { headers, credentials: 'same-origin', signal: ctrl.signal, cache: 'no-store' })
      if (res.status === 401) { onUnauthorized?.(); return }
      if (res.status === 403) { closed = true; h.onState('off'); return }
      if (!res.ok || !res.body) throw new Error(String(res.status))
      h.onState('connected')
      attempt = 0
      await readEvents(res.body, (id, type) => {
        if (id) lastId = id
        if (type) h.onEvent({ id: id ?? '', type })
      })
      if (closed) return
      throw new Error('eof')
    } catch (e) {
      if (closed || (e instanceof DOMException && e.name === 'AbortError')) return
      attempt++
      const delay = Math.min(30_000, 1000 * 2 ** Math.min(attempt, 5)) + Math.random() * 500
      h.onState('reconnecting')
      timer = setTimeout(connect, delay)
    }
  }

  void connect()
  return () => {
    closed = true
    if (timer) clearTimeout(timer)
    ctrl?.abort()
    h.onState('off')
  }
}

async function readEvents(body: ReadableStream<Uint8Array>, emit: (id: string | null, type: string | null) => void) {
  const reader = body.getReader()
  const dec = new TextDecoder()
  let buf = ''
  let id: string | null = null
  let type: string | null = null
  for (;;) {
    const { done, value } = await reader.read()
    if (done) return
    buf += dec.decode(value, { stream: true })
    let nl: number
    while ((nl = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, nl).replace(/\r$/, '')
      buf = buf.slice(nl + 1)
      if (line === '') {
        if (type) emit(id, type)
        type = null
        continue
      }
      if (line.startsWith(':')) continue // heartbeat comment
      const colon = line.indexOf(':')
      const field = colon < 0 ? line : line.slice(0, colon)
      const val = colon < 0 ? '' : line.slice(colon + 1).replace(/^ /, '')
      if (field === 'id') id = val
      else if (field === 'event') type = val
      // `data` is intentionally ignored: the console only invalidates by type.
    }
  }
}
