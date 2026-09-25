import { useCallback, useEffect, useId, useRef, useState, type FormEvent } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, type AuthSettings, type BadgeFormat, type CA, type DefaultProvider, type LoginMethod, type SystemInfo } from '../api'
import { TilesCard } from '../components/TilesCard'
import { useT } from '../i18n/catalog'
import { useSession } from '../auth/session'
import { useFormat } from '../lib/format'
import { loadedVersion, reloadApp, setAutoReloading } from '../lib/version'
import { setTheme, storedTheme, type Theme } from '../lib/theme'
import { useToast } from '../components/Toast'
import { Drawer } from '../components/Drawer'
import { apiBody, describeError, ErrorNote, Head, Loading, Pill } from '../components/bits'

const ROTATE_WORD = 'ROTATE'
const RETIRE_WORD = 'RETIRE'

export function System() {
  const t = useT()
  const f = useFormat()
  const qc = useQueryClient()
  const toast = useToast()
  const { can } = useSession()
  const sys = useQuery({ queryKey: ['system'], queryFn: () => api.system() })
  const upd = useQuery({ queryKey: ['updates'], queryFn: () => api.updates(), enabled: can('updates.read') })
  const u = upd.data

  // "Check now" asks the server to fetch the channel (POST /v1/admin/updates/check); report what changed.
  const check = useMutation({
    mutationFn: () => api.checkUpdates(),
    onSuccess: (s) => {
      qc.setQueryData(['updates'], s)
      toast(s.available ? t('ui.updates.available_toast', { version: s.available }) : t('ui.updates.none_toast'))
    },
  })
  // After apply the core restarts on the new build: poll GET /v1/admin/system
  // every 2 s (errors are the restart), and once the version differs from the
  // one this page loaded with, say so and reload. Gives up after 3 minutes.
  const [pollSince, setPollSince] = useState<number | null>(null)
  const apply = useMutation({
    mutationFn: () => api.applyUpdate(),
    onSuccess: (s) => {
      qc.setQueryData(['updates'], s)
      toast(t('ui.updates.requested_toast', { version: s.available ?? '' }))
      setAutoReloading(true)
      setPollSince(Date.now())
    },
  })
  useEffect(() => {
    if (pollSince === null) return
    let done = false
    const tick = async () => {
      if (done) return
      if (Date.now() - pollSince > 180_000) { done = true; setPollSince(null); return }
      try {
        const s = await api.system()
        if (done) return
        qc.setQueryData(['system'], s)
        const from = loadedVersion()
        if (from && s.version !== from) {
          done = true
          setPollSince(null)
          toast(t('ui.updates.reloading_toast', { version: s.version }))
          setTimeout(reloadApp, 1200)
        }
      } catch { /* the core is restarting */ }
    }
    const id = setInterval(() => void tick(), 2000)
    return () => {
      clearInterval(id)
      // Leaving the screen (or timing out) hands the notice back to the shell banner.
      if (!done) setAutoReloading(false)
      done = true
    }
  }, [pollSince, qc, t, toast])

  // Poll while an apply is in flight (SSE update.state also invalidates).
  const installing = !!u?.apply_requested
  const prevInstalling = useRef(false)
  useEffect(() => {
    if (!installing) return
    const id = setInterval(() => void qc.invalidateQueries({ queryKey: ['updates'] }), 3000)
    return () => clearInterval(id)
  }, [installing, qc])
  useEffect(() => {
    if (prevInstalling.current && !installing) void qc.invalidateQueries({ queryKey: ['system'] })
    prevInstalling.current = installing
  }, [installing, qc])

  const waiting = pollSince !== null && !installing
  const state = installing ? 'installing' : u?.available ? 'available' : 'up_to_date'
  const pillTone = state === 'installing' ? 'pending' : state === 'available' ? 'pending' : 'active'
  const pillLabel = state === 'installing' ? t('ui.updates.installing', { version: u?.available ?? '' })
    : state === 'available' ? t('ui.updates.available', { version: u?.available ?? '' }) : t('ui.updates.up_to_date')

  return (
    <section>
      <Head titleCode="ui.system.title" subCode="ui.system.subtitle" />
      <ErrorNote error={sys.error ?? upd.error ?? check.error ?? apply.error} />
      <div className="cards">
        <div className="card">
          <h3>{t('ui.system.software')}</h3>
          {u && <p>{t('ui.system.channel', { channel: u.channel, time: f.relDay(u.checked_at) })}</p>}
          <div className="row">
            <span className="ver">{u?.current ?? sys.data?.version ?? ''}</span>
            {u && <Pill value={pillTone} label={pillLabel} />}
          </div>
          <div className={installing || waiting ? 'progress busy' : 'progress'} aria-hidden="true"><i /></div>
          {u?.last_error && <p className="error" style={{ marginTop: 8 }}>{t('ui.updates.error', { error: u.last_error })}</p>}
          <div className="row">
            <span className="muted">{waiting ? t('ui.updates.waiting', { version: u?.available ?? u?.current ?? '' }) : u?.notes ?? ''}</span>
            <span className="actions">
              {can('updates.read') && <button type="button" className="btn" disabled={check.isPending || installing} onClick={() => check.mutate()}>{t(check.isPending ? 'ui.updates.checking' : 'ui.updates.check')}</button>}
              {can('updates.write') && u?.available && !installing && (
                <button type="button" className="btn primary" disabled={apply.isPending} onClick={() => apply.mutate()}>{t('ui.updates.install', { version: u.available })}</button>
              )}
            </span>
          </div>
        </div>
        <div className="card">
          <h3>{t('ui.system.appliance')}</h3>
          {sys.data && (
            <dl className="kv">
              <dt>{t('ui.system.tenant')}</dt><dd>{sys.data.tenant.name} <span className="mono muted">{sys.data.tenant.id}</span></dd>
              {listeners(sys.data).map((l, i) => <Listener key={i} name={l.name} addr={l.addr} />)}
              <dt>{t('ui.system.database')}</dt><dd>{sys.data.db.engine ? `${sys.data.db.engine} · ` : ''}{f.bytes(sys.data.db.size_bytes)}</dd>
              <dt>{t('ui.system.uptime')}</dt><dd className="num">{f.duration(sys.data.uptime_seconds)}</dd>
            </dl>
          )}
        </div>
        <KeysCard sys={sys.data} canRead={can('system.read')} canWrite={can('system.write')} />
        <div className="card">
          <h3>{t('ui.system.profile')}</h3>
          {sys.data && <p><b>{t(`ui.system.profile.${sys.data.profile}`)}</b></p>}
        </div>
        {can('system.read') && <SignInSettings canWrite={can('policies.write')} />}
        <OrganisationCard canWrite={can('system.write')} />
        <AppearanceCard />
        <TilesCard canWrite={can('system.write')} />
      </div>
    </section>
  )
}

/** This browser's console theme (see lib/theme). Dark unless light is chosen here. */
/** The organisation's name: the console header, the sign-in page, the portal, passkey prompts and the workstation tiles all show it. */
function OrganisationCard({ canWrite }: { canWrite: boolean }) {
  const t = useT()
  const id = useId()
  const qc = useQueryClient()
  const toast = useToast()
  const q = useQuery({ queryKey: ['organisation'], queryFn: () => api.organisation() })
  const [name, setName] = useState<string | null>(null)
  const cur = name ?? q.data?.name ?? ''
  const save = useMutation({
    mutationFn: (n: string) => api.setOrganisation(n),
    onSuccess: (r) => { setName(null); for (const k of ['organisation', 'brand', 'system', 'device-settings']) void qc.invalidateQueries({ queryKey: [k] }); toast(t('ui.system.organisation_saved_toast', { name: r.name })) },
  })
  return (
    <div className="card">
      <h3>{t('ui.system.organisation')}</h3>
      <ErrorNote error={q.error ?? save.error} />
      <form onSubmit={(e) => { e.preventDefault(); if (cur.trim()) save.mutate(cur.trim()) }}>
        <div className="field">
          <label htmlFor={id}>{t('ui.system.organisation_name')}</label>
          <input id={id} className="input" value={cur} onChange={(e) => setName(e.target.value)} maxLength={80} readOnly={!canWrite} autoComplete="organization" />
          <small className="muted">{t('ui.system.organisation_hint')}</small>
        </div>
        {canWrite && (
          <div className="actions">
            <button type="submit" className="btn primary" disabled={save.isPending || name === null || !cur.trim() || cur.trim() === q.data?.name}>{t(save.isPending ? 'ui.common.working' : 'ui.common.save')}</button>
          </div>
        )}
      </form>
    </div>
  )
}

function AppearanceCard() {
  const t = useT()
  const id = useId()
  const [theme, setLocal] = useState<Theme>(storedTheme)
  return (
    <div className="card">
      <h3>{t('ui.system.appearance')}</h3>
      <div className="field">
        <label htmlFor={id}>{t('ui.system.theme')}</label>
        <select id={id} className="input" value={theme} onChange={(e) => { const v = e.target.value as Theme; setLocal(v); setTheme(v) }}>
          <option value="dark">{t('ui.system.theme.dark')}</option>
          <option value="light">{t('ui.system.theme.light')}</option>
        </select>
        <small className="muted">{t('ui.system.theme_hint')}</small>
      </div>
    </div>
  )
}

/**
 * Tenant sign-in settings: the WebAuthn relying party. Changing the domain
 * orphans every passkey registered under the old one, so with passkeys
 * enrolled the new domain must be typed back to confirm.
 */
function SignInSettings({ canWrite }: { canWrite: boolean }) {
  const t = useT()
  const f = useFormat()
  const qc = useQueryClient()
  const toast = useToast()
  const ids = { rp: useId(), name: useId(), origins: useId(), confirm: useId(), method: useId(), badge: useId(), provider: useId() }
  const q = useQuery({ queryKey: ['auth-settings'], queryFn: () => api.authSettings() })
  const [form, setForm] = useState<{ rp_id: string; display_name: string; origins: string; default_method: LoginMethod; badge_format: BadgeFormat; default_provider: DefaultProvider } | null>(null)
  const [confirm, setConfirm] = useState('')
  const saved = q.data?.webauthn
  // Edit a copy; the query stays the source of truth until save.
  const cur = form ?? (saved ? { rp_id: saved.rp_id, display_name: saved.display_name, origins: (saved.origins ?? []).join('\n'), default_method: q.data?.login?.default_method ?? 'password', badge_format: q.data?.badge?.format ?? 'none', default_provider: q.data?.logon?.default_provider ?? 'rostor' } : null)
  const enrolled = saved?.enrolled_passkeys ?? 0
  const rpChanged = !!saved && !!cur && cur.rp_id.trim().toLowerCase() !== saved.rp_id
  const needConfirm = rpChanged && enrolled > 0
  const dirty = !!saved && !!cur && (rpChanged || cur.display_name !== saved.display_name || cur.origins !== (saved.origins ?? []).join('\n') || cur.default_method !== (q.data?.login?.default_method ?? 'password') || cur.badge_format !== (q.data?.badge?.format ?? 'none') || cur.default_provider !== (q.data?.logon?.default_provider ?? 'rostor'))
  // Type the new domain back; when the domain is being cleared, the old one.
  const confirmWord = (cur?.rp_id.trim().toLowerCase() || saved?.rp_id) ?? ''
  const confirmed = !needConfirm || confirm.trim().toLowerCase() === confirmWord

  const save = useMutation({
    mutationFn: (body: AuthSettings['webauthn'] & { default_method: LoginMethod; badge_format: BadgeFormat; default_provider: DefaultProvider }) => api.setAuthSettings({ webauthn: { rp_id: body.rp_id, display_name: body.display_name, origins: body.origins }, login: { default_method: body.default_method }, badge: { format: body.badge_format }, logon: { default_provider: body.default_provider } }),
    onSuccess: (s) => { qc.setQueryData(['auth-settings'], s); setForm(null); setConfirm(''); toast(t('ui.signin.saved_toast')) },
  })
  const submit = (e: FormEvent) => {
    e.preventDefault()
    if (!cur || !confirmed) return
    save.mutate({ rp_id: cur.rp_id.trim().toLowerCase(), display_name: cur.display_name.trim(), origins: cur.origins.split(/\r?\n/).map((o) => o.trim()).filter(Boolean), enrolled_passkeys: enrolled, default_method: cur.default_method, badge_format: cur.badge_format, default_provider: cur.default_provider })
  }
  const set = (k: 'rp_id' | 'display_name' | 'origins' | 'default_method' | 'badge_format' | 'default_provider') => (e: { target: { value: string } }) => { if (cur) setForm({ ...cur, [k]: e.target.value }) }

  return (
    <div className="card">
      <h3>{t('ui.signin.title')}</h3>
      <p>{t('ui.signin.note')}</p>
      <ErrorNote error={q.error ?? save.error} />
      {cur && (
        <form onSubmit={submit}>
          <div className="field">
            <label htmlFor={ids.rp}>{t('ui.signin.rp_id')}</label>
            <input id={ids.rp} className="input mono" value={cur.rp_id} onChange={set('rp_id')} readOnly={!canWrite} autoComplete="off" autoCapitalize="none" spellCheck={false} />
            <small className="muted">{t('ui.signin.rp_id_hint')}</small>
          </div>
          <div className="field">
            <label htmlFor={ids.name}>{t('ui.signin.display_name')}</label>
            <input id={ids.name} className="input" value={cur.display_name} onChange={set('display_name')} readOnly={!canWrite} autoComplete="off" />
          </div>
          <div className="field">
            <label htmlFor={ids.origins}>{t('ui.signin.origins')}</label>
            <textarea id={ids.origins} className="input mono" rows={3} value={cur.origins} onChange={set('origins')} readOnly={!canWrite} spellCheck={false} />
            <small className="muted">{t('ui.signin.origins_hint')}</small>
          </div>
          <div className="field">
            <label htmlFor={ids.method}>{t('ui.signin.default_method')}</label>
            <select id={ids.method} className="input" value={cur.default_method} onChange={set('default_method')} disabled={!canWrite}>
              <option value="password">{t('ui.method.password')}</option>
              <option value="passkey">{t('ui.method.webauthn')}</option>
              <option value="badge">{t('ui.method.badge')}</option>
            </select>
            <small className="muted">{t('ui.signin.default_method_hint')}</small>
          </div>
          <div className="field">
            <label htmlFor={ids.badge}>{t('ui.signin.badge_format')}</label>
            <select id={ids.badge} className="input" value={cur.badge_format} onChange={set('badge_format')} disabled={!canWrite}>
              <option value="none">{t('ui.signin.badge_format.none')}</option>
              <option value="wiegand26">{t('ui.signin.badge_format.wiegand26')}</option>
            </select>
            <small className="muted">{t('ui.signin.badge_format_hint')}</small>
          </div>
          <div className="field">
            <label htmlFor={ids.provider}>{t('ui.signin.default_provider')}</label>
            <select id={ids.provider} className="input" value={cur.default_provider} onChange={set('default_provider')} disabled={!canWrite}>
              <option value="rostor">{t('ui.signin.default_provider.rostor')}</option>
              <option value="windows">{t('ui.signin.default_provider.windows')}</option>
            </select>
            <small className="muted">{t('ui.signin.default_provider_hint')}</small>
          </div>
          {needConfirm && (
            <div className="field">
              <p className="form-error" role="alert">{t('ui.signin.rp_id_warning', { n: f.int(enrolled) })}</p>
              <label htmlFor={ids.confirm} style={{ marginTop: 10 }}>{t('ui.signin.rp_id_confirm', { rp_id: confirmWord })}</label>
              <input id={ids.confirm} className="input mono" value={confirm} onChange={(e) => setConfirm(e.target.value)} autoComplete="off" autoCapitalize="none" spellCheck={false} />
            </div>
          )}
          <div className="row">
            <span className="muted">{t('ui.signin.enrolled', { n: f.int(enrolled) })}</span>
            {canWrite && (
              <span className="actions">
                {dirty && <button type="button" className="btn quiet" disabled={save.isPending} onClick={() => { setForm(null); setConfirm('') }}>{t('ui.common.cancel')}</button>}
                <button type="submit" className="btn primary" disabled={!dirty || !confirmed || save.isPending}>{t(save.isPending ? 'ui.common.working' : 'ui.common.save')}</button>
              </span>
            )}
          </div>
        </form>
      )}
      <SignInOverrides canWrite={canWrite} />
    </div>
  )
}

const METHOD_LABEL: Record<LoginMethod, string> = { password: 'ui.method.password', passkey: 'ui.method.webauthn', badge: 'ui.method.badge' }
const METHODS: LoginMethod[] = ['password', 'passkey', 'badge']

/**
 * Sign-in overrides by group: login.default_method per group, for people and
 * for devices in it (GET/PUT/DELETE /v1/admin/settings/auth/overrides). Each
 * change saves at once; nothing here is part of the settings form above.
 */
function SignInOverrides({ canWrite }: { canWrite: boolean }) {
  const t = useT()
  const qc = useQueryClient()
  const toast = useToast()
  const ids = { group: useId(), method: useId() }
  const list = useQuery({ queryKey: ['auth-overrides'], queryFn: () => api.authOverrides() })
  const groups = useQuery({ queryKey: ['groups', ''], queryFn: () => api.groups(), enabled: canWrite, staleTime: 60_000 })
  const [group, setGroup] = useState('')
  const [method, setMethod] = useState<LoginMethod | ''>('badge')
  const [account, setAccount] = useState('')
  const [provider, setProvider] = useState<DefaultProvider | ''>('')
  const refresh = () => { void qc.invalidateQueries({ queryKey: ['auth-overrides'] }); void qc.invalidateQueries({ queryKey: ['audit'] }) }
  const add = useMutation({
    mutationFn: (v: { group: string; method: LoginMethod | ''; account: string; provider: DefaultProvider | '' }) => api.setAuthOverride(v.group, {
      ...(v.method ? { login: { default_method: v.method } } : {}),
      ...(v.account.trim() || v.provider ? { logon: { ...(v.account.trim() ? { session_account: v.account.trim().toLowerCase() } : {}), ...(v.provider ? { default_provider: v.provider } : {}) } } : {}),
    }),
    onSuccess: (o) => { refresh(); setGroup(''); setAccount(''); toast(t('ui.signin.overrides.added_toast', { group: o.group.name, method: o.login.default_method ? t(METHOD_LABEL[o.login.default_method]) : t('ui.signin.overrides.method_default') })) },
  })
  const remove = useMutation({
    mutationFn: (name: string) => api.deleteAuthOverride(name),
    onSuccess: (_, name) => { refresh(); toast(t('ui.signin.overrides.removed_toast', { group: name })) },
  })
  const items = list.data?.items ?? []
  const taken = new Set(items.map((o) => o.group.name))
  const available = (groups.data?.items ?? []).filter((g) => !taken.has(g.name))
  const submit = (e: FormEvent) => { e.preventDefault(); if (group && (method || account.trim() || provider)) add.mutate({ group, method, account, provider }) }
  return (
    <div style={{ marginTop: 18 }}>
      <b>{t('ui.signin.overrides.title')}</b>
      <p className="muted" style={{ marginTop: 4 }}>{t('ui.signin.overrides.hint')}</p>
      <ErrorNote error={list.error ?? groups.error ?? add.error ?? remove.error} />
      {list.isPending && <Loading />}
      {!list.isPending && items.length === 0 && <p className="muted">{t('ui.signin.overrides.empty')}</p>}
      {items.length > 0 && (
        <ul className="list">
          {items.map((o) => (
            <li key={o.group.id} className="inline">
              <span><b>{o.group.name}</b> <span className="muted">→</span> {o.login.default_method ? t(METHOD_LABEL[o.login.default_method]) : t('ui.signin.overrides.method_default')}
                {o.logon?.session_account && <> <span className="muted">·</span> {t('ui.signin.overrides.as_account', { account: o.logon.session_account })}</>}
                {o.logon?.default_provider && <> <span className="muted">·</span> {t(`ui.signin.default_provider.${o.logon.default_provider}`)}</>}</span>
              {canWrite && (
                <span className="actions">
                  <button type="button" className="btn quiet danger" disabled={remove.isPending} onClick={() => remove.mutate(o.group.name)}>{t('ui.common.remove')}</button>
                </span>
              )}
            </li>
          ))}
        </ul>
      )}
      {canWrite && (
        <form className="inline" onSubmit={submit} style={{ marginTop: 10 }}>
          <select id={ids.group} className="input" aria-label={t('ui.signin.overrides.group')} value={group} onChange={(e) => setGroup(e.target.value)} disabled={add.isPending}>
            <option value="">{t('ui.signin.overrides.choose_group')}</option>
            {available.map((g) => <option key={g.id} value={g.name}>{g.name}</option>)}
          </select>
          <select id={ids.method} className="input" aria-label={t('ui.signin.overrides.method')} value={method} onChange={(e) => setMethod(e.target.value as LoginMethod | '')} disabled={add.isPending}>
            <option value="">{t('ui.signin.overrides.method_default')}</option>
            {METHODS.map((m) => <option key={m} value={m}>{t(METHOD_LABEL[m])}</option>)}
          </select>
          <input className="input mono" aria-label={t('ui.signin.overrides.session_account')} placeholder={t('ui.signin.overrides.session_account')} value={account} onChange={(e) => setAccount(e.target.value)} maxLength={20} autoComplete="off" autoCapitalize="none" spellCheck={false} disabled={add.isPending} />
          <select className="input" aria-label={t('ui.signin.default_provider')} value={provider} onChange={(e) => setProvider(e.target.value as DefaultProvider | '')} disabled={add.isPending}>
            <option value="">{t('ui.signin.overrides.provider_default')}</option>
            <option value="rostor">{t('ui.signin.default_provider.rostor')}</option>
            <option value="windows">{t('ui.signin.default_provider.windows')}</option>
          </select>
          <button type="submit" className="btn" disabled={!group || (!method && !account.trim() && !provider) || add.isPending}>{t(add.isPending ? 'ui.common.working' : 'ui.common.add')}</button>
        </form>
      )}
    </div>
  )
}

/**
 * Keys: the tenant CAs devices trust (GET /v1/admin/ca), the pinned release
 * key and the snapshot key. Rotation adds a CA alongside the current one;
 * devices renew onto it by themselves; the old one is retired by hand.
 */
function KeysCard({ sys, canRead, canWrite }: { sys: SystemInfo | undefined; canRead: boolean; canWrite: boolean }) {
  const t = useT()
  const f = useFormat()
  const qc = useQueryClient()
  const toast = useToast()
  const cas = useQuery({ queryKey: ['ca'], queryFn: () => api.cas(), enabled: canRead })
  const [rotating, setRotating] = useState(false)
  const closeRotate = useCallback(() => setRotating(false), [])
  // A refused retirement (ca.in_use) stays on the row with the server's message and the forced path.
  const [inUse, setInUse] = useState<{ id: string; message: string } | null>(null)
  const [retireWord, setRetireWord] = useState('')
  const retire = useMutation({
    mutationFn: ({ id, force }: { id: string; force: boolean }) => api.retireCA(id, force),
    onSuccess: () => { setInUse(null); setRetireWord(''); void qc.invalidateQueries({ queryKey: ['ca'] }); void qc.invalidateQueries({ queryKey: ['devices'] }); toast(t('ui.ca.retired_toast')) },
    onError: (e, v) => { if (apiBody(e)?.code === 'ca.in_use') setInUse({ id: v.id, message: describeError(e, t) }) },
  })
  const retireError = apiBody(retire.error)?.code === 'ca.in_use' ? null : retire.error
  const d = cas.data
  return (
    <div className="card">
      <h3>{t('ui.system.keys')}</h3>
      {d && <p>{t('ui.ca.header', { version: d.trust_version, n: f.int(d.devices.total - d.devices.on_older_bundle), m: f.int(d.devices.total) })}</p>}
      <ErrorNote error={cas.error ?? retireError} />
      {d && (
        <div className="list calist">
          {d.items.length === 0 && <div><span className="muted">{t('ui.ca.empty')}</span></div>}
          {d.items.map((ca) => (
            <div key={ca.id}>
              <div className="ca">
                <b>
                  {ca.subject}
                  {ca.newest && <Pill value="active" label={t('ui.ca.newest')} />}
                  {ca.retired_at && <Pill value="revoked" label={t('ui.ca.retired')} />}
                </b>
                <div className="meta">
                  <span className="mono" title={ca.fingerprint}>{f.fingerprint(ca.fingerprint)}</span>
                  <span className="num">{t('ui.ca.created', { date: f.date(ca.created_at) })}</span>
                  <span className="num">{t('ui.ca.expires', { date: f.date(ca.not_after) })}</span>
                  <span className="num">{t('ui.ca.devices', { n: f.int(ca.devices) })}</span>
                </div>
              </div>
              {canWrite && !ca.newest && !ca.retired_at && (
                <button type="button" className="btn danger" disabled={retire.isPending} onClick={() => { setInUse(null); setRetireWord(''); retire.mutate({ id: ca.id, force: false }) }}>{t('ui.ca.retire')}</button>
              )}
              {inUse?.id === ca.id && (
                <div className="retirewarn subform">
                  <p className="form-error" role="alert" style={{ marginTop: 0 }}>{inUse.message}</p>
                  <p className="muted" style={{ marginTop: 8 }}>{t('ui.ca.retire_force_note')}</p>
                  <div className="field">
                    <label htmlFor={`retire-${ca.id}`}>{t('ui.ca.retire_confirm', { word: RETIRE_WORD })}</label>
                    <input id={`retire-${ca.id}`} className="input mono" value={retireWord} onChange={(e) => setRetireWord(e.target.value)} autoComplete="off" autoCapitalize="characters" spellCheck={false} />
                  </div>
                  <div className="actions">
                    <button type="button" className="btn danger" disabled={retireWord.trim() !== RETIRE_WORD || retire.isPending} onClick={() => retire.mutate({ id: ca.id, force: true })}>{t(retire.isPending ? 'ui.common.working' : 'ui.ca.retire_anyway')}</button>
                    <button type="button" className="btn quiet" onClick={() => { setInUse(null); setRetireWord('') }}>{t('ui.common.cancel')}</button>
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      )}
      {!canRead && sys && <dl className="kv"><dt>{t('ui.system.tenant_ca')}</dt><dd>{sys.ca.subject}</dd></dl>}
      {sys && (
        <dl className="kv">
          <dt>{t('ui.system.release_key')}</dt><dd className="mono">{f.fingerprint(sys.release_key_fingerprint)} · {t('ui.system.pinned')}</dd>
          <dt>{t('ui.system.snapshot_key')}</dt><dd><span className="muted">{t('ui.system.not_issued')}</span></dd>
        </dl>
      )}
      {canWrite && <div className="row"><span /><button type="button" className="btn" onClick={() => setRotating(true)}>{t('ui.ca.rotate')}</button></div>}
      <RotateDrawer open={rotating} onClose={closeRotate} />
    </div>
  )
}

/** Typed confirmation for POST /v1/admin/ca/rotate, explaining the three steps. */
function RotateDrawer({ open, onClose }: { open: boolean; onClose: () => void }) {
  const t = useT()
  const qc = useQueryClient()
  const toast = useToast()
  const id = useId()
  const [word, setWord] = useState('')
  const rotate = useMutation({
    mutationFn: () => api.rotateCA(),
    onSuccess: (ca: CA) => {
      void qc.invalidateQueries({ queryKey: ['ca'] }); void qc.invalidateQueries({ queryKey: ['devices'] })
      toast(t('ui.ca.rotated_toast', { subject: ca.subject })); setWord(''); onClose()
    },
  })
  const close = () => { setWord(''); rotate.reset(); onClose() }
  const submit = (e: FormEvent) => { e.preventDefault(); if (word.trim() === ROTATE_WORD) rotate.mutate() }
  return (
    <Drawer open={open} onClose={close} labelCode="ui.ca.rotate_title" title={t('ui.ca.rotate_title')}>
      <form onSubmit={submit}>
        <p className="note">{t('ui.ca.rotate_intro')}</p>
        <ol className="steps">
          <li>{t('ui.ca.rotate_step1')}</li>
          <li>{t('ui.ca.rotate_step2')}</li>
          <li>{t('ui.ca.rotate_step3')}</li>
        </ol>
        <div className="field">
          <label htmlFor={id}>{t('ui.ca.rotate_confirm', { word: ROTATE_WORD })}</label>
          <input id={id} className="input mono" value={word} onChange={(e) => setWord(e.target.value)} autoComplete="off" autoCapitalize="characters" spellCheck={false} />
        </div>
        <ErrorNote error={rotate.error} />
        <div className="actions">
          <button type="submit" className="btn primary" disabled={word.trim() !== ROTATE_WORD || rotate.isPending}>{t(rotate.isPending ? 'ui.common.working' : 'ui.ca.rotate_submit')}</button>
          <button type="button" className="btn quiet" onClick={close}>{t('ui.common.cancel')}</button>
        </div>
      </form>
    </Drawer>
  )
}

function Listener({ name, addr }: { name?: string; addr: string }) {
  const t = useT()
  return <><dt>{name ?? t('ui.system.listener')}</dt><dd className="mono">{addr}</dd></>
}

function listeners(s: SystemInfo): Array<{ name?: string; addr: string }> {
  return (s.listeners ?? []).map((l) => (typeof l === 'string' ? { addr: l } : l))
}
