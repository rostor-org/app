import { useCallback, useEffect, useRef, useState, type FormEvent, type KeyboardEvent } from 'react'
import { Link, useNavigate, useParams } from 'react-router'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, ApiError, type Binding, type User } from '../api'
import { useT } from '../i18n/catalog'
import { useSession } from '../auth/session'
import { createPasskey, defaultPasskeyLabel, isCancelled, passkeysSupported } from '../auth/webauthn'
import { useFormat } from '../lib/format'
import { useToast } from '../components/Toast'
import { Drawer } from '../components/Drawer'
import { Field, SelectField } from '../components/Form'
import { IconCard, IconKey, IconPassword } from '../components/Icons'
import { Chips, Empty, ErrorNote, Head, Loading, RowButton, Stat, StatePill } from '../components/bits'
import { WhyChain } from '../components/WhyChain'

const invalidatePeople = ['users', 'user', 'summary', 'groups', 'group', 'why']

export function People() {
  const t = useT()
  const f = useFormat()
  const nav = useNavigate()
  const toast = useToast()
  const { can } = useSession()
  const { id } = useParams()
  const [q, setQ] = useState('')
  const [adding, setAdding] = useState(false)
  const summary = useQuery({ queryKey: ['summary'], queryFn: () => api.summary() })
  const users = useQuery({ queryKey: ['users', q], queryFn: () => api.users(q || undefined) })
  const close = useCallback(() => nav('/people'), [nav])
  const closeAdd = useCallback(() => setAdding(false), [])

  return (
    <section>
      <Head titleCode="ui.people.title" subCode="ui.people.subtitle">
        <button type="button" className="btn quiet" onClick={() => toast(t('ui.common.not_available'))}>{t('ui.people.import')}</button>
        {can('users.write') && <button type="button" className="btn primary" onClick={() => { nav('/people'); setAdding(true) }}>{t('ui.people.add')}</button>}
      </Head>
      <div className="strip">
        <Stat value={f.int(summary.data?.people.active)} labelCode="ui.people.stat.active" />
        <Stat value={f.int(summary.data?.people.suspended)} labelCode="ui.people.stat.suspended" />
        <Stat value={f.int(summary.data?.people.applicants)} labelCode="ui.people.stat.applicants" />
        <Stat value={f.int(summary.data?.people.service_accounts)} labelCode="ui.people.stat.service" />
      </div>
      <div className="search">
        <input type="search" value={q} onChange={(e) => setQ(e.target.value)} placeholder={t('ui.people.search')} aria-label={t('ui.people.search')} />
        {users.data && <span className="muted">{t('ui.common.showing', { shown: users.data.items.length, total: f.int(users.data.total) })}</span>}
      </div>
      <ErrorNote error={users.error} />
      <div className="tablewrap">
        <table>
          <thead><tr>
            <th>{t('ui.people.col.person')}</th><th>{t('ui.people.col.username')}</th><th>{t('ui.people.col.groups')}</th>
            <th>{t('ui.people.col.methods')}</th><th>{t('ui.people.col.state')}</th><th>{t('ui.people.col.last_sign_in')}</th>
          </tr></thead>
          <tbody>
            {users.isPending && <tr><td colSpan={6}><Loading /></td></tr>}
            {users.data?.items.length === 0 && <tr><td colSpan={6}><Empty /></td></tr>}
            {users.data?.items.map((u) => <PersonRow key={u.id} u={u} onOpen={() => { setAdding(false); nav(`/people/${encodeURIComponent(u.id)}`) }} />)}
          </tbody>
        </table>
      </div>
      <PersonDrawer id={adding ? undefined : id} onClose={close} />
      <NewPersonDrawer open={adding} onClose={closeAdd} />
    </section>
  )
}

function PersonRow({ u, onOpen }: { u: User; onOpen: () => void }) {
  const t = useT()
  const f = useFormat()
  return (
    <tr className="row" onClick={onOpen}>
      <td><RowButton onClick={onOpen}>{f.name(u.display_name, u.username)}</RowButton>{u.kind === 'service' && <> <span className="muted">{t('ui.common.service')}</span></>}</td>
      <td className="mono">{u.username}</td>
      <td><Chips items={u.groups.map((g) => g.name)} /></td>
      <td>{u.methods.length === 0 ? <span className="muted">{t('ui.people.methods_none')}</span>
        : u.methods.map((m, i) => <span key={i}>{i > 0 && ' '}<span className="al">{m.method}</span></span>)}</td>
      <td><StatePill family="ui.state" value={u.state} /></td>
      <td className={u.last_sign_in ? 'num' : 'muted'}>{u.last_sign_in ? `${f.relDay(u.last_sign_in.ts)} · ${u.last_sign_in.resource}` : t('ui.time.never')}</td>
    </tr>
  )
}

/** Create → optional password binding → optional group membership, then open the new person. */
function NewPersonDrawer({ open, onClose }: { open: boolean; onClose: () => void }) {
  const t = useT()
  const qc = useQueryClient()
  const nav = useNavigate()
  const toast = useToast()
  const [username, setUsername] = useState('')
  const [displayName, setDisplayName] = useState('')
  const [password, setPassword] = useState('')
  const [group, setGroup] = useState('')
  const groups = useQuery({ queryKey: ['groups', ''], queryFn: () => api.groups(), enabled: open })
  const create = useMutation({
    mutationFn: async () => {
      const p = await api.createUser({ username: username.trim(), display_name: { en: displayName.trim() || username.trim() } })
      if (password) await api.enrollBinding(p.id, { method: 'password', fields: { password } })
      if (group) await api.addMember(group, { member_kind: 'principal', member: p.username ?? username.trim() })
      return p
    },
    onSuccess: (p) => {
      for (const k of invalidatePeople) void qc.invalidateQueries({ queryKey: [k] })
      toast(t('ui.person.created_toast', { name: displayName.trim() || username.trim() }))
      setUsername(''); setDisplayName(''); setPassword(''); setGroup('')
      onClose()
      nav(`/people/${encodeURIComponent(p.id)}`)
    },
  })
  const submit = (e: FormEvent) => { e.preventDefault(); create.mutate() }
  return (
    <Drawer open={open} onClose={onClose} labelCode="ui.person.new_title" title={t('ui.person.new_title')}>
      <form onSubmit={submit}>
        <Field labelCode="ui.person.new_username" value={username} onChange={(e) => setUsername(e.target.value)} required autoComplete="off" autoCapitalize="none" spellCheck={false} />
        <Field labelCode="ui.person.new_display_name" value={displayName} onChange={(e) => setDisplayName(e.target.value)} autoComplete="off" />
        <Field labelCode="ui.person.new_password" hintCode="ui.person.new_password_hint" type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="new-password" minLength={8} />
        <SelectField labelCode="ui.person.new_group" value={group} onChange={(e) => setGroup(e.target.value)}
          options={[['', 'ui.person.new_group_none'], ...(groups.data?.items.map((g) => [g.name, undefined] as [string, undefined]) ?? [])]} />
        <ErrorNote error={create.error} />
        <div className="actions">
          <button type="submit" className="btn primary" disabled={create.isPending}>{t(create.isPending ? 'ui.common.working' : 'ui.person.create')}</button>
          <button type="button" className="btn quiet" onClick={onClose}>{t('ui.common.cancel')}</button>
        </div>
      </form>
    </Drawer>
  )
}

function PersonDrawer({ id, onClose }: { id: string | undefined; onClose: () => void }) {
  const t = useT()
  const f = useFormat()
  const qc = useQueryClient()
  const toast = useToast()
  const { can, session } = useSession()
  const open = !!id
  const user = useQuery({ queryKey: ['user', id], queryFn: () => api.user(id!), enabled: open })
  const u = user.data
  const groups = useQuery({ queryKey: ['groups', ''], queryFn: () => api.groups(), enabled: open && can('groups.write') })
  const [pw, setPw] = useState<string | null>(null) // null = form closed
  const [pk, setPk] = useState<string | null>(null) // passkey label; null = form closed
  const [badge, setBadge] = useState(false)
  const [pickGroup, setPickGroup] = useState('')
  const closeBadge = useCallback(() => setBadge(false), [])
  // Passkey registration is self-service (the API binds the signed-in person).
  // Badge registration and revocation are admin actions; the person's own row
  // offers them too (see the contract note on self-service).
  const isSelf = !!u && session?.principal.id === u.id
  const canCredentials = can('credentials.write') || isSelf
  const refresh = () => { for (const k of invalidatePeople) void qc.invalidateQueries({ queryKey: [k] }) }
  const name = u ? f.name(u.display_name, u.username) : (id ?? '')

  const setState = useMutation({
    mutationFn: (state: string) => api.setUserState(id!, state),
    onSuccess: (_d, state) => { toast(t(state === 'suspended' ? 'ui.person.suspended_toast' : 'ui.person.reactivated_toast')); refresh() },
  })
  const setPassword = useMutation({
    mutationFn: (password: string) => api.enrollBinding(id!, { method: 'password', fields: { password } }),
    onSuccess: () => { toast(t('ui.person.password_set_toast', { name })); setPw(null); refresh() },
  })
  const revoke = useMutation({
    mutationFn: (bid: string) => api.revokeBinding(id!, bid),
    onSuccess: () => { toast(t('ui.person.binding_revoked_toast')); refresh() },
  })
  // begin → browser ceremony → finish. A cancelled prompt is not an error.
  const addPasskey = useMutation({
    mutationFn: async (label: string) => {
      const c = await api.passkeyRegisterBegin()
      const response = await createPasskey(c.options)
      return api.passkeyRegisterFinish({ ceremony_id: c.ceremony_id, label: label.trim(), response })
    },
    onSuccess: (b) => { toast(t('ui.person.passkey_added_toast', { label: b.label })); setPk(null); refresh() },
  })
  const passkeyError = isCancelled(addPasskey.error) ? null : addPasskey.error
  const passkeysUnconfigured = errorCode(passkeyError) === 'auth.passkeys_unconfigured'
  const addGroup = useMutation({
    mutationFn: (group: string) => api.addMember(group, { member_kind: 'principal', member: u!.username }),
    onSuccess: (_d, group) => { toast(t('ui.person.group_added_toast', { group })); setPickGroup(''); refresh() },
  })
  const removeGroup = useMutation({
    mutationFn: (group: string) => api.removeMember(group, { member_kind: 'principal', member: u!.username }),
    onSuccess: (_d, group) => { toast(t('ui.person.group_removed_toast', { group })); refresh() },
  })

  // The detail body has no last_sign_in; fall back to the newest allowed sign-in in `recent`.
  const lastAllowed = u?.recent.find((r) => r.outcome === 'allow' && (r.action === 'verify' || r.action === 'session.create'))
  const lastResource = u?.last_sign_in?.resource ?? (lastAllowed && lastAllowed.target.type ? `${lastAllowed.target.type}:${lastAllowed.target.id}` : undefined)
  const [rt, rid] = lastResource && lastResource.includes(':') ? lastResource.split(/:(.*)/, 2) : [undefined, undefined]
  const action = rt === 'door' ? 'enter' : 'logon'
  const why = useQuery({
    queryKey: ['why', u?.username, action, rt, rid],
    queryFn: () => api.why({ principal: u!.username, action, resource_type: rt!, resource_id: rid! }),
    enabled: open && !!u && !!rt && !!rid && rt !== 'api' && rt !== 'principal' && can('authz.read'),
    staleTime: 30_000,
  })

  const suspended = u?.state === 'suspended'
  const candidateGroups = groups.data?.items.filter((g) => !u?.groups.some((m) => m.name === g.name)) ?? []
  const error = user.error ?? setState.error ?? setPassword.error ?? revoke.error ?? addGroup.error ?? removeGroup.error ?? passkeyError

  return (
    <>
    <Drawer open={open} onClose={onClose} labelCode="ui.person.details" title={name} subtitle={u ? `${f.shortId(u.id)} · ${u.username}` : undefined}>
      <ErrorNote error={error} />
      {passkeysUnconfigured && <p className="note">{t('ui.person.passkeys_unconfigured_hint')} <Link to="/system">{t('ui.person.passkeys_unconfigured_link')}</Link></p>}
      {user.isPending && <Loading />}
      {u && (
        <>
          <div className="actions">
            {can('users.write') && (
              <button type="button" className="btn" disabled={setState.isPending} onClick={() => setState.mutate(suspended ? 'active' : 'suspended')}>
                {t(suspended ? 'ui.person.reactivate' : 'ui.person.suspend')}
              </button>
            )}
            {can('credentials.write') && (
              <button type="button" className="btn" aria-expanded={pw !== null} onClick={() => { setPk(null); setPw(pw === null ? '' : null) }}>{t('ui.person.set_password')}</button>
            )}
            {isSelf && passkeysSupported() && (
              <button type="button" className="btn" aria-expanded={pk !== null} disabled={addPasskey.isPending}
                onClick={() => { setPw(null); addPasskey.reset(); setPk(pk === null ? defaultPasskeyLabel(t('ui.person.passkey_default_label')) : null) }}>{t('ui.person.add_passkey')}</button>
            )}
            {canCredentials && <button type="button" className="btn" onClick={() => setBadge(true)}>{t('ui.person.register_badge')}</button>}
            {can('credentials.write') && <button type="button" className="btn" onClick={() => toast(t('ui.common.not_available'))}>{t('ui.person.reset_password')}</button>}
          </div>
          {pw !== null && (
            <form className="inline" style={{ marginTop: 12 }} onSubmit={(e) => { e.preventDefault(); setPassword.mutate(pw) }}>
              <input className="input" type="password" value={pw} onChange={(e) => setPw(e.target.value)} minLength={8} required autoFocus autoComplete="new-password" aria-label={t('ui.person.new_password_label')} />
              <button type="submit" className="btn primary" disabled={setPassword.isPending}>{t(setPassword.isPending ? 'ui.common.working' : 'ui.common.save')}</button>
              <button type="button" className="btn quiet" onClick={() => setPw(null)}>{t('ui.common.cancel')}</button>
            </form>
          )}
          {pk !== null && (
            <form className="inline" style={{ marginTop: 12 }} onSubmit={(e) => { e.preventDefault(); addPasskey.mutate(pk) }}>
              <input className="input" value={pk} onChange={(e) => setPk(e.target.value)} required autoFocus autoComplete="off" aria-label={t('ui.person.passkey_label')} />
              <button type="submit" className="btn primary" disabled={addPasskey.isPending}>{t(addPasskey.isPending ? 'ui.person.passkey_prompting' : 'ui.person.add_passkey')}</button>
              <button type="button" className="btn quiet" onClick={() => { setPk(null); addPasskey.reset() }}>{t('ui.common.cancel')}</button>
            </form>
          )}
          <dl className="kv">
            <dt>{t('ui.person.state')}</dt><dd><StatePill family="ui.state" value={u.state} /></dd>
            <dt>{t('ui.person.username')}</dt><dd className="mono">{u.username}</dd>
            <dt>{t('ui.person.groups')}</dt>
            <dd>
              <div className="chips">
                {u.groups.length === 0 && !can('groups.write') && <span className="chip muted">{t('ui.common.none')}</span>}
                {u.groups.map((g) => (
                  <span key={g.id} className="chip">{g.name}
                    {can('groups.write') && <button type="button" aria-label={t('ui.person.remove_from_group', { group: g.name })} disabled={removeGroup.isPending}
                      onClick={() => { if (confirm(t('ui.common.confirm_remove_member', { member: u.username, group: g.name }))) removeGroup.mutate(g.name) }}>×</button>}
                  </span>
                ))}
              </div>
              {can('groups.write') && candidateGroups.length > 0 && (
                <form className="inline" style={{ marginTop: 8 }} onSubmit={(e) => { e.preventDefault(); if (pickGroup) addGroup.mutate(pickGroup) }}>
                  <select className="input" value={pickGroup} onChange={(e) => setPickGroup(e.target.value)} aria-label={t('ui.person.add_to_group')}>
                    <option value="">{t('ui.person.add_to_group')}</option>
                    {candidateGroups.map((g) => <option key={g.id} value={g.name}>{g.name}</option>)}
                  </select>
                  <button type="submit" className="btn" disabled={!pickGroup || addGroup.isPending}>{t('ui.common.add')}</button>
                </form>
              )}
            </dd>
            <dt>{t('ui.person.security')}</dt>
            <dd><span className="al">{u.effective_security.assurance}</span> <span className="muted">· {t('ui.person.security_summary', { bindings: u.effective_security.bindings, recovery: u.effective_security.recovery_paths })}</span></dd>
          </dl>
          <div className="section">
            <h3>{t('ui.person.methods')}</h3>
            <div className="list">
              {u.bindings.length === 0 && <div><span className="muted">{t('ui.person.methods_empty')}</span></div>}
              {byMethod(u.bindings).map((b) => (
                <div key={b.id}>
                  <span className="method">
                    <MethodGlyph method={b.method} />
                    <span><b>{b.label || methodName(t, b.method)}</b><br />
                      <span className="muted">{t('ui.person.binding_meta', { properties: methodName(t, b.method), created: f.relDay(b.created_at), used: f.relDay(b.last_used_at) })}</span></span>
                  </span>
                  <span className="actions">
                    <span className="al">{b.state === 'active' ? (b.assurance ?? u.effective_security.assurance) : t(`ui.state.${b.state}`)}</span>
                    {canCredentials && b.state === 'active' && (
                      <button type="button" className="btn quiet danger" disabled={revoke.isPending}
                        onClick={() => { if (confirm(t('ui.common.confirm_revoke', { what: b.label || methodName(t, b.method) }))) revoke.mutate(b.id) }}>{t('ui.person.revoke')}</button>
                    )}
                  </span>
                </div>
              ))}
            </div>
          </div>
          {why.data && (
            <div className="section">
              <h3>{t('ui.person.why_title', { name: name.split(' ')[0], resource: rid })}</h3>
              <WhyChain ex={why.data} />
            </div>
          )}
          <div className="section">
            <h3>{t('ui.person.recent')}</h3>
            <div className="list">
              {u.recent.length === 0 && <div><span className="muted">{t('ui.person.recent_empty')}</span></div>}
              {u.recent.map((r) => (
                <div key={r.seq}>
                  <span>{r.action} · <span className="mono">{r.target.type}:{r.target.id}</span>{r.outcome !== 'ok' && <> · {t(`ui.audit.outcome.${r.outcome}`)}</>}{typeof r.detail?.reason === 'string' && <span className="muted"> · {r.detail.reason}</span>}</span>
                  <span className="muted num">{f.relDay(r.ts)}</span>
                </div>
              ))}
            </div>
          </div>
        </>
      )}
    </Drawer>
    <BadgeDrawer open={badge && !!u} id={u?.id ?? ''} name={name} onClose={closeBadge} onDone={refresh} />
    </>
  )
}

/** The API error code behind a failure, from the HTTP client or the mock. */
function errorCode(err: unknown): string | undefined {
  if (err instanceof ApiError) return err.body.code
  if (err && typeof err === 'object' && 'body' in err) return (err as { body?: { code?: string } }).body?.code
  return undefined
}

// Passkeys first, then badges, passwords, and everything else, keeping the
// server's order within a method.
const METHOD_ORDER = ['webauthn', 'badge', 'password']
const KNOWN_METHODS = new Set([...METHOD_ORDER, 'api_token'])
function byMethod(bs: Binding[]): Binding[] {
  const rank = (m: string) => { const i = METHOD_ORDER.indexOf(m); return i < 0 ? METHOD_ORDER.length : i }
  return [...bs].sort((a, b) => rank(a.method) - rank(b.method))
}
function methodName(t: (code: string) => string, method: string): string {
  return KNOWN_METHODS.has(method) ? t(`ui.method.${method}`) : method
}
function MethodGlyph({ method }: { method: string }) {
  return <span className="glyph">{method === 'webauthn' ? <IconKey /> : method === 'badge' ? <IconCard /> : <IconPassword />}</span>
}

/**
 * Register a badge. The number field takes a keyboard-wedge burst: the reader
 * types the card as digits and finishes with Enter, which moves on to the PIN
 * instead of submitting. Typing the number by hand works the same way.
 */
function BadgeDrawer({ open, id, name, onClose, onDone }: { open: boolean; id: string; name: string; onClose: () => void; onDone: () => void }) {
  const t = useT()
  const toast = useToast()
  const [number, setNumber] = useState('')
  const [pin, setPin] = useState('')
  const [pin2, setPin2] = useState('')
  const [label, setLabel] = useState('')
  const [mismatch, setMismatch] = useState(false)
  const numRef = useRef<HTMLInputElement>(null)
  const pinRef = useRef<HTMLInputElement>(null)
  // The Drawer takes focus when it opens; hand it to the reader field so a card can be presented at once.
  useEffect(() => { if (open) numRef.current?.focus() }, [open])
  const enroll = useMutation({
    mutationFn: () => api.enrollBinding(id, { method: 'badge', label: label.trim(), fields: pin ? { number: number.trim(), pin } : { number: number.trim() } }),
    onSuccess: (b) => { toast(t('ui.badge.registered_toast', { label: b.label, name })); close(); onDone() },
  })
  const close = () => { setNumber(''); setPin(''); setPin2(''); setLabel(''); setMismatch(false); enroll.reset(); onClose() }
  const onNumberKey = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key !== 'Enter') return
    e.preventDefault()
    if (number.trim()) pinRef.current?.focus()
  }
  const submit = (e: FormEvent) => {
    e.preventDefault()
    if (pin !== pin2) { setMismatch(true); return }
    setMismatch(false)
    enroll.mutate()
  }
  return (
    <Drawer open={open} onClose={close} labelCode="ui.badge.title" title={t('ui.badge.title')} subtitle={name}>
      <form onSubmit={submit}>
        <p className="note">{t('ui.badge.reader_note')}</p>
        <Field labelCode="ui.badge.number" hintCode="ui.badge.number_hint" value={number} onChange={(e) => setNumber(e.target.value)} onKeyDown={onNumberKey}
          required autoComplete="off" autoCapitalize="none" spellCheck={false} inputMode="numeric" className="input mono" ref={numRef} />
        <Field labelCode="ui.badge.pin" hintCode="ui.badge.pin_hint" type="password" value={pin} onChange={(e) => setPin(e.target.value)}
          inputMode="numeric" pattern="[0-9]{4,}" autoComplete="off" ref={pinRef} />
        <Field labelCode="ui.badge.pin_confirm" type="password" value={pin2} onChange={(e) => setPin2(e.target.value)} inputMode="numeric" autoComplete="off" required={pin !== ''} />
        <Field labelCode="ui.badge.label" hintCode="ui.badge.label_hint" value={label} onChange={(e) => setLabel(e.target.value)} autoComplete="off" />
        {mismatch && <p className="form-error" role="alert">{t('ui.badge.pin_mismatch')}</p>}
        <ErrorNote error={enroll.error} />
        <div className="actions">
          <button type="submit" className="btn primary" disabled={enroll.isPending || !number.trim()}>{t(enroll.isPending ? 'ui.common.working' : 'ui.badge.register')}</button>
          <button type="button" className="btn quiet" onClick={close}>{t('ui.common.cancel')}</button>
        </div>
      </form>
    </Drawer>
  )
}
