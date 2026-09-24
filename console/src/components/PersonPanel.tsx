import { useCallback, useEffect, useRef, useState, type FormEvent, type KeyboardEvent } from 'react'
import { Link } from 'react-router'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, ApiError, type Binding, type UserDetail } from '../api'
import { useT } from '../i18n/catalog'
import { useSession } from '../auth/session'
import { createPasskey, defaultPasskeyLabel, isCancelled, passkeysSupported } from '../auth/webauthn'
import { useFormat } from '../lib/format'
import { useToast } from './Toast'
import { Drawer } from './Drawer'
import { Field } from './Form'
import { IconCard, IconKey, IconPassword } from './Icons'
import { ErrorNote, Loading, StatePill } from './bits'
import { WhyChain } from './WhyChain'
import { TargetRef, actorName, subjectName } from './AuditEvent'

export const invalidatePeople = ['users', 'user', 'summary', 'groups', 'group', 'why']

type PasswordForm = { current: string; next: string; confirm: string }
const emptyPassword: PasswordForm = { current: '', next: '', confirm: '' }

/**
 * A person's record: identity, groups (direct vs inherited), sign-in methods
 * with self-service actions, recent activity. Rendered inside the People
 * drawer for admins and as the My account page for everyone (`page`).
 */
export function PersonPanel({ id, page = false }: { id: string; page?: boolean }) {
  const t = useT()
  const f = useFormat()
  const qc = useQueryClient()
  const toast = useToast()
  const { can, session } = useSession()
  const user = useQuery({ queryKey: ['user', id], queryFn: () => api.user(id) })
  const u = user.data
  const groups = useQuery({ queryKey: ['groups', ''], queryFn: () => api.groups(), enabled: can('groups.write') })
  const [pw, setPw] = useState<string | null>(null) // admin "set password" (enroll); null = form closed
  const [chg, setChg] = useState<PasswordForm | null>(null) // change (self) / reset (admin); null = closed
  const [pk, setPk] = useState<string | null>(null) // passkey label; null = form closed
  const [pinFor, setPinFor] = useState<{ bid: string; pin: string; confirm: string } | null>(null)
  const [badge, setBadge] = useState(false)
  const [pickGroup, setPickGroup] = useState('')
  const [formError, setFormError] = useState<string | null>(null)
  const closeBadge = useCallback(() => setBadge(false), [])
  // Passkey registration is self-service (the API binds the signed-in person).
  // Badge registration, PINs and revocation are admin actions that the
  // person's own row offers too (the contract's self-service rule).
  const isSelf = !!u && session?.principal.id === u.id
  const canCredentials = can('credentials.write') || isSelf
  const refresh = () => { for (const k of invalidatePeople) void qc.invalidateQueries({ queryKey: [k] }) }
  const name = u ? f.name(u.display_name, u.username) : id
  const closeForms = () => { setPw(null); setChg(null); setPk(null); setPinFor(null); setFormError(null) }

  const setState = useMutation({
    mutationFn: (state: string) => api.setUserState(id, state),
    onSuccess: (_d, state) => { toast(t(state === 'suspended' ? 'ui.person.suspended_toast' : 'ui.person.reactivated_toast')); refresh() },
  })
  const setPassword = useMutation({
    mutationFn: (password: string) => api.enrollBinding(id, { method: 'password', fields: { password } }),
    onSuccess: () => { toast(t('ui.person.password_set_toast', { name })); setPw(null); refresh() },
  })
  const changePassword = useMutation({
    mutationFn: (form: PasswordForm) => api.changePassword(id, isSelf ? { current: form.current, new: form.next } : { new: form.next }),
    onSuccess: () => { toast(t(isSelf ? 'ui.person.password_changed_toast' : 'ui.person.password_reset_toast', { name })); setChg(null); refresh() },
  })
  const setPin = useMutation({
    mutationFn: ({ bid, pin }: { bid: string; pin: string }) => api.setPin(id, bid, pin),
    onSuccess: (_d, { pin }) => { toast(t(pin ? 'ui.person.pin_set_toast' : 'ui.person.pin_removed_toast')); setPinFor(null); refresh() },
  })
  const revoke = useMutation({
    mutationFn: (bid: string) => api.revokeBinding(id, bid),
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
    enabled: !!u && !!rt && !!rid && rt !== 'api' && rt !== 'principal' && can('authz.read'),
    staleTime: 30_000,
  })

  const suspended = u?.state === 'suspended'
  const hasPassword = !!u?.bindings.some((b) => b.method === 'password' && b.state === 'active')
  const candidateGroups = groups.data?.items.filter((g) => !u?.groups.some((m) => m.name === g.name)) ?? []
  const error = user.error ?? setState.error ?? setPassword.error ?? changePassword.error ?? setPin.error ?? revoke.error ?? addGroup.error ?? removeGroup.error ?? passkeyError

  const submitChange = (e: FormEvent) => {
    e.preventDefault()
    if (!chg) return
    if (chg.next !== chg.confirm) { setFormError('ui.person.password_mismatch'); return }
    setFormError(null)
    changePassword.mutate(chg)
  }
  const submitPin = (e: FormEvent) => {
    e.preventDefault()
    if (!pinFor) return
    if (pinFor.pin !== pinFor.confirm) { setFormError('ui.badge.pin_mismatch'); return }
    setFormError(null)
    setPin.mutate({ bid: pinFor.bid, pin: pinFor.pin })
  }
  const removePin = (b: Binding) => {
    if (confirm(t('ui.person.confirm_remove_pin', { what: b.label || methodName(t, b.method) }))) setPin.mutate({ bid: b.id, pin: '' })
  }

  return (
    <>
      <ErrorNote error={error} />
      {formError && <p className="form-error" role="alert">{t(formError)}</p>}
      {passkeysUnconfigured && <p className="note">{t('ui.person.passkeys_unconfigured_hint')} {can('system.read') && <Link to="/system">{t('ui.person.passkeys_unconfigured_link')}</Link>}</p>}
      {user.isPending && <Loading />}
      {u && (
        <>
          {page && (
            <div className="identity">
              <span className="avatar big" aria-hidden="true">{initials(name)}</span>
              <div><h2>{name}</h2><div className="muted mono">{u.username} · {f.shortId(u.id)}</div></div>
            </div>
          )}
          <div className="actions">
            {can('users.write') && !isSelf && (
              <button type="button" className="btn" disabled={setState.isPending} onClick={() => setState.mutate(suspended ? 'active' : 'suspended')}>
                {t(suspended ? 'ui.person.reactivate' : 'ui.person.suspend')}
              </button>
            )}
            {isSelf && (
              <button type="button" className="btn" aria-expanded={chg !== null} onClick={() => { const open = chg === null; closeForms(); if (open) setChg(emptyPassword) }}>{t('ui.person.change_password')}</button>
            )}
            {!isSelf && can('credentials.write') && !hasPassword && (
              <button type="button" className="btn" aria-expanded={pw !== null} onClick={() => { const open = pw === null; closeForms(); if (open) setPw('') }}>{t('ui.person.set_password')}</button>
            )}
            {!isSelf && can('credentials.write') && hasPassword && (
              <button type="button" className="btn" aria-expanded={chg !== null} onClick={() => { const open = chg === null; closeForms(); if (open) setChg(emptyPassword) }}>{t('ui.person.reset_password')}</button>
            )}
            {isSelf && passkeysSupported() && (
              <button type="button" className="btn" aria-expanded={pk !== null} disabled={addPasskey.isPending}
                onClick={() => { const open = pk === null; closeForms(); addPasskey.reset(); if (open) setPk(defaultPasskeyLabel(t('ui.person.passkey_default_label'))) }}>{t('ui.person.add_passkey')}</button>
            )}
            {canCredentials && <button type="button" className="btn" onClick={() => setBadge(true)}>{t('ui.person.register_badge')}</button>}
          </div>
          {pw !== null && (
            <form className="inline" style={{ marginTop: 12 }} onSubmit={(e) => { e.preventDefault(); setPassword.mutate(pw) }}>
              <input className="input" type="password" value={pw} onChange={(e) => setPw(e.target.value)} minLength={8} required autoFocus autoComplete="new-password" aria-label={t('ui.person.new_password_label')} />
              <button type="submit" className="btn primary" disabled={setPassword.isPending}>{t(setPassword.isPending ? 'ui.common.working' : 'ui.common.save')}</button>
              <button type="button" className="btn quiet" onClick={() => setPw(null)}>{t('ui.common.cancel')}</button>
            </form>
          )}
          {chg !== null && (
            <form className="subform" onSubmit={submitChange}>
              {isSelf && <Field labelCode="ui.person.current_password" type="password" value={chg.current} onChange={(e) => setChg({ ...chg, current: e.target.value })} required autoFocus autoComplete="current-password" />}
              <Field labelCode="ui.person.new_password_label" hintCode="ui.person.new_password_rule" type="password" value={chg.next} onChange={(e) => setChg({ ...chg, next: e.target.value })} minLength={8} required autoFocus={!isSelf} autoComplete="new-password" />
              <Field labelCode="ui.person.confirm_password" type="password" value={chg.confirm} onChange={(e) => setChg({ ...chg, confirm: e.target.value })} required autoComplete="new-password" />
              {!isSelf && <p className="note">{t('ui.person.reset_password_note', { name })}</p>}
              <div className="actions">
                <button type="submit" className="btn primary" disabled={changePassword.isPending}>{t(changePassword.isPending ? 'ui.common.working' : isSelf ? 'ui.person.change_password' : 'ui.person.reset_password')}</button>
                <button type="button" className="btn quiet" onClick={() => { setChg(null); setFormError(null) }}>{t('ui.common.cancel')}</button>
              </div>
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
            {!page && <><dt>{t('ui.person.username')}</dt><dd className="mono">{u.username}</dd></>}
            <dt>{t('ui.person.groups')}</dt>
            <dd>
              <GroupChips u={u} canEdit={can('groups.write')} busy={removeGroup.isPending}
                onRemove={(g) => { if (confirm(t('ui.common.confirm_remove_member', { member: u.username, group: g }))) removeGroup.mutate(g) }} />
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
              {byMethod(u.bindings).map((b) => {
                const hasPin = b.method === 'badge' && b.properties.includes('knowledge')
                const pinOpen = pinFor?.bid === b.id
                return (
                  <div key={b.id} className="binding">
                    <div className="bindrow">
                      <span className="method">
                        <MethodGlyph method={b.method} />
                        <span><b>{b.label || methodName(t, b.method)}</b><br />
                          <span className="muted">{t('ui.person.binding_meta', { properties: methodName(t, b.method), created: f.relDay(b.created_at), used: f.relDay(b.last_used_at) })}</span></span>
                      </span>
                      <span className="actions">
                        <span className="al">{b.state === 'active' ? (b.assurance ?? u.effective_security.assurance) : t(`ui.state.${b.state}`)}</span>
                        {canCredentials && b.state === 'active' && b.method === 'badge' && (
                          <>
                            <button type="button" className="btn quiet" aria-expanded={pinOpen} disabled={setPin.isPending}
                              onClick={() => { const open = !pinOpen; closeForms(); if (open) setPinFor({ bid: b.id, pin: '', confirm: '' }) }}>{t(hasPin ? 'ui.person.change_pin' : 'ui.person.set_pin')}</button>
                            {hasPin && <button type="button" className="btn quiet" disabled={setPin.isPending} onClick={() => removePin(b)}>{t('ui.person.remove_pin')}</button>}
                          </>
                        )}
                        {canCredentials && b.state === 'active' && (
                          <button type="button" className="btn quiet danger" disabled={revoke.isPending}
                            onClick={() => { if (confirm(t('ui.common.confirm_revoke', { what: b.label || methodName(t, b.method) }))) revoke.mutate(b.id) }}>{t('ui.person.revoke')}</button>
                        )}
                      </span>
                    </div>
                    {pinOpen && pinFor && (
                      <form className="inline pinform" onSubmit={submitPin}>
                        <input className="input" type="password" value={pinFor.pin} onChange={(e) => setPinFor({ ...pinFor, pin: e.target.value })} inputMode="numeric" pattern="[0-9]{4,}" required autoFocus autoComplete="off" aria-label={t('ui.person.pin_label')} placeholder={t('ui.person.pin_label')} />
                        <input className="input" type="password" value={pinFor.confirm} onChange={(e) => setPinFor({ ...pinFor, confirm: e.target.value })} inputMode="numeric" required autoComplete="off" aria-label={t('ui.badge.pin_confirm')} placeholder={t('ui.badge.pin_confirm')} />
                        <button type="submit" className="btn primary" disabled={setPin.isPending}>{t(setPin.isPending ? 'ui.common.working' : 'ui.common.save')}</button>
                        <button type="button" className="btn quiet" onClick={() => { setPinFor(null); setFormError(null) }}>{t('ui.common.cancel')}</button>
                        <small className="muted">{t('ui.badge.pin_hint')}</small>
                      </form>
                    )}
                  </div>
                )
              })}
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
              {u.recent.map((r) => {
                const subject = subjectName(r)
                const byOther = r.actor.id !== u.id
                return (
                  <div key={r.seq}>
                    <span className="what">
                      <span className="mono">{r.action}</span> · <TargetRef r={r} />
                      {byOther && <span className="muted" title={`${r.actor.kind}:${r.actor.id}`}> · {t('ui.audit.by', { name: actorName(r) })}</span>}
                      {subject && subject !== u.username && subject !== name && <span className="muted"> · {t('ui.audit.for', { name: subject })}</span>}
                      {r.outcome !== 'ok' && <> · {t(`ui.audit.outcome.${r.outcome}`)}</>}{typeof r.detail?.reason === 'string' && <span className="muted"> · {r.detail.reason}</span>}
                    </span>
                    <span className="muted num">{f.relDay(r.ts)}</span>
                  </div>
                )
              })}
            </div>
          </div>
        </>
      )}
      <BadgeDrawer open={badge && !!u} id={u?.id ?? ''} name={name} onClose={closeBadge} onDone={refresh} />
    </>
  )
}

/** Group chips: direct memberships are plain (and removable); inherited ones are dashed, marked "via". */
function GroupChips({ u, canEdit, busy, onRemove }: { u: UserDetail; canEdit: boolean; busy: boolean; onRemove: (group: string) => void }) {
  const t = useT()
  return (
    <div className="chips">
      {u.groups.length === 0 && !canEdit && <span className="chip muted">{t('ui.common.none')}</span>}
      {u.groups.map((g) => g.direct === false ? (
        <span key={g.id} className="chip via" title={t('ui.person.group_inherited')}>{g.name}<small>{t('ui.person.via')}</small></span>
      ) : (
        <span key={g.id} className="chip">{g.name}
          {canEdit && <button type="button" aria-label={t('ui.person.remove_from_group', { group: g.name })} disabled={busy} onClick={() => onRemove(g.name)}>×</button>}
        </span>
      ))}
    </div>
  )
}

function initials(name: string): string {
  return name.split(/\s+/).map((s) => s[0] ?? '').join('').slice(0, 2)
}

/** The API error code behind a failure, from the HTTP client or the mock. */
export function errorCode(err: unknown): string | undefined {
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
export function BadgeDrawer({ open, id, name, onClose, onDone }: { open: boolean; id: string; name: string; onClose: () => void; onDone: () => void }) {
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
