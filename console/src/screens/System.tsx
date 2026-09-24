import { useEffect, useId, useRef, useState, type FormEvent } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, type AuthSettings, type SystemInfo } from '../api'
import { useT } from '../i18n/catalog'
import { useSession } from '../auth/session'
import { useFormat } from '../lib/format'
import { useToast } from '../components/Toast'
import { ErrorNote, Head, Pill } from '../components/bits'

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
  const apply = useMutation({
    mutationFn: () => api.applyUpdate(),
    onSuccess: (s) => { qc.setQueryData(['updates'], s); toast(t('ui.updates.requested_toast', { version: s.available ?? '' })) },
  })

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
          <div className={installing ? 'progress busy' : 'progress'} aria-hidden="true"><i /></div>
          {u?.last_error && <p className="error" style={{ marginTop: 8 }}>{t('ui.updates.error', { error: u.last_error })}</p>}
          <div className="row">
            <span className="muted">{u?.notes ?? ''}</span>
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
        <div className="card">
          <h3>{t('ui.system.keys')}</h3>
          {sys.data && (
            <dl className="kv">
              <dt>{t('ui.system.tenant_ca')}</dt><dd>{t('ui.system.ca_exp', { subject: sys.data.ca.subject, date: f.date(sys.data.ca.not_after) })}</dd>
              <dt>{t('ui.system.release_key')}</dt><dd className="mono">{fp(sys.data.release_key_fingerprint)} · {t('ui.system.pinned')}</dd>
              <dt>{t('ui.system.snapshot_key')}</dt><dd><span className="muted">{t('ui.system.not_issued')}</span></dd>
            </dl>
          )}
          <div className="row"><span className="muted">{t('ui.system.rotation_note')}</span><button type="button" className="btn" onClick={() => toast(t('ui.common.not_available'))}>{t('ui.system.rotate')}</button></div>
        </div>
        <div className="card">
          <h3>{t('ui.system.profile')}</h3>
          {sys.data && <p><b>{t(`ui.system.profile.${sys.data.profile}`)}</b></p>}
        </div>
        {can('system.read') && <SignInSettings canWrite={can('policies.write')} />}
      </div>
    </section>
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
  const ids = { rp: useId(), name: useId(), origins: useId(), confirm: useId() }
  const q = useQuery({ queryKey: ['auth-settings'], queryFn: () => api.authSettings() })
  const [form, setForm] = useState<{ rp_id: string; display_name: string; origins: string } | null>(null)
  const [confirm, setConfirm] = useState('')
  const saved = q.data?.webauthn
  // Edit a copy; the query stays the source of truth until save.
  const cur = form ?? (saved ? { rp_id: saved.rp_id, display_name: saved.display_name, origins: saved.origins.join('\n') } : null)
  const enrolled = saved?.enrolled_passkeys ?? 0
  const rpChanged = !!saved && !!cur && cur.rp_id.trim().toLowerCase() !== saved.rp_id
  const needConfirm = rpChanged && enrolled > 0
  const dirty = !!saved && !!cur && (rpChanged || cur.display_name !== saved.display_name || cur.origins !== saved.origins.join('\n'))
  // Type the new domain back; when the domain is being cleared, the old one.
  const confirmWord = (cur?.rp_id.trim().toLowerCase() || saved?.rp_id) ?? ''
  const confirmed = !needConfirm || confirm.trim().toLowerCase() === confirmWord

  const save = useMutation({
    mutationFn: (body: AuthSettings['webauthn']) => api.setAuthSettings({ webauthn: { rp_id: body.rp_id, display_name: body.display_name, origins: body.origins } }),
    onSuccess: (s) => { qc.setQueryData(['auth-settings'], s); setForm(null); setConfirm(''); toast(t('ui.signin.saved_toast')) },
  })
  const submit = (e: FormEvent) => {
    e.preventDefault()
    if (!cur || !confirmed) return
    save.mutate({ rp_id: cur.rp_id.trim().toLowerCase(), display_name: cur.display_name.trim(), origins: cur.origins.split(/\r?\n/).map((o) => o.trim()).filter(Boolean), enrolled_passkeys: enrolled })
  }
  const set = (k: 'rp_id' | 'display_name' | 'origins') => (e: { target: { value: string } }) => { if (cur) setForm({ ...cur, [k]: e.target.value }) }

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
    </div>
  )
}

function Listener({ name, addr }: { name?: string; addr: string }) {
  const t = useT()
  return <><dt>{name ?? t('ui.system.listener')}</dt><dd className="mono">{addr}</dd></>
}

function listeners(s: SystemInfo): Array<{ name?: string; addr: string }> {
  return (s.listeners ?? []).map((l) => (typeof l === 'string' ? { addr: l } : l))
}

function fp(s: string): string {
  return s.length > 16 ? `${s.slice(0, 8)}…${s.slice(-4)}` : s
}
