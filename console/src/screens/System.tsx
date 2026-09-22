import { useEffect, useRef } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, type SystemInfo } from '../api'
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

  // "Check now" is a refetch of GET /v1/admin/updates; report what changed.
  const check = useMutation({
    mutationFn: () => api.updates(),
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
      </div>
    </section>
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
