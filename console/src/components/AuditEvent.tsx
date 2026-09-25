import { useState, type ReactNode } from 'react'
import type { AuditRow } from '../api'
import { useT } from '../i18n/catalog'
import { useFormat } from '../lib/format'
import { Pill } from './bits'

// Audit rows lead with names (actor.name, target.name, detail.principal_name
// from the server, v0.3.0) and keep ids for hover and the expanded detail.

/** The person an event was about, when it was not the actor: verify rows name the principal in `detail`. */
export function subjectName(r: AuditRow): string | null {
  const d = r.detail
  const n = typeof d?.principal_name === 'string' ? d.principal_name : typeof d?.identifier === 'string' ? d.identifier : null
  if (!n) return null
  // The target already names the person, or the actor is the person: nothing to add.
  if (r.target.type === 'principal' || r.target.type === 'user') return null
  const pid = typeof d?.principal_id === 'string' ? d.principal_id : null
  if (pid && pid === r.actor.id) return null
  if (n === r.actor.name || n === r.actor.id) return null
  return n
}

export function actorName(r: AuditRow): string {
  return r.actor.name ?? r.actor.id
}

/** Target as "<type> <name>", the id only on hover (or when there is no name). */
export function TargetRef({ r }: { r: AuditRow }) {
  const ref = `${r.target.type}:${r.target.id}`
  return (
    <span className="target" title={ref}>
      {r.target.type && <span className="muted">{r.target.type}</span>}{r.target.type && ' '}
      {r.target.name ?? (r.target.id ? <span className="mono">{r.target.id}</span> : null)}
    </span>
  )
}

export function Actor({ r }: { r: AuditRow }) {
  const t = useT()
  const subject = subjectName(r)
  return (
    <>
      <b title={`${r.actor.kind}:${r.actor.id}`}>{actorName(r)}</b>
      {r.actor.kind === 'agent' && r.actor.owner_name && <span className="muted"> · {t('ui.audit.agent_of', { name: r.actor.owner_name })}</span>}
      {subject && <span className="muted"> · {t('ui.audit.for', { name: subject })}</span>}
    </>
  )
}

/** One row of the audit log; click (or Enter) expands the raw ids and detail. */
export function AuditEvent({ r, fresh }: { r: AuditRow; fresh: boolean }) {
  const t = useT()
  const f = useFormat()
  const [open, setOpen] = useState(false)
  const reason = typeof r.detail?.reason === 'string' ? r.detail.reason : null
  const outcome = t(`ui.audit.outcome.${r.outcome}`)
  const toggle = () => setOpen((o) => !o)
  return (
    <>
      <div className={`ev${fresh ? ' new' : ''}${open ? ' open' : ''}`} role="button" tabIndex={0} aria-expanded={open}
        onClick={toggle} onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); toggle() } }}>
        <span className="t">{f.clock(r.ts)}</span>
        <span className="mono action">{r.action}</span>
        <span className="what">
          <Actor r={r} />
          {' · '}<TargetRef r={r} />
          {r.credential_type && <span className="muted"> · {r.credential_type}</span>}
          {r.assurance && <> · <span className="al">{r.assurance}</span></>}
        </span>
        <Pill value={r.outcome} className="outcome" label={reason ? `${outcome} · ${reason}` : outcome} />
      </div>
      {open && (
        <div className="evdetail">
          <dl>
            <Item label={t('ui.audit.detail.seq')}>{r.seq}</Item>
            <Item label={t('ui.audit.detail.time')}>{r.ts}</Item>
            <Item label={t('ui.audit.detail.actor')}>{r.actor.kind}:{r.actor.id}</Item>
            <Item label={t('ui.audit.detail.target')}>{r.target.type}:{r.target.id}</Item>
            {r.correlation_id && <Item label={t('ui.audit.detail.correlation')}>{r.correlation_id}</Item>}
          </dl>
          <pre>{r.detail ? JSON.stringify(r.detail, null, 2) : t('ui.common.none')}</pre>
        </div>
      )}
    </>
  )
}

function Item({ label, children }: { label: string; children: ReactNode }) {
  return <><dt>{label}</dt><dd className="mono">{children}</dd></>
}
