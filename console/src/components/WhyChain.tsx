import type { Explanation, Reason } from '../api'
import { useT, type Params } from '../i18n/catalog'
import { useFormat } from '../lib/format'
import { Pill } from './bits'

interface Step {
  key: string
  ok: boolean | null // true ok, false first failing, null neutral
  text: string
  note?: string
}

function reasonText(t: ReturnType<typeof useT>, r: Reason): string {
  return r.message ?? t(r.code, r.params as Params)
}

/** Renders a `GET /v1/admin/why` explanation as the mockup's numbered chain. */
export function WhyChain({ ex }: { ex: Explanation }) {
  const t = useT()
  const f = useFormat()
  const steps: Step[] = []
  const reasons = ex.reason ?? []
  const candidates = ex.candidates ?? []
  const stateFail = reasons.find((r) => r.code.startsWith('principal.'))
  const failingCode = reasons.find((r) => r.code !== 'grant.matched')

  if (stateFail) {
    steps.push({ key: 'state', ok: false, text: reasonText(t, stateFail), note: t('ui.why.suspension_note') })
    const n = candidates.length
    steps.push({ key: 'skipped', ok: null, text: t('ui.why.grants_not_considered'), note: n ? t('ui.why.candidates_note', { n }) : undefined })
  } else {
    steps.push({ key: 'state', ok: true, text: t('ui.why.not_suspended'), note: t('ui.why.suspension_note') })
    for (const [group, path] of Object.entries(ex.groups ?? {})) {
      steps.push({ key: `g:${group}`, ok: true, text: t('ui.why.member_of', { principal: ex.principal, group }), note: t('ui.why.member_path', { path: path.join(' → ') }) })
    }
    const matched = candidates.find((c) => c.matched) ?? candidates[0]
    for (const c of candidates) {
      const g = c.grant
      const resource = `${g.resource_type}:${g.resource_id}`
      const isMain = c === matched
      steps.push({
        key: `c:${g.id}`, ok: isMain ? true : null,
        text: t('ui.why.grant_step', { via: c.via, role: g.role, resource }),
        note: isMain ? t('ui.why.grant_meta', { id: g.id }) : t('ui.why.grant_skipped', { id: g.id }),
      })
      if (isMain) {
        if (g.condition) {
          const failed = !c.matched
          steps.push({ key: `cond:${g.id}`, ok: !failed, text: t('ui.why.condition_result', { condition: g.condition, result: c.condition_result ?? (c.matched ? 'true' : 'false') }),
            note: failed && failingCode ? reasonText(t, failingCode) : t('ui.why.condition_class', { class: g.condition_class }) })
        } else {
          steps.push({ key: `cond:${g.id}`, ok: true, text: t('ui.why.no_condition'), note: t('ui.why.condition_class', { class: g.condition_class }) })
        }
      }
    }
    if (candidates.length === 0 && failingCode) {
      steps.push({ key: 'none', ok: false, text: reasonText(t, failingCode) })
    }
  }

  let n = 0
  return (
    <div className="why">
      <div className="verdict">
        <Pill value={ex.decision === 'ALLOW' ? 'allow' : 'deny'} label={t(`ui.why.decision.${ex.decision}`)} />
        {t('ui.why.verdict', { action: ex.action })} <span className="mono">{ex.resource}</span>
      </div>
      <ol className="chain">
        {steps.map((s) => (
          <li key={s.key} className={s.ok === true ? 'ok' : s.ok === false ? 'first' : ''}>
            <i>{s.ok === null ? '·' : ++n}</i>
            <span>{s.ok === false ? <b>{s.text}</b> : s.text}{s.note && <small>{s.note}</small>}</span>
          </li>
        ))}
      </ol>
      <div className="asof">{t('ui.why.as_of', { time: f.clock(ex.as_of), n: candidates.length })}</div>
    </div>
  )
}
