import { useCallback, useRef, useState, type FormEvent } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import { api, type EnrollmentToken } from '../api'
import { useT } from '../i18n/catalog'
import { useSession } from '../auth/session'
import { useFormat } from '../lib/format'
import { useToast } from '../components/Toast'
import { Drawer } from '../components/Drawer'
import { SelectField } from '../components/Form'
import { Empty, ErrorNote, Head, Loading, Stat, StatePill } from '../components/bits'

export function Devices() {
  const t = useT()
  const f = useFormat()
  const { can } = useSession()
  const [q, setQ] = useState('')
  const [minting, setMinting] = useState(false)
  const summary = useQuery({ queryKey: ['summary'], queryFn: () => api.summary() })
  const devices = useQuery({ queryKey: ['devices', q], queryFn: () => api.devices(q || undefined) })
  const byLc = summary.data?.devices ?? {}
  const closeMint = useCallback(() => setMinting(false), [])

  return (
    <section>
      <Head titleCode="ui.devices.title" subCode="ui.devices.subtitle">
        {can('devices.write') && <button type="button" className="btn primary" onClick={() => setMinting(true)}>{t('ui.devices.enrollment_token')}</button>}
      </Head>
      <div className="strip">
        <Stat value={f.int(byLc['trusted'] ?? 0)} labelCode="ui.devices.stat.trusted" />
        <Stat value={f.int(byLc['quarantined'] ?? 0)} labelCode="ui.devices.stat.quarantined" />
        <Stat value={f.int(summary.data?.offline_points ?? 0)} labelCode="ui.devices.stat.offline_points" />
        <Stat value={f.duration(summary.data?.oldest_snapshot_age_seconds)} labelCode="ui.devices.stat.oldest_snapshot" />
      </div>
      <div className="search">
        <input type="search" value={q} onChange={(e) => setQ(e.target.value)} placeholder={t('ui.devices.search')} aria-label={t('ui.devices.search')} />
        {devices.data && <span className="muted">{t('ui.common.showing', { shown: devices.data.items.length, total: f.int(devices.data.total) })}</span>}
      </div>
      <ErrorNote error={devices.error} />
      <div className="tablewrap">
        <table>
          <thead><tr>
            <th>{t('ui.devices.col.device')}</th><th>{t('ui.devices.col.type')}</th><th>{t('ui.devices.col.lifecycle')}</th>
            <th>{t('ui.devices.col.last_seen')}</th><th>{t('ui.devices.col.posture')}</th><th>{t('ui.devices.col.certificate')}</th>
          </tr></thead>
          <tbody>
            {devices.isPending && <tr><td colSpan={6}><Loading /></td></tr>}
            {devices.data?.items.length === 0 && <tr><td colSpan={6}><Empty /></td></tr>}
            {devices.data?.items.map((d) => (
              <tr key={d.id}>
                <td><b>{d.display_name}</b><br /><span className="mono muted">{f.shortId(d.id)}</span></td>
                <td>{d.resource.type}{typeof d.posture?.model === 'string' && <> · {d.posture.model}</>}</td>
                <td><StatePill family="ui.devices.lifecycle" value={d.lifecycle} /></td>
                <td className="num">{f.relDay(d.last_seen_at)}{typeof d.posture?.via === 'string' && <> · {d.posture.via}</>}</td>
                <td>{posture(d.posture)}</td>
                <td className="mono">{d.cert_not_after ? t('ui.devices.cert_exp', { date: f.date(d.cert_not_after) }) : t('ui.common.none')}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <TokenDrawer open={minting} onClose={closeMint} />
    </section>
  )
}

const TTL: Array<[string, string]> = [['3600', 'ui.devices.ttl.1h'], ['600', 'ui.devices.ttl.10m'], ['86400', 'ui.devices.ttl.24h']]

/** Mint an enrollment token and show it once, copyable, with its expiry. */
function TokenDrawer({ open, onClose }: { open: boolean; onClose: () => void }) {
  const t = useT()
  const f = useFormat()
  const toast = useToast()
  const [rt, setRt] = useState('workstation')
  const [ttl, setTtl] = useState('3600')
  const [result, setResult] = useState<(EnrollmentToken & { at: number }) | null>(null)
  const mint = useMutation({
    mutationFn: () => api.enrollmentToken(rt, Number(ttl)),
    onSuccess: (r) => setResult({ ...r, at: Date.now() }),
  })
  const submit = (e: FormEvent) => { e.preventDefault(); mint.mutate() }
  const close = () => { setResult(null); onClose() }
  const field = useRef<HTMLInputElement>(null)
  const copy = async () => {
    if (!result) return
    try {
      await navigator.clipboard.writeText(result.enrollment_token)
      toast(t('ui.common.copied'))
    } catch {
      // Clipboard blocked (permissions, insecure context): hand the user a selected field instead.
      field.current?.focus()
      field.current?.select()
    }
  }
  return (
    <Drawer open={open} onClose={close} labelCode="ui.devices.token_title" title={t('ui.devices.token_title')}>
      {!result ? (
        <form onSubmit={submit}>
          <SelectField labelCode="ui.devices.token_resource_type" value={rt} onChange={(e) => setRt(e.target.value)}
            options={[['workstation', 'ui.devices.type.workstation'], ['door', 'ui.devices.type.door']]} />
          <SelectField labelCode="ui.devices.token_ttl" value={ttl} onChange={(e) => setTtl(e.target.value)} options={TTL} />
          <ErrorNote error={mint.error} />
          <div className="actions">
            <button type="submit" className="btn primary" disabled={mint.isPending}>{t(mint.isPending ? 'ui.common.working' : 'ui.devices.token_create')}</button>
            <button type="button" className="btn quiet" onClick={close}>{t('ui.common.cancel')}</button>
          </div>
        </form>
      ) : (
        <>
          <p className="note">{t('ui.devices.token_once')}</p>
          <div className="inline">
            <input ref={field} className="input token" readOnly value={result.enrollment_token} onFocus={(e) => e.target.select()} aria-label={t('ui.devices.token_title')} />
            <button type="button" className="btn" onClick={() => void copy()}>{t('ui.common.copy')}</button>
          </div>
          <p className="muted num" style={{ marginTop: 10 }}>{t('ui.devices.token_expires', { time: f.relDay(result.at + result.expires_in * 1000) })}</p>
          <div className="actions" style={{ marginTop: 16 }}><button type="button" className="btn" onClick={close}>{t('ui.common.close')}</button></div>
        </>
      )}
    </Drawer>
  )
}

function posture(p: Record<string, unknown> | null): string {
  if (!p) return ''
  return Object.entries(p).filter(([k]) => k !== 'model' && k !== 'via').map(([k, v]) => `${k} ${String(v)}`).join(' · ')
}
