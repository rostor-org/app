import { useCallback, useRef, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, type CA, type Device, type EnrollmentToken } from '../api'
import { useT } from '../i18n/catalog'
import { useSession } from '../auth/session'
import { useFormat, type Fmt } from '../lib/format'
import { useToast } from '../components/Toast'
import { Drawer } from '../components/Drawer'
import { SelectField } from '../components/Form'
import { Dash, Empty, ErrorNote, Head, Loading, Pill, Stat, StatePill } from '../components/bits'

/** Certificates within this many days of expiry are flagged. */
const EXPIRY_WARN_DAYS = 30

export function Devices() {
  const t = useT()
  const f = useFormat()
  const { can } = useSession()
  const [q, setQ] = useState('')
  const [installing, setInstalling] = useState(false)
  const summary = useQuery({ queryKey: ['summary'], queryFn: () => api.summary() })
  const devices = useQuery({ queryKey: ['devices', q], queryFn: () => api.devices(q || undefined) })
  // The CA list names each issuer and says which one is newest (needs system.read).
  const cas = useQuery({ queryKey: ['ca'], queryFn: () => api.cas(), enabled: can('system.read') })
  const byLc = summary.data?.devices ?? {}
  const closeInstall = useCallback(() => setInstalling(false), [])
  const caById = new Map<string, CA>((cas.data?.items ?? []).map((c) => [c.id, c]))
  const newest = cas.data?.items.find((c) => c.newest)

  return (
    <section>
      <Head titleCode="ui.devices.title" subCode="ui.devices.subtitle">
        {can('devices.write') && <button type="button" className="btn primary" onClick={() => setInstalling(true)}>{t('ui.devices.install')}</button>}
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
            <th>{t('ui.devices.col.issuer')}</th><th>{t('ui.devices.col.renewed')}</th>
          </tr></thead>
          <tbody>
            {devices.isPending && <tr><td colSpan={8}><Loading /></td></tr>}
            {devices.data?.items.length === 0 && <tr><td colSpan={8}><Empty /></td></tr>}
            {devices.data?.items.map((d) => (
              <tr key={d.id}>
                <td><b>{d.display_name}</b><br /><span className="mono muted">{f.shortId(d.id)}</span></td>
                <td>{d.resource.type}{typeof d.posture?.model === 'string' && <> · {d.posture.model}</>}</td>
                <td><StatePill family="ui.devices.lifecycle" value={d.lifecycle} /></td>
                <td className="num">{f.relDay(d.last_seen_at)}{typeof d.posture?.via === 'string' && <> · {d.posture.via}</>}</td>
                <td>{posture(d.posture)}</td>
                <td className="num"><CertCell d={d} f={f} /></td>
                <td><IssuerCell d={d} ca={d.ca_key_id ? caById.get(d.ca_key_id) : undefined} newest={newest} f={f} /></td>
                <td className="num">{d.cert_renewed_at ? f.relDay(d.cert_renewed_at) : <Dash />}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <InstallDrawer open={installing} onClose={closeInstall} />
    </section>
  )
}

/** "expires in 78 days" over the date; red inside the warning window or once expired. */
function CertCell({ d, f }: { d: Device; f: Fmt }) {
  const t = useT()
  if (!d.cert_not_after) return <Dash />
  const n = f.daysUntil(d.cert_not_after)
  const when = f.relDays(d.cert_not_after)
  const label = n !== null && n < 0 ? t('ui.devices.cert_expired', { when }) : t('ui.devices.cert_expires', { when })
  return (
    <>
      <span className={n !== null && n < EXPIRY_WARN_DAYS ? 'expiring nowrap' : 'nowrap'}>{label}</span>
      <small className="muted">{f.date(d.cert_not_after)}</small>
    </>
  )
}

/** The issuing CA's fingerprint, flagged when it is no longer the newest CA. */
function IssuerCell({ d, ca, newest, f }: { d: Device; ca: CA | undefined; newest: CA | undefined; f: Fmt }) {
  const t = useT()
  if (!d.ca_key_id) return <Dash />
  const older = !!newest && d.ca_key_id !== newest.id
  return (
    <>
      <span className="mono nowrap" title={ca?.fingerprint ?? d.ca_key_id}>{ca ? f.fingerprint(ca.fingerprint) : f.shortId(d.ca_key_id)}</span>
      {older && <> <Pill value="pending" label={t('ui.devices.older_ca')} /></>}
    </>
  )
}

const TTL: Array<[string, string]> = [['3600', 'ui.devices.ttl.1h'], ['600', 'ui.devices.ttl.10m'], ['86400', 'ui.devices.ttl.24h']]

/**
 * Install a workstation: the version-matched agent bundle the appliance
 * serves, a one-shot enrollment token, and the install command built from
 * `device_url` (GET /v1/admin/system) and that token.
 */
function InstallDrawer({ open, onClose }: { open: boolean; onClose: () => void }) {
  const t = useT()
  const f = useFormat()
  const qc = useQueryClient()
  const toast = useToast()
  const { can } = useSession()
  const dl = useQuery({ queryKey: ['downloads'], queryFn: () => api.downloads(), enabled: open })
  const sys = useQuery({ queryKey: ['system'], queryFn: () => api.system(), enabled: open && can('system.read') })
  const [ttl, setTtl] = useState('3600')
  const [result, setResult] = useState<(EnrollmentToken & { at: number }) | null>(null)
  const mint = useMutation({
    mutationFn: () => api.enrollmentToken('workstation', Number(ttl)),
    onSuccess: (r) => setResult({ ...r, at: Date.now() }),
  })
  const close = () => { setResult(null); mint.reset(); onClose() }
  const w = dl.data?.windows
  const coreUrl = sys.data?.device_url || t('ui.install.core_url_placeholder')
  const token = result?.enrollment_token ?? t('ui.install.token_placeholder')
  const command = `powershell -ExecutionPolicy Bypass -File .\\install.ps1 -CoreUrl ${coreUrl} -Token ${token}`
  const cmdField = useRef<HTMLTextAreaElement>(null)
  const tokenField = useRef<HTMLInputElement>(null)
  const copy = async (text: string, fallback: HTMLTextAreaElement | HTMLInputElement | null) => {
    try {
      await navigator.clipboard.writeText(text)
      toast(t('ui.common.copied'))
    } catch {
      // Clipboard blocked (permissions, insecure context): hand the user a selected field instead.
      fallback?.focus()
      fallback?.select()
    }
  }
  // The first download makes the core fetch and cache the bundle; ask for the status again once that had time to happen.
  const downloaded = () => setTimeout(() => void qc.invalidateQueries({ queryKey: ['downloads'] }), 4000)

  return (
    <Drawer open={open} onClose={close} labelCode="ui.install.title" title={t('ui.install.title')}>
      <h3>{t('ui.install.download_title')}</h3>
      <ErrorNote error={dl.error} />
      <div className="inline">
        <a className="btn primary" href={api.downloadUrl('windows')} download={w?.name} onClick={downloaded}>{t('ui.install.download', { name: w?.name ?? '' })}</a>
        {w && <span className="muted num">{t('ui.install.download_meta', { version: w.version, size: w.cached ? f.bytes(w.size) : t('ui.install.not_cached') })}</span>}
      </div>
      {w?.error && <p className="error" style={{ marginTop: 8 }}>{t('ui.install.download_error', { error: w.error })}</p>}

      <h3>{t('ui.install.token_title')}</h3>
      {!result ? (
        <>
          <SelectField labelCode="ui.devices.token_ttl" value={ttl} onChange={(e) => setTtl(e.target.value)} options={TTL} />
          <ErrorNote error={mint.error} />
          <div className="actions">
            <button type="button" className="btn" disabled={mint.isPending} onClick={() => mint.mutate()}>{t(mint.isPending ? 'ui.common.working' : 'ui.install.new_token')}</button>
          </div>
        </>
      ) : (
        <>
          <p className="note">{t('ui.devices.token_once')}</p>
          <div className="inline">
            <input ref={tokenField} className="input token" readOnly value={result.enrollment_token} onFocus={(e) => e.target.select()} aria-label={t('ui.devices.token_title')} />
            <button type="button" className="btn" onClick={() => void copy(result.enrollment_token, tokenField.current)}>{t('ui.common.copy')}</button>
          </div>
          <p className="muted num" style={{ marginTop: 8 }}>{t('ui.devices.token_expires', { time: f.relDay(result.at + result.expires_in * 1000) })}</p>
        </>
      )}

      <h3>{t('ui.install.command_title')}</h3>
      <textarea ref={cmdField} className="input cmd" readOnly rows={3} value={command} onFocus={(e) => e.target.select()} aria-label={t('ui.install.command_label')} />
      {/* `.row` is only laid out inside cards; in the drawer it needs `.actions` for the gap. */}
      <div className="actions" style={{ marginTop: 8 }}>
        <span className="muted">{result ? '' : t('ui.install.command_hint')}</span>
        <button type="button" className="btn primary" disabled={!result} onClick={() => void copy(command, cmdField.current)}>{t('ui.common.copy')}</button>
      </div>

      <h3>{t('ui.install.steps_title')}</h3>
      <ol className="steps">
        <li>{t('ui.install.step1')}</li>
        <li>{t('ui.install.step2')}</li>
        <li>{t('ui.install.step3')}</li>
        <li>{t('ui.install.step4')}</li>
      </ol>
      <div className="actions" style={{ marginTop: 16 }}><button type="button" className="btn" onClick={close}>{t('ui.common.close')}</button></div>
    </Drawer>
  )
}

function posture(p: Record<string, unknown> | null): string {
  if (!p) return ''
  return Object.entries(p).filter(([k]) => k !== 'model' && k !== 'via').map(([k, v]) => `${k} ${String(v)}`).join(' · ')
}
