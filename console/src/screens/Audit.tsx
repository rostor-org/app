import { useEffect, useRef, useState } from 'react'
import { useInfiniteQuery, useMutation } from '@tanstack/react-query'
import { api } from '../api'
import { useT } from '../i18n/catalog'
import { useFormat } from '../lib/format'
import { useToast } from '../components/Toast'
import { Empty, ErrorNote, Head, Loading } from '../components/bits'
import { AuditEvent } from '../components/AuditEvent'

const LIMIT = 50

export function Audit() {
  const t = useT()
  const f = useFormat()
  const toast = useToast()
  const [q, setQ] = useState('')
  // People by default; the appliance's own work and device chatter on request.
  const [system, setSystem] = useState(false)
  const page = useInfiniteQuery({
    queryKey: ['audit', q, system],
    queryFn: ({ pageParam }) => api.audit({ q: q || undefined, before: pageParam, limit: LIMIT, include_system: system || undefined }),
    initialPageParam: undefined as number | undefined,
    getNextPageParam: (last) => (last.items.length >= LIMIT ? last.items[last.items.length - 1]?.seq : undefined),
  })
  const verify = useMutation({
    mutationFn: () => api.auditVerify(),
    onSuccess: (r) => toast(r.intact ? t('ui.audit.verify_ok') : t('ui.audit.verify_bad', { seq: r.first_bad_seq })),
  })

  // Rows above the head we last rendered flash once, as the mockup does for live arrivals.
  const head = page.data?.pages[0]?.head.seq
  const seenHead = useRef<number | null>(null)
  const [freshAbove, setFreshAbove] = useState<number | null>(null)
  useEffect(() => {
    if (head === undefined) return
    if (seenHead.current !== null && head > seenHead.current) setFreshAbove(seenHead.current)
    seenHead.current = head
    const id = setTimeout(() => setFreshAbove(null), 1700)
    return () => clearTimeout(id)
  }, [head])

  const rows = page.data?.pages.flatMap((p) => p.items) ?? []
  const broken = verify.data && !verify.data.intact ? verify.data.first_bad_seq : null

  return (
    <section>
      <Head titleCode="ui.audit.title" subCode="ui.audit.subtitle">
        <button type="button" className="btn" disabled={verify.isPending} onClick={() => verify.mutate()}>{t(verify.isPending ? 'ui.audit.verifying' : 'ui.audit.verify')}</button>
        <button type="button" className="btn quiet" onClick={() => toast(t('ui.common.not_available'))}>{t('ui.audit.export')}</button>
      </Head>
      <div className="search">
        <input type="search" value={q} onChange={(e) => setQ(e.target.value)} placeholder={t('ui.audit.search')} aria-label={t('ui.audit.search')} />
        <label className="check"><input type="checkbox" checked={system} onChange={(e) => setSystem(e.target.checked)} /> {t('ui.audit.include_system')}</label>
        {head !== undefined && (
          <span className={broken ? 'error' : 'muted'} role="status">
            {broken ? t('ui.audit.chain_broken', { seq: f.int(broken) })
              : verify.data?.intact ? t('ui.audit.chain_intact', { seq: f.int(head) }) : t('ui.audit.chain_head', { seq: f.int(head) })}
          </span>
        )}
      </div>
      <ErrorNote error={page.error ?? verify.error} />
      <div className="audit">
        {page.isPending && <Loading />}
        {!page.isPending && rows.length === 0 && <Empty code="ui.audit.empty" />}
        {rows.map((r) => <AuditEvent key={r.seq} r={r} fresh={freshAbove !== null && r.seq > freshAbove} />)}
      </div>
      {page.hasNextPage && (
        <div className="actions" style={{ marginTop: 12 }}>
          <button type="button" className="btn quiet" disabled={page.isFetchingNextPage} onClick={() => void page.fetchNextPage()}>{t('ui.audit.load_more')}</button>
        </div>
      )}
    </section>
  )
}
