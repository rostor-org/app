import { useCallback, useState, type FormEvent } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, type CreateGrant, type Grant, type WhyQuery } from '../api'
import { useT } from '../i18n/catalog'
import { useSession } from '../auth/session'
import { useFormat } from '../lib/format'
import { useToast } from '../components/Toast'
import { Drawer } from '../components/Drawer'
import { Field, SelectField } from '../components/Form'
import { Dash, Empty, ErrorNote, Head, Loading, Pill, RowButton } from '../components/bits'
import { WhyChain } from '../components/WhyChain'

interface WhyForm { principal: string; action: string; resource: string }
const invalidateGrants = ['grants', 'group', 'groups', 'summary', 'why']

export function Access() {
  const t = useT()
  const f = useFormat()
  const qc = useQueryClient()
  const toast = useToast()
  const { can } = useSession()
  const [q, setQ] = useState('')
  const [why, setWhy] = useState<WhyForm | null>(null)
  const [adding, setAdding] = useState(false)
  const grants = useQuery({ queryKey: ['grants', q], queryFn: () => api.grants(q || undefined) })
  const revoke = useMutation({
    mutationFn: (id: string) => api.revokeGrant(id),
    onSuccess: () => { toast(t('ui.access.revoked_toast')); for (const k of invalidateGrants) void qc.invalidateQueries({ queryKey: [k] }) },
  })
  const closeWhy = useCallback(() => setWhy(null), [])
  const closeAdd = useCallback(() => setAdding(false), [])
  const askFor = (g: Grant) => { setAdding(false); setWhy({ principal: g.subject.kind === 'group' ? '' : g.subject.name, action: g.role, resource: `${g.resource.type}:${g.resource.id}` }) }
  const confirmRevoke = (g: Grant) => {
    if (confirm(t('ui.common.confirm_revoke', { what: t('ui.access.grant_what', { subject: g.subject.name, resource: `${g.resource.type}:${g.resource.id}` }) }))) revoke.mutate(g.id)
  }

  return (
    <section>
      <Head titleCode="ui.access.title" subCode="ui.access.subtitle">
        {can('authz.read') && <button type="button" className="btn" onClick={() => { setAdding(false); setWhy({ principal: '', action: '', resource: '' }) }}>{t('ui.access.ask_why')}</button>}
        {can('grants.write') && <button type="button" className="btn primary" onClick={() => { setWhy(null); setAdding(true) }}>{t('ui.access.new')}</button>}
      </Head>
      <div className="search">
        <input type="search" value={q} onChange={(e) => setQ(e.target.value)} placeholder={t('ui.access.search')} aria-label={t('ui.access.search')} />
        {grants.data && <span className="muted">{t('ui.access.count', { n: f.int(grants.data.total) })}</span>}
      </div>
      <ErrorNote error={grants.error ?? revoke.error} />
      <div className="tablewrap">
        <table>
          <thead><tr>
            <th>{t('ui.access.col.subject')}</th><th>{t('ui.access.col.role')}</th><th>{t('ui.access.col.resource')}</th>
            <th>{t('ui.access.col.condition')}</th><th>{t('ui.access.col.class')}</th><th>{t('ui.access.col.expires')}</th>{can('grants.write') && <th />}
          </tr></thead>
          <tbody>
            {grants.isPending && <tr><td colSpan={7}><Loading /></td></tr>}
            {grants.data?.items.length === 0 && <tr><td colSpan={7}><Empty /></td></tr>}
            {grants.data?.items.map((g) => (
              <tr key={g.id} className="row" onClick={() => askFor(g)}>
                <td><RowButton onClick={() => askFor(g)}><span className="chip">{t('ui.access.subject', { kind: g.subject.kind, name: g.subject.name })}</span></RowButton></td>
                <td>{g.role}</td>
                <td className="mono">{g.resource.type}:{g.resource.id}</td>
                <td className={g.condition ? 'mono' : 'muted'}>{g.condition || t('ui.common.none')}</td>
                <td>{g.condition_class ? <Pill value={g.condition_class} label={g.condition_class} /> : <Dash />}</td>
                <td className={g.expires_at ? 'num' : 'muted'}>{g.expires_at ? f.date(g.expires_at) : t('ui.time.never')}</td>
                {can('grants.write') && <td><button type="button" className="btn quiet danger" disabled={revoke.isPending} onClick={(e) => { e.stopPropagation(); confirmRevoke(g) }}>{t('ui.access.revoke')}</button></td>}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <WhyDrawer form={why} onChange={setWhy} onClose={closeWhy} />
      <NewGrantDrawer open={adding} onClose={closeAdd} />
    </section>
  )
}

const emptyGrant: CreateGrant = { subject_kind: 'group', subject: '', role: '', resource_type: '', resource_id: '', condition: '', expires_at: null }

function NewGrantDrawer({ open, onClose }: { open: boolean; onClose: () => void }) {
  const t = useT()
  const qc = useQueryClient()
  const toast = useToast()
  const [g, setG] = useState<CreateGrant>(emptyGrant)
  const [expires, setExpires] = useState('')
  const set = <K extends keyof CreateGrant>(k: K) => (e: { target: { value: string } }) => setG({ ...g, [k]: e.target.value })
  const create = useMutation({
    mutationFn: () => api.createGrant({
      ...g, subject: g.subject.trim(), role: g.role.trim(), resource_type: g.resource_type.trim(), resource_id: g.resource_id.trim(),
      condition: g.condition?.trim() || undefined, expires_at: expires ? `${expires}T00:00:00Z` : null,
    }),
    onSuccess: (r) => {
      for (const k of invalidateGrants) void qc.invalidateQueries({ queryKey: [k] })
      toast(t('ui.access.created_toast', { subject: r.subject.name, role: r.role, resource: `${r.resource.type}:${r.resource.id}` }))
      setG(emptyGrant); setExpires('')
      onClose()
    },
  })
  const submit = (e: FormEvent) => { e.preventDefault(); create.mutate() }
  return (
    <Drawer open={open} onClose={onClose} labelCode="ui.access.new_title" title={t('ui.access.new_title')}>
      <form onSubmit={submit}>
        <SelectField labelCode="ui.access.subject_kind" value={g.subject_kind} onChange={set('subject_kind')}
          options={[['group', 'ui.access.subject_kind.group'], ['principal', 'ui.access.subject_kind.principal']]} />
        <Field labelCode="ui.access.subject_name" hintCode="ui.access.subject_hint" value={g.subject} onChange={set('subject')} required autoComplete="off" autoCapitalize="none" spellCheck={false} />
        <Field labelCode="ui.access.role" value={g.role} onChange={set('role')} required autoComplete="off" autoCapitalize="none" spellCheck={false} />
        <Field labelCode="ui.access.resource_type" value={g.resource_type} onChange={set('resource_type')} required autoComplete="off" autoCapitalize="none" spellCheck={false} />
        <Field labelCode="ui.access.resource_id" value={g.resource_id} onChange={set('resource_id')} required autoComplete="off" autoCapitalize="none" spellCheck={false} />
        <Field labelCode="ui.access.condition" hintCode="ui.access.condition_hint" className="input mono" value={g.condition ?? ''} onChange={set('condition')} autoComplete="off" spellCheck={false} />
        <Field labelCode="ui.access.expires" type="date" value={expires} onChange={(e) => setExpires(e.target.value)} />
        <ErrorNote error={create.error} />
        <div className="actions">
          <button type="submit" className="btn primary" disabled={create.isPending}>{t(create.isPending ? 'ui.common.working' : 'ui.access.create')}</button>
          <button type="button" className="btn quiet" onClick={onClose}>{t('ui.common.cancel')}</button>
        </div>
      </form>
    </Drawer>
  )
}

export function WhyDrawer({ form, onChange, onClose }: { form: WhyForm | null; onChange: (f: WhyForm) => void; onClose: () => void }) {
  const t = useT()
  const [query, setQuery] = useState<WhyQuery | null>(null)
  const ex = useQuery({ queryKey: ['why', query], queryFn: () => api.why(query!), enabled: !!query, staleTime: 0 })
  const open = form !== null
  const submit = (e: FormEvent) => {
    e.preventDefault()
    if (!form) return
    const [rt, rid] = form.resource.includes(':') ? form.resource.split(/:(.*)/, 2) : [form.resource, '']
    setQuery({ principal: form.principal.trim(), action: form.action.trim(), resource_type: (rt ?? '').trim(), resource_id: (rid ?? '').trim() })
  }
  const field = (k: keyof WhyForm) => ({
    className: 'input', style: { width: '100%', maxWidth: 'none' } as const, value: form?.[k] ?? '',
    onChange: (e: { target: { value: string } }) => form && onChange({ ...form, [k]: e.target.value }),
  })
  return (
    <Drawer open={open} onClose={onClose} labelCode="ui.why.title" title={t('ui.why.title')} subtitle={t('ui.why.subtitle')}>
      <form onSubmit={submit}>
        <dl className="kv">
          <dt><label htmlFor="why-p">{t('ui.why.person')}</label></dt><dd><input id="why-p" {...field('principal')} required autoComplete="off" /></dd>
          <dt><label htmlFor="why-a">{t('ui.why.action')}</label></dt><dd><input id="why-a" {...field('action')} required autoComplete="off" /></dd>
          <dt><label htmlFor="why-r">{t('ui.why.resource')}</label></dt><dd><input id="why-r" {...field('resource')} required placeholder={t('ui.why.resource_hint')} autoComplete="off" /></dd>
        </dl>
        <div className="actions"><button type="submit" className="btn primary" disabled={ex.isFetching}>{t(ex.isFetching ? 'ui.why.working' : 'ui.why.explain')}</button></div>
      </form>
      <ErrorNote error={ex.error} />
      {ex.data && <div className="section"><WhyChain ex={ex.data} /></div>}
    </Drawer>
  )
}
