import { useCallback, useId, useState, type FormEvent } from 'react'
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

const OTHER = '__other'
const NEW_ROLE = '__new'

/** A labelled select whose options are ready-made labels (names from the directory, or catalog strings the caller resolved). */
function PickField({ labelCode, hintCode, value, onChange, groups, required }: {
  labelCode: string; hintCode?: string; value: string; onChange: (v: string) => void; required?: boolean
  groups: Array<{ label?: string; options: Array<[string, string]> }>
}) {
  const t = useT()
  const id = useId()
  return (
    <div className="field">
      <label htmlFor={id}>{t(labelCode)}</label>
      <select id={id} className="input" value={value} onChange={(e) => onChange(e.target.value)} required={required}>
        {groups.map((g, i) => g.label
          ? <optgroup key={i} label={g.label}>{g.options.map(([v, l]) => <option key={v} value={v}>{l}</option>)}</optgroup>
          : g.options.map(([v, l]) => <option key={v} value={v}>{l}</option>))}
      </select>
      {hintCode && <small className="muted">{t(hintCode)}</small>}
    </div>
  )
}

/**
 * Everything is picked from what the directory already knows: the subject
 * from groups or people, the resource from GET /v1/admin/resources, the role
 * from those defined for that resource type. "Something else" and "New role…"
 * fall back to typing, so plugin-defined types stay reachable. A new role is
 * defined (POST /v1/admin/roles) right before the grant is created.
 */
function NewGrantDrawer({ open, onClose }: { open: boolean; onClose: () => void }) {
  const t = useT()
  const qc = useQueryClient()
  const toast = useToast()
  const { can } = useSession()
  const [g, setG] = useState<CreateGrant>(emptyGrant)
  const [resourceKey, setResourceKey] = useState('')
  const [subjectKey, setSubjectKey] = useState('')
  const [roleKey, setRoleKey] = useState('')
  const [newRole, setNewRole] = useState({ name: '', perms: [] as string[], extra: '' })
  const [expires, setExpires] = useState('')
  const set = <K extends keyof CreateGrant>(k: K) => (e: { target: { value: string } }) => setG({ ...g, [k]: e.target.value })

  const roles = useQuery({ queryKey: ['roles'], queryFn: () => api.roles(), enabled: open, staleTime: 60_000 })
  const resources = useQuery({ queryKey: ['resources'], queryFn: () => api.resources(), enabled: open, staleTime: 60_000 })
  const groupList = useQuery({ queryKey: ['groups', ''], queryFn: () => api.groups(), enabled: open && g.subject_kind === 'group' })
  const people = useQuery({ queryKey: ['users', ''], queryFn: () => api.users(), enabled: open && g.subject_kind === 'principal' })

  const resourceType = g.resource_type.trim()
  const rolesForType = roles.data?.items.filter((r) => r.resource_type === resourceType) ?? []
  const knownPerms = resources.data?.permissions[resourceType] ?? []
  const definingRole = roleKey === NEW_ROLE

  const resourceLabel = (r: { type: string; id: string }) => {
    if (r.type === 'directory' && r.id === 'root') return t('ui.resource.directory.root')
    if (r.type === 'workstations' && r.id === 'all') return t('ui.resource.workstations.all')
    if (r.type === 'workstation') return t('ui.resource.workstation', { id: r.id })
    return t('ui.resource.generic', { type: r.type, id: r.id })
  }
  // Resources grouped by type, parents first within a type.
  const byType = new Map<string, Array<[string, string]>>()
  for (const r of resources.data?.items ?? []) {
    const list = byType.get(r.type) ?? []
    list.push([`${r.type}:${r.id}`, resourceLabel(r)])
    byType.set(r.type, list)
  }
  const resourceGroups = [
    { options: [['', t('ui.access.resource_pick')] as [string, string]] },
    ...[...byType.entries()].map(([type, options]) => ({ label: type, options })),
    { options: [[OTHER, t('ui.access.resource_other')] as [string, string]] },
  ]
  const pickResource = (key: string) => {
    setResourceKey(key)
    setRoleKey('')
    if (key === OTHER || key === '') { setG({ ...g, resource_type: '', resource_id: '', role: '' }); return }
    const [type, id] = key.split(/:(.*)/, 2)
    setG({ ...g, resource_type: type ?? '', resource_id: id ?? '', role: '' })
  }
  const setResourceType = (e: { target: { value: string } }) => { setRoleKey(''); setG({ ...g, resource_type: e.target.value, role: '' }) }

  const subjectOptions: Array<[string, string]> = g.subject_kind === 'group'
    ? (groupList.data?.items ?? []).map((x) => [x.name, x.display_name && x.display_name !== x.name ? t('ui.access.group_option', { name: x.name, description: x.display_name }) : x.name])
    : (people.data?.items ?? []).filter((u) => u.state !== 'suspended').map((u) => [u.username, t('ui.access.subject_option', { name: u.display_name, username: u.username })])
  const subjectGroups = [
    { options: [['', t(`ui.access.subject_pick.${g.subject_kind}`)] as [string, string], ...subjectOptions] },
    ...(g.subject_kind === 'principal' ? [{ options: [[OTHER, t('ui.access.subject_other')] as [string, string]] }] : []),
  ]
  const pickSubject = (key: string) => { setSubjectKey(key); setG({ ...g, subject: key === OTHER ? '' : key }) }
  const setSubjectKind = (e: { target: { value: string } }) => { setSubjectKey(''); setG({ ...g, subject_kind: e.target.value as CreateGrant['subject_kind'], subject: '' }) }

  const roleGroups = [
    { options: [['', t('ui.access.role_pick')] as [string, string], ...rolesForType.map((r): [string, string] => [r.name, r.name])] },
    ...(can('roles.write') ? [{ options: [[NEW_ROLE, t('ui.access.role_new')] as [string, string]] }] : []),
  ]
  const pickRole = (key: string) => { setRoleKey(key); setG({ ...g, role: key === NEW_ROLE ? '' : key }) }
  const togglePerm = (perm: string) => setNewRole((n) => ({ ...n, perms: n.perms.includes(perm) ? n.perms.filter((x) => x !== perm) : [...n.perms, perm] }))
  const newRolePerms = [...new Set([...newRole.perms, ...newRole.extra.split(',').map((x) => x.trim()).filter(Boolean)])]

  const reset = () => { setG(emptyGrant); setExpires(''); setResourceKey(''); setSubjectKey(''); setRoleKey(''); setNewRole({ name: '', perms: [], extra: '' }) }
  const create = useMutation({
    mutationFn: async () => {
      let role = g.role.trim()
      if (definingRole) {
        role = newRole.name.trim()
        const defined = await api.upsertRole({ resource_type: resourceType, name: role, permissions: newRolePerms })
        void qc.invalidateQueries({ queryKey: ['roles'] })
        void qc.invalidateQueries({ queryKey: ['resources'] })
        toast(t('ui.access.role_created_toast', { role: defined.name, type: defined.resource_type }))
      }
      return api.createGrant({
        ...g, subject: g.subject.trim(), role, resource_type: resourceType, resource_id: g.resource_id.trim(),
        condition: g.condition?.trim() || undefined, expires_at: expires ? `${expires}T00:00:00Z` : null,
      })
    },
    onSuccess: (r) => {
      for (const k of invalidateGrants) void qc.invalidateQueries({ queryKey: [k] })
      toast(t('ui.access.created_toast', { subject: r.subject.name, role: r.role, resource: `${r.resource.type}:${r.resource.id}` }))
      reset()
      onClose()
    },
  })
  const roleReady = definingRole ? newRole.name.trim() !== '' && newRolePerms.length > 0 : g.role !== ''
  const submit = (e: FormEvent) => { e.preventDefault(); if (roleReady) create.mutate() }
  return (
    <Drawer open={open} onClose={onClose} labelCode="ui.access.new_title" title={t('ui.access.new_title')}>
      <form onSubmit={submit}>
        <SelectField labelCode="ui.access.subject_kind" value={g.subject_kind} onChange={setSubjectKind}
          options={[['group', 'ui.access.subject_kind.group'], ['principal', 'ui.access.subject_kind.principal']]} />
        <PickField labelCode="ui.access.subject_name" value={subjectKey} onChange={pickSubject} groups={subjectGroups} required />
        {subjectKey === OTHER && (
          <Field labelCode="ui.access.subject_name" hintCode="ui.access.subject_hint" value={g.subject} onChange={set('subject')} required autoComplete="off" autoCapitalize="none" spellCheck={false} />
        )}
        <ErrorNote error={groupList.error ?? people.error ?? resources.error ?? roles.error} />

        <PickField labelCode="ui.access.resource" hintCode="ui.access.resource_hint" value={resourceKey} onChange={pickResource} groups={resourceGroups} required />
        {resourceKey === OTHER && (
          <div className="subform">
            <Field labelCode="ui.access.resource_type" value={g.resource_type} onChange={setResourceType} required autoComplete="off" autoCapitalize="none" spellCheck={false} />
            <Field labelCode="ui.access.resource_id" value={g.resource_id} onChange={set('resource_id')} required autoComplete="off" autoCapitalize="none" spellCheck={false} />
          </div>
        )}

        {resourceType !== '' && (
          <>
            <PickField labelCode="ui.access.role" hintCode="ui.access.role_hint" value={roleKey} onChange={pickRole} groups={roleGroups} required />
            {!definingRole && g.role && <p className="note">{t('ui.access.role_permissions', { permissions: rolesForType.find((r) => r.name === g.role)?.permissions.join(', ') ?? '' })}</p>}
            {definingRole && (
              <div className="subform">
                <Field labelCode="ui.access.role_name" hintCode="ui.access.role_name_hint" value={newRole.name} onChange={(e) => setNewRole({ ...newRole, name: e.target.value })} required autoComplete="off" autoCapitalize="none" spellCheck={false} />
                <div className="field">
                  <label>{t('ui.access.role_perms')}</label>
                  {knownPerms.length > 0 && (
                    <div className="checks">
                      {knownPerms.map((perm) => (
                        <label key={perm}>
                          <input type="checkbox" checked={newRole.perms.includes(perm)} onChange={() => togglePerm(perm)} />
                          <span className={perm === '*' ? '' : 'mono'}>{perm === '*' ? t('ui.access.permission_all') : perm}</span>
                        </label>
                      ))}
                    </div>
                  )}
                  <small className="muted">{t('ui.access.role_perms_hint')}</small>
                </div>
                <Field labelCode="ui.access.role_perms_extra" hintCode="ui.access.role_perms_extra_hint" className="input mono" value={newRole.extra} onChange={(e) => setNewRole({ ...newRole, extra: e.target.value })} autoComplete="off" spellCheck={false} />
                {newRole.name.trim() !== '' && newRolePerms.length === 0 && <p className="note">{t('ui.access.role_perms_none')}</p>}
              </div>
            )}
          </>
        )}

        <Field labelCode="ui.access.condition" hintCode="ui.access.condition_hint" className="input mono" value={g.condition ?? ''} onChange={set('condition')} autoComplete="off" spellCheck={false} />
        <Field labelCode="ui.access.expires" type="date" value={expires} onChange={(e) => setExpires(e.target.value)} />
        <ErrorNote error={create.error} />
        <div className="actions">
          <button type="submit" className="btn primary" disabled={create.isPending || !roleReady}>{t(create.isPending ? 'ui.common.working' : 'ui.access.create')}</button>
          <button type="button" className="btn quiet" onClick={() => { reset(); onClose() }}>{t('ui.common.cancel')}</button>
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
