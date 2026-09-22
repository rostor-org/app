import { useCallback, useState, type FormEvent } from 'react'
import { useNavigate, useParams } from 'react-router'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, type MemberChange } from '../api'
import { useT } from '../i18n/catalog'
import { useSession } from '../auth/session'
import { useFormat } from '../lib/format'
import { useToast } from '../components/Toast'
import { Drawer } from '../components/Drawer'
import { Field, SelectField } from '../components/Form'
import { Dash, Empty, ErrorNote, Head, Loading, Pill, RowButton, StatePill } from '../components/bits'

const invalidateGroups = ['groups', 'group', 'users', 'user', 'summary', 'why']

export function Groups() {
  const t = useT()
  const f = useFormat()
  const nav = useNavigate()
  const { can } = useSession()
  const { name } = useParams()
  const [q, setQ] = useState('')
  const [adding, setAdding] = useState(false)
  const groups = useQuery({ queryKey: ['groups', q], queryFn: () => api.groups(q || undefined) })
  const close = useCallback(() => nav('/groups'), [nav])
  const closeAdd = useCallback(() => setAdding(false), [])

  return (
    <section>
      <Head titleCode="ui.groups.title" subCode="ui.groups.subtitle">
        {can('groups.write') && <button type="button" className="btn primary" onClick={() => { nav('/groups'); setAdding(true) }}>{t('ui.groups.new')}</button>}
      </Head>
      <div className="search">
        <input type="search" value={q} onChange={(e) => setQ(e.target.value)} placeholder={t('ui.groups.search')} aria-label={t('ui.groups.search')} />
        {groups.data && <span className="muted">{t('ui.common.showing', { shown: groups.data.items.length, total: f.int(groups.data.total) })}</span>}
      </div>
      <ErrorNote error={groups.error} />
      <div className="tablewrap">
        <table>
          <thead><tr><th>{t('ui.groups.col.group')}</th><th>{t('ui.groups.col.kind')}</th><th>{t('ui.groups.col.members')}</th><th>{t('ui.groups.col.grants')}</th></tr></thead>
          <tbody>
            {groups.isPending && <tr><td colSpan={4}><Loading /></td></tr>}
            {groups.data?.items.length === 0 && <tr><td colSpan={4}><Empty /></td></tr>}
            {groups.data?.items.map((g) => {
              const open = () => { setAdding(false); nav(`/groups/${encodeURIComponent(g.name)}`) }
              return (
                <tr key={g.id} className="row" onClick={open}>
                  <td><RowButton onClick={open}>{g.name}</RowButton><br /><span className="muted">{f.name(g.display_name)}</span></td>
                  <td>{t(`ui.group.kind.${g.kind}`)}</td>
                  <td className="num">{f.int(g.member_count)}</td>
                  <td className="num">{f.int(g.grant_count)}</td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
      <GroupDrawer name={adding ? undefined : name} onClose={close} />
      <NewGroupDrawer open={adding} onClose={closeAdd} />
    </section>
  )
}

function NewGroupDrawer({ open, onClose }: { open: boolean; onClose: () => void }) {
  const t = useT()
  const qc = useQueryClient()
  const nav = useNavigate()
  const toast = useToast()
  const [name, setName] = useState('')
  const [displayName, setDisplayName] = useState('')
  const create = useMutation({
    mutationFn: () => api.createGroup({ name: name.trim(), display_name: { en: displayName.trim() || name.trim() } }),
    onSuccess: (g) => {
      for (const k of invalidateGroups) void qc.invalidateQueries({ queryKey: [k] })
      toast(t('ui.group.created_toast', { name: g.name }))
      setName(''); setDisplayName('')
      onClose()
      nav(`/groups/${encodeURIComponent(g.name)}`)
    },
  })
  const submit = (e: FormEvent) => { e.preventDefault(); create.mutate() }
  return (
    <Drawer open={open} onClose={onClose} labelCode="ui.group.new_title" title={t('ui.group.new_title')}>
      <form onSubmit={submit}>
        <Field labelCode="ui.group.new_name" hintCode="ui.group.new_name_hint" value={name} onChange={(e) => setName(e.target.value)} required autoComplete="off" autoCapitalize="none" spellCheck={false} pattern="[a-z0-9][a-z0-9._\-]*" />
        <Field labelCode="ui.group.new_display_name" value={displayName} onChange={(e) => setDisplayName(e.target.value)} autoComplete="off" />
        <ErrorNote error={create.error} />
        <div className="actions">
          <button type="submit" className="btn primary" disabled={create.isPending}>{t(create.isPending ? 'ui.common.working' : 'ui.group.create')}</button>
          <button type="button" className="btn quiet" onClick={onClose}>{t('ui.common.cancel')}</button>
        </div>
      </form>
    </Drawer>
  )
}

function GroupDrawer({ name, onClose }: { name: string | undefined; onClose: () => void }) {
  const t = useT()
  const f = useFormat()
  const qc = useQueryClient()
  const nav = useNavigate()
  const toast = useToast()
  const { can } = useSession()
  const open = !!name
  const g = useQuery({ queryKey: ['group', name], queryFn: () => api.group(name!), enabled: open })
  const d = g.data
  const [member, setMember] = useState('')
  const [kind, setKind] = useState<MemberChange['member_kind']>('principal')
  const refresh = () => { for (const k of invalidateGroups) void qc.invalidateQueries({ queryKey: [k] }) }
  const add = useMutation({
    mutationFn: (body: MemberChange) => api.addMember(name!, body),
    onSuccess: (_d, body) => { toast(t('ui.group.member_added_toast', { member: body.member, group: name })); setMember(''); refresh() },
  })
  const remove = useMutation({
    mutationFn: (body: MemberChange) => api.removeMember(name!, body),
    onSuccess: (_d, body) => { toast(t('ui.group.member_removed_toast', { member: body.member, group: name })); refresh() },
  })

  return (
    <Drawer open={open} onClose={onClose} labelCode="ui.group.details" title={name ?? ''} subtitle={d ? `${f.shortId(d.id)} · ${t(`ui.group.kind.${d.kind}`)}` : undefined}>
      <ErrorNote error={g.error ?? add.error ?? remove.error} />
      {g.isPending && <Loading />}
      {d && (
        <>
          <p className="muted">{f.name(d.display_name)}</p>
          <dl className="kv">
            <dt>{t('ui.group.kind')}</dt><dd>{t(`ui.group.kind.${d.kind}`)}</dd>
            <dt>{t('ui.group.members')}</dt><dd className="num">{f.int(d.member_count ?? d.members.length)}</dd>
            <dt>{t('ui.group.grants')}</dt><dd className="num">{f.int(d.grant_count ?? d.grants.length)}</dd>
          </dl>
          <div className="section">
            <h3>{t('ui.group.members')}</h3>
            {can('groups.write') && d.kind === 'static' && (
              <form className="inline" style={{ marginBottom: 8 }} onSubmit={(e) => { e.preventDefault(); if (member.trim()) add.mutate({ member_kind: kind, member: member.trim() }) }}>
                <SelectField labelCode="ui.group.member_kind" value={kind} onChange={(e) => setKind(e.target.value as MemberChange['member_kind'])}
                  options={[['principal', 'ui.group.member_kind.principal'], ['group', 'ui.group.member_kind.group']]} />
                <Field labelCode="ui.group.member_username" value={member} onChange={(e) => setMember(e.target.value)} autoComplete="off" autoCapitalize="none" spellCheck={false} />
                <button type="submit" className="btn" disabled={!member.trim() || add.isPending}>{t('ui.group.add_member')}</button>
              </form>
            )}
            <div className="list">
              {d.members.length === 0 && <div><span className="muted">{t('ui.group.members_empty')}</span></div>}
              {d.members.map((m) => {
                const label = m.kind === 'group' ? (m.name ?? m.id) : f.name(m.display_name, m.username ?? m.name ?? m.id)
                const ref = m.username ?? m.name ?? m.id
                return (
                  <div key={`${m.kind}:${m.id}`}>
                    <span>
                      <button type="button" className="rowlink" onClick={() => nav(m.kind === 'group' ? `/groups/${encodeURIComponent(ref)}` : `/people/${encodeURIComponent(m.id)}`)}>{label}</button>
                      {' '}<span className="muted mono">{ref}</span>
                    </span>
                    <span className="actions">
                      {m.state ? <StatePill family="ui.state" value={m.state} /> : <span className="chip">{t(`ui.group.member_kind.${m.kind}`)}</span>}
                      {can('groups.write') && d.kind === 'static' && (
                        <button type="button" className="btn quiet danger" disabled={remove.isPending}
                          onClick={() => { if (confirm(t('ui.common.confirm_remove_member', { member: ref, group: name }))) remove.mutate({ member_kind: m.kind === 'group' ? 'group' : 'principal', member: ref }) }}>{t('ui.common.remove')}</button>
                      )}
                    </span>
                  </div>
                )
              })}
            </div>
          </div>
          <div className="section">
            <h3>{t('ui.group.grants')}</h3>
            <div className="list">
              {d.grants.length === 0 && <div><span className="muted">{t('ui.group.grants_empty')}</span></div>}
              {d.grants.map((gr) => (
                <div key={gr.id}>
                  <span>{gr.role} · <span className="mono">{gr.resource.type}:{gr.resource.id}</span>{gr.condition ? <><br /><span className="mono muted">{gr.condition}</span></> : null}</span>
                  {gr.condition_class ? <Pill value={gr.condition_class} label={gr.condition_class} /> : <Dash />}
                </div>
              ))}
            </div>
          </div>
        </>
      )}
    </Drawer>
  )
}
