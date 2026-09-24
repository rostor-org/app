import { useCallback, useState, type FormEvent } from 'react'
import { useNavigate, useParams } from 'react-router'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, type User } from '../api'
import { useT } from '../i18n/catalog'
import { useSession } from '../auth/session'
import { useFormat } from '../lib/format'
import { useToast } from '../components/Toast'
import { Drawer } from '../components/Drawer'
import { Field, SelectField } from '../components/Form'
import { Chips, Empty, ErrorNote, Head, Loading, RowButton, Stat, StatePill } from '../components/bits'
import { PersonPanel, invalidatePeople } from '../components/PersonPanel'

export function People() {
  const t = useT()
  const f = useFormat()
  const nav = useNavigate()
  const toast = useToast()
  const { can } = useSession()
  const { id } = useParams()
  const [q, setQ] = useState('')
  const [adding, setAdding] = useState(false)
  const summary = useQuery({ queryKey: ['summary'], queryFn: () => api.summary() })
  const users = useQuery({ queryKey: ['users', q], queryFn: () => api.users(q || undefined) })
  const close = useCallback(() => nav('/people'), [nav])
  const closeAdd = useCallback(() => setAdding(false), [])

  return (
    <section>
      <Head titleCode="ui.people.title" subCode="ui.people.subtitle">
        <button type="button" className="btn quiet" onClick={() => toast(t('ui.common.not_available'))}>{t('ui.people.import')}</button>
        {can('users.write') && <button type="button" className="btn primary" onClick={() => { nav('/people'); setAdding(true) }}>{t('ui.people.add')}</button>}
      </Head>
      <div className="strip">
        <Stat value={f.int(summary.data?.people.active)} labelCode="ui.people.stat.active" />
        <Stat value={f.int(summary.data?.people.suspended)} labelCode="ui.people.stat.suspended" />
        <Stat value={f.int(summary.data?.people.applicants)} labelCode="ui.people.stat.applicants" />
        <Stat value={f.int(summary.data?.people.service_accounts)} labelCode="ui.people.stat.service" />
      </div>
      <div className="search">
        <input type="search" value={q} onChange={(e) => setQ(e.target.value)} placeholder={t('ui.people.search')} aria-label={t('ui.people.search')} />
        {users.data && <span className="muted">{t('ui.common.showing', { shown: users.data.items.length, total: f.int(users.data.total) })}</span>}
      </div>
      <ErrorNote error={users.error} />
      <div className="tablewrap">
        <table>
          <thead><tr>
            <th>{t('ui.people.col.person')}</th><th>{t('ui.people.col.username')}</th><th>{t('ui.people.col.groups')}</th>
            <th>{t('ui.people.col.methods')}</th><th>{t('ui.people.col.state')}</th><th>{t('ui.people.col.last_sign_in')}</th>
          </tr></thead>
          <tbody>
            {users.isPending && <tr><td colSpan={6}><Loading /></td></tr>}
            {users.data?.items.length === 0 && <tr><td colSpan={6}><Empty /></td></tr>}
            {users.data?.items.map((u) => <PersonRow key={u.id} u={u} onOpen={() => { setAdding(false); nav(`/people/${encodeURIComponent(u.id)}`) }} />)}
          </tbody>
        </table>
      </div>
      <PersonDrawer id={adding ? undefined : id} onClose={close} />
      <NewPersonDrawer open={adding} onClose={closeAdd} />
    </section>
  )
}

function PersonRow({ u, onOpen }: { u: User; onOpen: () => void }) {
  const t = useT()
  const f = useFormat()
  return (
    <tr className="row" onClick={onOpen}>
      <td><RowButton onClick={onOpen}>{f.name(u.display_name, u.username)}</RowButton>{u.kind === 'service' && <> <span className="muted">{t('ui.common.service')}</span></>}</td>
      <td className="mono">{u.username}</td>
      <td><Chips items={u.groups.map((g) => g.name)} /></td>
      <td>{u.methods.length === 0 ? <span className="muted">{t('ui.people.methods_none')}</span>
        : u.methods.map((m, i) => <span key={i}>{i > 0 && ' '}<span className="al">{m.method}</span></span>)}</td>
      <td><StatePill family="ui.state" value={u.state} /></td>
      <td className={u.last_sign_in ? 'num' : 'muted'}>{u.last_sign_in ? `${f.relDay(u.last_sign_in.ts)} · ${u.last_sign_in.resource}` : t('ui.time.never')}</td>
    </tr>
  )
}

/** Create → optional password binding → optional group membership, then open the new person. */
function NewPersonDrawer({ open, onClose }: { open: boolean; onClose: () => void }) {
  const t = useT()
  const qc = useQueryClient()
  const nav = useNavigate()
  const toast = useToast()
  const [username, setUsername] = useState('')
  const [displayName, setDisplayName] = useState('')
  const [password, setPassword] = useState('')
  const [group, setGroup] = useState('')
  const groups = useQuery({ queryKey: ['groups', ''], queryFn: () => api.groups(), enabled: open })
  const create = useMutation({
    mutationFn: async () => {
      const p = await api.createUser({ username: username.trim(), display_name: { en: displayName.trim() || username.trim() } })
      if (password) await api.enrollBinding(p.id, { method: 'password', fields: { password } })
      if (group) await api.addMember(group, { member_kind: 'principal', member: p.username ?? username.trim() })
      return p
    },
    onSuccess: (p) => {
      for (const k of invalidatePeople) void qc.invalidateQueries({ queryKey: [k] })
      toast(t('ui.person.created_toast', { name: displayName.trim() || username.trim() }))
      setUsername(''); setDisplayName(''); setPassword(''); setGroup('')
      onClose()
      nav(`/people/${encodeURIComponent(p.id)}`)
    },
  })
  const submit = (e: FormEvent) => { e.preventDefault(); create.mutate() }
  return (
    <Drawer open={open} onClose={onClose} labelCode="ui.person.new_title" title={t('ui.person.new_title')}>
      <form onSubmit={submit}>
        <Field labelCode="ui.person.new_username" value={username} onChange={(e) => setUsername(e.target.value)} required autoComplete="off" autoCapitalize="none" spellCheck={false} />
        <Field labelCode="ui.person.new_display_name" value={displayName} onChange={(e) => setDisplayName(e.target.value)} autoComplete="off" />
        <Field labelCode="ui.person.new_password" hintCode="ui.person.new_password_hint" type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="new-password" minLength={8} />
        <SelectField labelCode="ui.person.new_group" value={group} onChange={(e) => setGroup(e.target.value)}
          options={[['', 'ui.person.new_group_none'], ...(groups.data?.items.map((g) => [g.name, undefined] as [string, undefined]) ?? [])]} />
        <ErrorNote error={create.error} />
        <div className="actions">
          <button type="submit" className="btn primary" disabled={create.isPending}>{t(create.isPending ? 'ui.common.working' : 'ui.person.create')}</button>
          <button type="button" className="btn quiet" onClick={onClose}>{t('ui.common.cancel')}</button>
        </div>
      </form>
    </Drawer>
  )
}

function PersonDrawer({ id, onClose }: { id: string | undefined; onClose: () => void }) {
  const f = useFormat()
  const open = !!id
  // Same query key as the panel inside: one fetch serves the title and the body.
  const user = useQuery({ queryKey: ['user', id], queryFn: () => api.user(id!), enabled: open })
  const u = user.data
  const name = u ? f.name(u.display_name, u.username) : (id ?? '')
  return (
    <Drawer open={open} onClose={onClose} labelCode="ui.person.details" title={name} subtitle={u ? `${f.shortId(u.id)} · ${u.username}` : undefined}>
      {id && <PersonPanel id={id} />}
    </Drawer>
  )
}
