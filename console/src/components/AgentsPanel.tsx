import { useRef, useState, type FormEvent } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, type AgentDetail, type HeldRight } from '../api'
import { useT } from '../i18n/catalog'
import { useFormat } from '../lib/format'
import { useToast } from './Toast'
import { Drawer } from './Drawer'
import { Field } from './Form'
import { Empty, ErrorNote, Loading, StatePill } from './bits'

const invalidate = ['agents', 'agent', 'users', 'user', 'grants', 'summary', 'why', 'audit']

/**
 * A person's agents (SPEC-agents): create one, hand it a token, hand it
 * rights the owner holds, suspend it. With `owner` unset an admin sees every
 * agent; a member always sees their own.
 */
export function AgentsPanel({ owner, canCreate = true }: { owner?: string; canCreate?: boolean }) {
  const t = useT()
  const f = useFormat()
  const qc = useQueryClient()
  const toast = useToast()
  const list = useQuery({ queryKey: ['agents', owner ?? ''], queryFn: () => api.agents(owner) })
  const [adding, setAdding] = useState(false)
  const [form, setForm] = useState({ username: '', display: '' })
  const [open, setOpen] = useState<string | null>(null)
  const create = useMutation({
    mutationFn: () => api.createAgent({ username: form.username.trim(), display_name: { en: form.display.trim() || form.username.trim() }, owner }),
    onSuccess: (a) => {
      for (const k of invalidate) void qc.invalidateQueries({ queryKey: [k] })
      toast(t('ui.agents.created_toast', { name: a.display_name }))
      setForm({ username: '', display: '' }); setAdding(false); setOpen(a.id)
    },
  })
  const submit = (e: FormEvent) => { e.preventDefault(); create.mutate() }
  return (
    <div className="section">
      <div className="row-head">
        <h3>{t('ui.agents.title')}</h3>
        {canCreate && <button type="button" className="btn" aria-expanded={adding} onClick={() => setAdding(!adding)}>{t('ui.agents.new')}</button>}
      </div>
      <p className="muted">{t('ui.agents.intro')}</p>
      <ErrorNote error={list.error ?? create.error} />
      {adding && (
        <form className="subform" onSubmit={submit}>
          <Field labelCode="ui.agents.username" hintCode="ui.agents.username_hint" value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} required autoFocus autoComplete="off" autoCapitalize="none" spellCheck={false} />
          <Field labelCode="ui.agents.display_name" value={form.display} onChange={(e) => setForm({ ...form, display: e.target.value })} autoComplete="off" />
          <div className="actions">
            <button type="submit" className="btn primary" disabled={create.isPending}>{t(create.isPending ? 'ui.common.working' : 'ui.agents.create')}</button>
            <button type="button" className="btn quiet" onClick={() => setAdding(false)}>{t('ui.common.cancel')}</button>
          </div>
        </form>
      )}
      {list.isPending && <Loading />}
      {list.data?.items.length === 0 && !adding && <Empty code="ui.agents.empty" />}
      {list.data && list.data.items.length > 0 && (
        <table className="table compact">
          <thead><tr><th>{t('ui.agents.col.agent')}</th>{!owner && <th>{t('ui.agents.col.owner')}</th>}<th>{t('ui.agents.col.token')}</th><th>{t('ui.agents.col.rights')}</th><th>{t('ui.agents.col.state')}</th></tr></thead>
          <tbody>
            {list.data.items.map((a) => (
              <tr key={a.id} className="row" tabIndex={0} onClick={() => setOpen(a.id)} onKeyDown={(e) => { if (e.key === 'Enter') setOpen(a.id) }}>
                <td><b>{a.display_name}</b> <span className="muted mono">{a.username}</span></td>
                {!owner && <td>{a.owner?.name ?? ''}</td>}
                <td className={a.token.active ? 'num' : 'muted'}>{a.token.active ? t('ui.agents.token_issued', { time: f.relDay(a.token.issued_at ?? '') }) : t('ui.agents.token_none')}</td>
                <td className="num">{f.int(a.grant_count)}</td>
                <td><StatePill family="ui.state" value={a.state} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <AgentDrawer id={open} onClose={() => setOpen(null)} />
    </div>
  )
}

function AgentDrawer({ id, onClose }: { id: string | null; onClose: () => void }) {
  const t = useT()
  const f = useFormat()
  const qc = useQueryClient()
  const toast = useToast()
  const detail = useQuery({ queryKey: ['agent', id], queryFn: () => api.agent(id!), enabled: !!id })
  const [token, setToken] = useState<string | null>(null)
  const tokenField = useRef<HTMLInputElement>(null)
  const [right, setRight] = useState('')
  const refresh = () => { for (const k of invalidate) void qc.invalidateQueries({ queryKey: [k] }) }
  const issue = useMutation({ mutationFn: () => api.agentToken(id!), onSuccess: (r) => { setToken(r.token); refresh(); toast(t('ui.agents.token_issued_toast')) } })
  const revokeToken = useMutation({ mutationFn: () => api.agentTokenRevoke(id!), onSuccess: () => { setToken(null); refresh(); toast(t('ui.agents.token_revoked_toast')) } })
  const setState = useMutation({ mutationFn: (state: 'active' | 'suspended') => api.agentState(id!, state), onSuccess: refresh })
  const grant = useMutation({
    mutationFn: (h: HeldRight) => api.agentGrant(id!, { role: h.role, resource_type: h.resource_type, resource_id: h.resource_id }),
    onSuccess: () => { setRight(''); refresh(); toast(t('ui.agents.right_added_toast')) },
  })
  const revokeGrant = useMutation({ mutationFn: (gid: string) => api.agentGrantRevoke(id!, gid), onSuccess: () => { refresh(); toast(t('ui.agents.right_removed_toast')) } })
  const a: AgentDetail | undefined = detail.data
  const key = (h: HeldRight) => `${h.resource_type}:${h.resource_id}:${h.role}`
  const notYet = (a?.grantable ?? []).filter((h) => !a?.grants.some((g) => g.role === h.role && g.resource.type === h.resource_type && g.resource.id === h.resource_id))
  const copy = async () => {
    try { await navigator.clipboard.writeText(token ?? ''); toast(t('ui.common.copied')) } catch { tokenField.current?.focus(); tokenField.current?.select() }
  }
  const close = () => { setToken(null); setRight(''); onClose() }
  return (
    <Drawer open={!!id} onClose={close} labelCode="ui.agents.drawer_title" title={a?.display_name ?? t('ui.agents.drawer_title')} subtitle={a ? t('ui.agents.owned_by', { name: a.owner?.name ?? '' }) : undefined}>
      <ErrorNote error={detail.error ?? issue.error ?? revokeToken.error ?? setState.error ?? grant.error ?? revokeGrant.error} />
      {detail.isPending && id && <Loading />}
      {a && (
        <>
          <div className="actions">
            <button type="button" className="btn" disabled={setState.isPending} onClick={() => setState.mutate(a.state === 'suspended' ? 'active' : 'suspended')}>
              {t(a.state === 'suspended' ? 'ui.person.reactivate' : 'ui.person.suspend')}
            </button>
          </div>

          <h3>{t('ui.agents.token_title')}</h3>
          <p className="muted">{a.token.active ? t('ui.agents.token_issued', { time: f.relDay(a.token.issued_at ?? '') }) : t('ui.agents.token_none')}</p>
          {token ? (
            <>
              <p className="note">{t('ui.agents.token_once')}</p>
              <div className="inline">
                <input ref={tokenField} className="input token" readOnly value={token} onFocus={(e) => e.target.select()} aria-label={t('ui.agents.token_title')} />
                <button type="button" className="btn" onClick={() => void copy()}>{t('ui.common.copy')}</button>
              </div>
            </>
          ) : (
            <div className="actions">
              <button type="button" className="btn primary" disabled={issue.isPending} onClick={() => issue.mutate()}>{t(a.token.active ? 'ui.agents.rotate_token' : 'ui.agents.issue_token')}</button>
              {a.token.active && <button type="button" className="btn quiet danger" disabled={revokeToken.isPending} onClick={() => revokeToken.mutate()}>{t('ui.agents.revoke_token')}</button>}
            </div>
          )}
          <p className="muted" style={{ marginTop: 8 }}>{t('ui.agents.mcp_hint', { url: `${location.origin}/mcp` })}</p>

          <h3>{t('ui.agents.rights_title')}</h3>
          <p className="muted">{t('ui.agents.rights_intro', { name: a.owner?.name ?? '' })}</p>
          {a.grants.length === 0 && <p className="muted">{t('ui.agents.rights_none')}</p>}
          {a.grants.length > 0 && (
            <ul className="list">
              {a.grants.map((g) => (
                <li key={g.id} className="inline">
                  <span><b>{g.role}</b> <span className="muted">{t('ui.agents.on')}</span> <span className="mono">{g.resource.type}:{g.resource.id}</span></span>
                  <button type="button" className="btn quiet danger" disabled={revokeGrant.isPending} onClick={() => revokeGrant.mutate(g.id)}>{t('ui.access.revoke')}</button>
                </li>
              ))}
            </ul>
          )}
          {notYet.length > 0 ? (
            <div className="inline" style={{ marginTop: 8 }}>
              <select className="input" value={right} onChange={(e) => setRight(e.target.value)} aria-label={t('ui.agents.add_right')}>
                <option value="">{t('ui.agents.add_right')}</option>
                {notYet.map((h) => <option key={key(h)} value={key(h)}>{t('ui.agents.right_option', { role: h.role, resource: `${h.resource_type}:${h.resource_id}` })}</option>)}
              </select>
              <button type="button" className="btn" disabled={!right || grant.isPending} onClick={() => { const h = notYet.find((x) => key(x) === right); if (h) grant.mutate(h) }}>{t('ui.common.add')}</button>
            </div>
          ) : a.grantable.length === 0 ? <p className="muted">{t('ui.agents.owner_holds_nothing')}</p> : null}
        </>
      )}
    </Drawer>
  )
}
