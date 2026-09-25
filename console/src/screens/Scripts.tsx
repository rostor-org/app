import { useCallback, useEffect, useId, useState, type FormEvent } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, type List, type Script, type ScriptAssignment, type ScriptMode, type ScriptRun, type ScriptTargetKind } from '../api'
import { useT, type T } from '../i18n/catalog'
import { useSession } from '../auth/session'
import { useFormat, type Fmt } from '../lib/format'
import { useToast } from '../components/Toast'
import { Drawer } from '../components/Drawer'
import { Field } from '../components/Form'
import { Dash, Empty, ErrorNote, Head, Loading, Pill, RowButton } from '../components/bits'

const invalidate = ['scripts', 'script', 'audit']
/** Select value for the "every workstation" target; groups are `group:<name>`. */
const ALL_TARGET = 'all:workstation'
const MODES: ScriptMode[] = ['immediate', 'signin']
/** Run statuses are not audit outcomes, so map them onto the vocabulary tone() colours. */
const RUN_TONE: Record<string, string> = { ok: 'allow', failed: 'deny', timeout: 'pending', error: 'error' }
const emptyForm = { name: '', description: '', body: '' }

/**
 * Scripts (SPEC-scripts): PowerShell text assigned to every workstation or to
 * a group, run by the agent in position order. The list is the order; the
 * drawer edits one script, its assignments and shows its run history.
 */
export function Scripts() {
  const t = useT()
  const f = useFormat()
  const qc = useQueryClient()
  const { can } = useSession()
  const canRead = can('scripts.read')
  const canWrite = can('scripts.write')
  const list = useQuery({ queryKey: ['scripts'], queryFn: () => api.scripts(), enabled: canRead })
  const [open, setOpen] = useState<string | null>(null)
  const [creating, setCreating] = useState(false)
  const closeDrawer = useCallback(() => setOpen(null), [])
  const closeNew = useCallback(() => setCreating(false), [])
  const order = useMutation({
    mutationFn: (ids: string[]) => api.orderScripts(ids),
    // Optimistic: the rows swap at once; the server's order replaces it once the call settles.
    onMutate: async (ids) => {
      await qc.cancelQueries({ queryKey: ['scripts'] })
      const prev = qc.getQueryData<List<Script>>(['scripts'])
      if (prev) {
        const byId = new Map(prev.items.map((s) => [s.id, s]))
        qc.setQueryData<List<Script>>(['scripts'], { ...prev, items: ids.flatMap((id, i) => { const s = byId.get(id); return s ? [{ ...s, position: i + 1 }] : [] }) })
      }
      return { prev }
    },
    onError: (_e, _ids, ctx) => { if (ctx?.prev) qc.setQueryData(['scripts'], ctx.prev) },
    onSettled: () => { void qc.invalidateQueries({ queryKey: ['scripts'] }) },
  })
  const items = list.data?.items ?? []
  const move = (i: number, dir: -1 | 1) => {
    const ids = items.map((s) => s.id)
    const j = i + dir
    const a = ids[i], b = ids[j]
    if (a === undefined || b === undefined) return
    ids[i] = b; ids[j] = a
    order.mutate(ids)
  }
  const show = (id: string) => { setCreating(false); setOpen(id) }

  if (!canRead) {
    return (
      <section>
        <Head titleCode="ui.scripts.title" subCode="ui.scripts.subtitle" />
        <p className="note">{t('ui.scripts.no_access')}</p>
      </section>
    )
  }

  return (
    <section>
      <Head titleCode="ui.scripts.title" subCode="ui.scripts.subtitle">
        {canWrite && <button type="button" className="btn primary" onClick={() => { setOpen(null); setCreating(true) }}>{t('ui.scripts.new')}</button>}
      </Head>
      <ErrorNote error={list.error ?? order.error} />
      <div className="tablewrap">
        <table>
          <thead><tr>
            <th className="num">{t('ui.scripts.col.position')}</th><th>{t('ui.scripts.col.script')}</th><th>{t('ui.scripts.col.version')}</th>
            <th>{t('ui.scripts.col.assignments')}</th><th>{t('ui.scripts.col.last_run')}</th>{canWrite && <th />}
          </tr></thead>
          <tbody>
            {list.isPending && <tr><td colSpan={6}><Loading /></td></tr>}
            {list.data?.items.length === 0 && <tr><td colSpan={6}><Empty code="ui.scripts.empty" /></td></tr>}
            {items.map((s, i) => (
              <tr key={s.id} className="row" onClick={() => show(s.id)}>
                {/* The row number is the order; the list arrives sorted by position, so no assumption about its base is needed. */}
                <td className="num muted">{i + 1}</td>
                <td><RowButton onClick={() => show(s.id)}>{s.name}</RowButton>{s.description && <small className="muted">{s.description}</small>}</td>
                <td className="num">{t('ui.scripts.version', { version: s.version })}</td>
                <td>{s.assignments.length === 0 ? <Dash /> : <div className="chips">{s.assignments.map((a) => <span key={a.id} className="chip">{assignmentLabel(a, t)}</span>)}</div>}</td>
                <td>
                  {s.last_run
                    ? <><RunPill status={s.last_run.status} /> <span className="muted num">{t('ui.scripts.last_run_meta', { time: f.relDay(s.last_run.at), device: s.last_run.device.name })}</span></>
                    : <span className="muted">{t('ui.scripts.never_run')}</span>}
                </td>
                {canWrite && (
                  <td className="movers nowrap">
                    <button type="button" className="btn quiet" disabled={i === 0 || order.isPending} onClick={(e) => { e.stopPropagation(); move(i, -1) }}>{t('ui.scripts.move_up')}</button>
                    <button type="button" className="btn quiet" disabled={i === items.length - 1 || order.isPending} onClick={(e) => { e.stopPropagation(); move(i, 1) }}>{t('ui.scripts.move_down')}</button>
                  </td>
                )}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <ScriptDrawer id={open} onClose={closeDrawer} canWrite={canWrite} />
      <NewScriptDrawer open={creating} onClose={closeNew} onCreated={show} />
    </section>
  )
}

function RunPill({ status }: { status: string }) {
  const t = useT()
  return <Pill value={RUN_TONE[status] ?? status} label={t(`ui.scripts.status.${status}`)} />
}

/** "every workstation · now", "group laser-certified · at sign-in". */
function assignmentLabel(a: ScriptAssignment, t: T): string {
  const target = a.target.kind === 'all' ? t('ui.scripts.target.all') : t('ui.scripts.target.group', { name: a.target.name })
  return t('ui.scripts.assignment', { target, mode: t(`ui.scripts.mode_short.${a.mode}`) })
}

/** The PowerShell body: monospace, no spell-check, tall enough to read a whole script. */
function BodyField({ value, onChange, readOnly }: { value: string; onChange: (v: string) => void; readOnly?: boolean }) {
  const t = useT()
  const id = useId()
  return (
    <div className="field">
      <label htmlFor={id}>{t('ui.scripts.body')}</label>
      <textarea id={id} className="input mono" rows={16} spellCheck={false} autoCapitalize="none" autoComplete="off" wrap="off" required readOnly={readOnly}
        value={value} onChange={(e) => onChange(e.target.value)} />
      <small className="muted">{t('ui.scripts.body_hint')}</small>
    </div>
  )
}

/**
 * One script: editor (a changed body makes a new version), assignments, and
 * the last runs the agents reported. Every write needs an AL2 session; the
 * server's request.assurance_required renders through ErrorNote.
 */
function ScriptDrawer({ id, onClose, canWrite }: { id: string | null; onClose: () => void; canWrite: boolean }) {
  const t = useT()
  const f = useFormat()
  const qc = useQueryClient()
  const toast = useToast()
  const detail = useQuery({ queryKey: ['script', id], queryFn: () => api.script(id!), enabled: !!id })
  const groups = useQuery({ queryKey: ['groups', ''], queryFn: () => api.groups(), enabled: !!id && canWrite, staleTime: 60_000 })
  const sc = detail.data
  const [form, setForm] = useState(emptyForm)
  const [assign, setAssign] = useState<{ target: string; mode: ScriptMode }>({ target: '', mode: 'immediate' })
  // The form follows the server copy: on open, after a save, and when a live update lands
  // (react-query keeps the same object while the data is unchanged, so typing is not disturbed).
  useEffect(() => { if (sc) setForm({ name: sc.name, description: sc.description, body: sc.body }) }, [sc])
  const refresh = () => { for (const k of invalidate) void qc.invalidateQueries({ queryKey: [k] }) }
  const dirty = !!sc && (form.name !== sc.name || form.description !== sc.description || form.body !== sc.body)
  const save = useMutation({
    mutationFn: () => api.updateScript(id!, { name: form.name.trim(), description: form.description.trim(), body: form.body }),
    onSuccess: (r) => { refresh(); toast(t('ui.scripts.saved_toast', { version: r.version })) },
  })
  const add = useMutation({
    mutationFn: () => {
      const [kind, target] = assign.target.split(/:(.*)/, 2)
      return api.assignScript(id!, { target_kind: (kind ?? 'all') as ScriptTargetKind, target: target ?? '', mode: assign.mode })
    },
    onSuccess: () => { setAssign({ target: '', mode: 'immediate' }); refresh(); toast(t('ui.scripts.assigned_toast')) },
  })
  const remove = useMutation({ mutationFn: (aid: string) => api.unassignScript(id!, aid), onSuccess: () => { refresh(); toast(t('ui.scripts.unassigned_toast')) } })
  const del = useMutation({
    mutationFn: () => api.deleteScript(id!),
    onSuccess: () => { refresh(); toast(t('ui.scripts.deleted_toast', { name: sc?.name ?? '' })); onClose() },
  })
  const confirmDelete = () => { if (sc && confirm(t('ui.scripts.confirm_delete', { name: sc.name }))) del.mutate() }
  const submit = (e: FormEvent) => { e.preventDefault(); if (dirty && form.name.trim() && form.body.trim()) save.mutate() }
  const close = () => { save.reset(); add.reset(); remove.reset(); del.reset(); onClose() }

  return (
    <Drawer open={!!id} onClose={close} labelCode="ui.scripts.drawer_title" title={sc?.name ?? t('ui.scripts.drawer_title')}
      subtitle={sc ? t('ui.scripts.updated_by', { version: sc.version, time: f.relDay(sc.updated_at), name: sc.updated_by.name }) : undefined}>
      <ErrorNote error={detail.error ?? save.error ?? add.error ?? remove.error ?? del.error ?? groups.error} />
      {detail.isPending && id && <Loading />}
      {sc && (
        <>
          <form onSubmit={submit}>
            <Field labelCode="ui.scripts.name" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} required readOnly={!canWrite} autoComplete="off" />
            <Field labelCode="ui.scripts.description" value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} readOnly={!canWrite} autoComplete="off" />
            <BodyField value={form.body} onChange={(body) => setForm({ ...form, body })} readOnly={!canWrite} />
            {canWrite && (
              <div className="actions">
                <button type="submit" className="btn primary" disabled={!dirty || save.isPending}>{t(save.isPending ? 'ui.common.working' : 'ui.common.save')}</button>
                {dirty && <span className="muted">{t('ui.scripts.unsaved')}</span>}
              </div>
            )}
          </form>

          <h3>{t('ui.scripts.assignments_title')}</h3>
          {sc.assignments.length === 0 && <p className="muted">{t('ui.scripts.assignments_empty')}</p>}
          {sc.assignments.length > 0 && (
            <ul className="list">
              {sc.assignments.map((a) => (
                <li key={a.id} className="inline">
                  <span>{assignmentLabel(a, t)}</span>
                  {canWrite && <button type="button" className="btn quiet danger" disabled={remove.isPending} onClick={() => remove.mutate(a.id)}>{t('ui.common.remove')}</button>}
                </li>
              ))}
            </ul>
          )}
          {canWrite && (
            <div className="inline" style={{ marginTop: 8 }}>
              <select className="input" value={assign.target} onChange={(e) => setAssign({ ...assign, target: e.target.value })} aria-label={t('ui.scripts.target_label')}>
                <option value="">{t('ui.scripts.target_pick')}</option>
                <option value={ALL_TARGET}>{t('ui.scripts.target_all_option')}</option>
                {(groups.data?.items ?? []).map((g) => <option key={g.id} value={`group:${g.name}`}>{t('ui.scripts.target.group', { name: g.name })}</option>)}
              </select>
              <select className="input" value={assign.mode} onChange={(e) => setAssign({ ...assign, mode: e.target.value as ScriptMode })} aria-label={t('ui.scripts.mode_label')}>
                {MODES.map((m) => <option key={m} value={m}>{t(`ui.scripts.mode.${m}`)}</option>)}
              </select>
              <button type="button" className="btn" disabled={!assign.target || add.isPending} onClick={() => add.mutate()}>{t('ui.common.add')}</button>
            </div>
          )}

          <h3>{t('ui.scripts.runs_title')}</h3>
          {sc.runs.length === 0
            ? <p className="muted">{t('ui.scripts.runs_empty')}</p>
            : <ul className="list">{sc.runs.map((r) => <RunRow key={r.id} r={r} f={f} />)}</ul>}

          {canWrite && (
            <div className="actions" style={{ marginTop: 20 }}>
              <button type="button" className="btn quiet danger" disabled={del.isPending} onClick={confirmDelete}>{t('ui.scripts.delete')}</button>
            </div>
          )}
        </>
      )}
    </Drawer>
  )
}

/** One reported run; the output tail unfolds on demand. */
function RunRow({ r, f }: { r: ScriptRun; f: Fmt }) {
  const t = useT()
  return (
    <li>
      <div className="inline">
        <b>{r.device.name}</b>
        <span className="muted num">{f.relDay(r.started_at)}</span>
        <span className="muted">{t('ui.scripts.run_meta', { version: r.version, mode: t(`ui.scripts.mode_short.${r.mode}`) })}</span>
        {r.principal && <span className="muted">{t('ui.scripts.run_for', { name: r.principal.name })}</span>}
        <RunPill status={r.status} />
        <span className="mono muted">{t('ui.scripts.exit_code', { code: r.exit_code })}</span>
      </div>
      {r.output_tail
        ? <details className="output"><summary>{t('ui.scripts.output')}</summary><pre className="code">{r.output_tail}</pre></details>
        : <small className="muted">{t('ui.scripts.output_none')}</small>}
    </li>
  )
}

function NewScriptDrawer({ open, onClose, onCreated }: { open: boolean; onClose: () => void; onCreated: (id: string) => void }) {
  const t = useT()
  const qc = useQueryClient()
  const toast = useToast()
  const [form, setForm] = useState(emptyForm)
  const create = useMutation({
    mutationFn: () => api.createScript({ name: form.name.trim(), description: form.description.trim() || undefined, language: 'powershell', body: form.body }),
    onSuccess: (s) => {
      for (const k of invalidate) void qc.invalidateQueries({ queryKey: [k] })
      toast(t('ui.scripts.created_toast', { name: s.name }))
      setForm(emptyForm)
      onCreated(s.id)
    },
  })
  const submit = (e: FormEvent) => { e.preventDefault(); if (form.name.trim() && form.body.trim()) create.mutate() }
  const cancel = () => { setForm(emptyForm); create.reset(); onClose() }
  return (
    <Drawer open={open} onClose={cancel} labelCode="ui.scripts.new_title" title={t('ui.scripts.new_title')}>
      <p className="note">{t('ui.scripts.new_note')}</p>
      <form onSubmit={submit}>
        <Field labelCode="ui.scripts.name" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} required autoFocus autoComplete="off" />
        <Field labelCode="ui.scripts.description" hintCode="ui.scripts.description_hint" value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} autoComplete="off" />
        <BodyField value={form.body} onChange={(body) => setForm({ ...form, body })} />
        <ErrorNote error={create.error} />
        <div className="actions">
          <button type="submit" className="btn primary" disabled={create.isPending}>{t(create.isPending ? 'ui.common.working' : 'ui.scripts.create')}</button>
          <button type="button" className="btn quiet" onClick={cancel}>{t('ui.common.cancel')}</button>
        </div>
      </form>
    </Drawer>
  )
}
