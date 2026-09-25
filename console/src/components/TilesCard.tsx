import { useState, type FormEvent } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, type Tile, type TileInput } from '../api'
import { useT } from '../i18n/catalog'
import { useToast } from './Toast'
import { Field, SelectField } from './Form'
import { ErrorNote, Loading, Pill } from './bits'

const invalidate = ['tiles', 'portal', 'grants', 'resources', 'audit']
const CATEGORIES: Array<[string, string]> = [['links', 'ui.portal.category.links'], ['public', 'ui.portal.category.public'], ['you', 'ui.portal.category.you'], ['admin', 'ui.portal.category.admin']]

/**
 * System → Portal tiles: the console's screens are built in; an admin adds
 * links. "Public" grants view to everyone (anonymous visitors included);
 * anything narrower is a grant on Access, like any other resource.
 */
export function TilesCard({ canWrite }: { canWrite: boolean }) {
  const t = useT()
  const qc = useQueryClient()
  const toast = useToast()
  const list = useQuery({ queryKey: ['tiles'], queryFn: () => api.tiles() })
  const refresh = () => { for (const k of invalidate) void qc.invalidateQueries({ queryKey: [k] }) }
  const empty: TileInput = { title: '', description: '', href: '', category: 'links', icon: '', public: false }
  const [form, setForm] = useState<TileInput | null>(null)
  const [editing, setEditing] = useState<string | null>(null)
  const save = useMutation({
    mutationFn: (f: TileInput) => editing ? api.updateTile(editing, f) : api.createTile(f),
    onSuccess: (tile) => { refresh(); toast(t('ui.tiles.saved_toast', { title: tile.title })); setForm(null); setEditing(null) },
  })
  const remove = useMutation({ mutationFn: (id: string) => api.deleteTile(id), onSuccess: () => { refresh(); toast(t('ui.tiles.deleted_toast')) } })
  const togglePublic = useMutation({ mutationFn: (tile: Tile) => api.updateTile(tile.id, { public: !tile.public }), onSuccess: refresh })
  const submit = (e: FormEvent) => { e.preventDefault(); if (form) save.mutate(form) }
  const edit = (tile: Tile) => { setEditing(tile.id); setForm({ title: tile.title, description: tile.description, href: tile.href, category: tile.category, icon: tile.icon, public: tile.public }) }
  const links = (list.data?.items ?? []).filter((x) => !x.builtin)
  return (
    <div className="card">
      <h3>{t('ui.tiles.title')}</h3>
      <p>{t('ui.tiles.note')}</p>
      <ErrorNote error={list.error ?? save.error ?? remove.error ?? togglePublic.error} />
      {list.isPending && <Loading />}
      {links.length === 0 && !list.isPending && <p className="muted">{t('ui.tiles.empty')}</p>}
      {links.length > 0 && (
        <ul className="list">
          {links.map((tile) => (
            <li key={tile.id} className="inline">
              <span><b>{tile.title}</b> <span className="muted mono">{tile.href}</span> {tile.public ? <Pill value="ok" label={t('ui.tiles.public')} /> : <span className="muted">{t('ui.tiles.grants', { n: String(tile.grants) })}</span>}</span>
              {canWrite && (
                <span className="actions">
                  <button type="button" className="btn quiet" onClick={() => togglePublic.mutate(tile)}>{t(tile.public ? 'ui.tiles.make_private' : 'ui.tiles.make_public')}</button>
                  <button type="button" className="btn quiet" onClick={() => edit(tile)}>{t('ui.common.edit')}</button>
                  <button type="button" className="btn quiet danger" onClick={() => { if (confirm(t('ui.tiles.confirm_delete', { title: tile.title }))) remove.mutate(tile.id) }}>{t('ui.common.delete')}</button>
                </span>
              )}
            </li>
          ))}
        </ul>
      )}
      {canWrite && !form && <div className="actions" style={{ marginTop: 10 }}><button type="button" className="btn" onClick={() => { setEditing(null); setForm(empty) }}>{t('ui.tiles.add')}</button></div>}
      {form && (
        <form className="subform" onSubmit={submit}>
          <Field labelCode="ui.tiles.field.title" value={form.title ?? ''} onChange={(e) => setForm({ ...form, title: e.target.value })} required autoFocus autoComplete="off" />
          <Field labelCode="ui.tiles.field.href" hintCode="ui.tiles.field.href_hint" className="input mono" value={form.href ?? ''} onChange={(e) => setForm({ ...form, href: e.target.value })} required autoComplete="off" spellCheck={false} />
          <Field labelCode="ui.tiles.field.description" value={form.description ?? ''} onChange={(e) => setForm({ ...form, description: e.target.value })} autoComplete="off" />
          <Field labelCode="ui.tiles.field.icon" hintCode="ui.tiles.field.icon_hint" value={form.icon ?? ''} onChange={(e) => setForm({ ...form, icon: e.target.value })} maxLength={2} autoComplete="off" />
          <SelectField labelCode="ui.tiles.field.category" value={form.category ?? 'links'} onChange={(e) => setForm({ ...form, category: e.target.value })} options={CATEGORIES} />
          <label className="check"><input type="checkbox" checked={!!form.public} onChange={(e) => setForm({ ...form, public: e.target.checked })} /> {t('ui.tiles.field.public')}</label>
          <div className="actions" style={{ marginTop: 10 }}>
            <button type="submit" className="btn primary" disabled={save.isPending}>{t(save.isPending ? 'ui.common.working' : 'ui.common.save')}</button>
            <button type="button" className="btn quiet" onClick={() => { setForm(null); setEditing(null) }}>{t('ui.common.cancel')}</button>
          </div>
        </form>
      )}
    </div>
  )
}
