import type { ReactNode } from 'react'
import { ApiError } from '../api'
import { useT } from '../i18n/catalog'
import { tone } from '../lib/format'

export function Pill({ value, label, className = '' }: { value?: string; label: ReactNode; className?: string }) {
  const k = tone(value)
  return <span className={`pill ${k} ${className}`.trim()}><i />{label}</span>
}

/** State pill whose label comes from a code family, e.g. ui.state.{active}. */
export function StatePill({ family, value }: { family: string; value: string }) {
  const t = useT()
  return <Pill value={value} label={t(`${family}.${value}`)} />
}

export function Stat({ value, labelCode }: { value: ReactNode; labelCode: string }) {
  const t = useT()
  return <div className="stat"><b className="num">{value}</b><span>{t(labelCode)}</span></div>
}

export function Head({ titleCode, subCode, children }: { titleCode: string; subCode: string; children?: ReactNode }) {
  const t = useT()
  return (
    <div className="head">
      <div><h1>{t(titleCode)}</h1><div className="sub">{t(subCode)}</div></div>
      {children && <div className="actions">{children}</div>}
    </div>
  )
}

export function Chips({ items, emptyCode = 'ui.common.none' }: { items: string[]; emptyCode?: string }) {
  const t = useT()
  if (items.length === 0) return <div className="chips"><span className="chip muted">{t(emptyCode)}</span></div>
  return <div className="chips">{items.map((s) => <span key={s} className="chip">{s}</span>)}</div>
}

export function Dash() {
  const t = useT()
  return <span className="muted">{t('ui.common.none')}</span>
}

/** The API error body behind a failure (ApiError, or the mock's plain error carrying `body`), if any. */
export function apiBody(error: unknown): { code: string; params?: Record<string, unknown>; message?: string } | null {
  if (error instanceof ApiError) return error.body
  if (error && typeof error === 'object' && 'body' in error) {
    const b = (error as { body: unknown }).body
    if (b && typeof b === 'object' && 'code' in b) return b as { code: string; params?: Record<string, unknown>; message?: string }
  }
  return null
}

/** The server's rendered message for a failure, or the code through the catalog. */
export function describeError(error: unknown, t: (code: string, params?: Record<string, string>) => string): string {
  const b = apiBody(error)
  if (b) return b.message ?? t(b.code, b.params as Record<string, string>)
  return error instanceof Error ? error.message : String(error)
}

/** Renders an API failure using the server's rendered message, or the code via the catalog. */
export function ErrorNote({ error }: { error: unknown }) {
  const t = useT()
  if (!error) return null
  return <p className="form-error" role="alert">{t('ui.common.error', { message: describeError(error, t) })}</p>
}

export function Empty({ code = 'ui.common.empty' }: { code?: string }) {
  const t = useT()
  return <div className="empty">{t(code)}</div>
}

export function Loading() {
  const t = useT()
  return <div className="empty" aria-busy="true">{t('ui.common.loading')}</div>
}

/** A table row that opens something: keyboard-reachable via the button in the first cell. */
export function RowButton({ onClick, children }: { onClick: () => void; children: ReactNode }) {
  return <button type="button" className="rowlink" onClick={(e) => { e.stopPropagation(); onClick() }}>{children}</button>
}
