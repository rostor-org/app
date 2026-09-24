import { useEffect, useRef, type ReactNode } from 'react'
import { useT } from '../i18n/catalog'

interface Props {
  open: boolean
  onClose: () => void
  labelCode: string
  title: ReactNode
  subtitle?: ReactNode
  children: ReactNode
}

/** Slide-in panel over the list, as in the mockup. Escape closes; focus moves in on open and back on close. */
export function Drawer({ open, onClose, labelCode, title, subtitle, children }: Props) {
  const t = useT()
  const ref = useRef<HTMLElement>(null)
  const returnTo = useRef<Element | null>(null)

  useEffect(() => {
    if (!open) return
    returnTo.current = document.activeElement
    ref.current?.focus({ preventScroll: true })
    // Only the topmost open drawer answers Escape, so a drawer stacked over
    // another (register badge over the person panel) closes one at a time.
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== 'Escape') return
      const open = document.querySelectorAll('.drawer.open')
      if (open.length && open[open.length - 1] !== ref.current) return
      e.stopPropagation(); onClose()
    }
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('keydown', onKey)
      const el = returnTo.current
      if (el instanceof HTMLElement && document.contains(el)) el.focus({ preventScroll: true })
    }
  }, [open, onClose])

  return (
    <aside ref={ref} className={open ? 'drawer open' : 'drawer'} role="dialog" aria-label={t(labelCode)} aria-hidden={!open} tabIndex={-1}>
      {open && (
        <>
          <div className="dhead">
            <div><h2>{title}</h2>{subtitle && <div className="muted mono">{subtitle}</div>}</div>
            <button type="button" className="btn quiet" onClick={onClose}>{t('ui.common.close')}</button>
          </div>
          {children}
        </>
      )}
    </aside>
  )
}
