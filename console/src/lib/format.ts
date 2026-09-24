import { useMemo } from 'react'
import { useT, type T } from '../i18n/catalog'

export interface Fmt {
  /** "13:59:07" */
  clock: (ts: string | number) => string
  /** "13:59" */
  time: (ts: string | number) => string
  /** "Today 13:59" / "Yesterday 19:12" / "Sep 14" — via ui.time.* codes. */
  relDay: (ts: string | number | null | undefined) => string
  /** "2026-12-31" */
  date: (ts: string | number | null | undefined) => string
  /** "in 78 days" / "today" / "3 days ago" — via ui.time.* codes. */
  relDays: (ts: string | number | null | undefined) => string
  /** Whole days from now to the instant (negative when past); null when unknown. */
  daysUntil: (ts: string | number | null | undefined) => number | null
  /** "2 h 06 m" via ui.time.duration */
  duration: (seconds: number | null | undefined) => string
  /** "18 MB" */
  bytes: (n: number | null | undefined) => string
  /** "1,184" */
  int: (n: number | null | undefined) => string
  /** Short opaque id: "usr_f40101ae…" */
  shortId: (id: string) => string
  /** Short key fingerprint: "f63294b2…4b76" */
  fingerprint: (fp: string) => string
  /** display_name may be a string or a locale map. */
  name: (v: string | Record<string, string> | undefined | null, fallback?: string) => string
}

export function makeFormat(t: T, locale: string): Fmt {
  const clock = new Intl.DateTimeFormat(locale, { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false })
  const hm = new Intl.DateTimeFormat(locale, { hour: '2-digit', minute: '2-digit', hour12: false })
  const md = new Intl.DateTimeFormat(locale, { month: 'short', day: 'numeric' })
  // Calendar dates (expiry, certificate notAfter) are UTC instants; render the UTC day so 2026-12-31T00:00Z reads as Dec 31 everywhere.
  const ymd = new Intl.DateTimeFormat(locale, { year: 'numeric', month: '2-digit', day: '2-digit', timeZone: 'UTC' })
  const num = new Intl.NumberFormat(locale)
  const toDate = (ts: string | number) => new Date(ts)
  const daysUntil = (ts: string | number | null | undefined): number | null => {
    if (ts === null || ts === undefined || ts === '') return null
    const d = toDate(ts)
    if (Number.isNaN(d.getTime())) return null
    return Math.ceil((d.getTime() - Date.now()) / 86_400_000)
  }
  const sameDay = (a: Date, b: Date) => a.getFullYear() === b.getFullYear() && a.getMonth() === b.getMonth() && a.getDate() === b.getDate()
  return {
    clock: (ts) => clock.format(toDate(ts)),
    time: (ts) => hm.format(toDate(ts)),
    relDay: (ts) => {
      if (ts === null || ts === undefined || ts === '') return t('ui.time.never')
      const d = toDate(ts)
      if (Number.isNaN(d.getTime())) return String(ts)
      const now = new Date()
      const y = new Date(now); y.setDate(now.getDate() - 1)
      if (sameDay(d, now)) return t('ui.time.today', { time: hm.format(d) })
      if (sameDay(d, y)) return t('ui.time.yesterday', { time: hm.format(d) })
      return md.format(d)
    },
    date: (ts) => {
      if (ts === null || ts === undefined || ts === '') return t('ui.time.never')
      const d = toDate(ts)
      if (Number.isNaN(d.getTime())) return String(ts)
      const p = ymd.formatToParts(d)
      const get = (k: string) => p.find((x) => x.type === k)?.value ?? ''
      return `${get('year')}-${get('month')}-${get('day')}`
    },
    daysUntil,
    relDays: (ts) => {
      const n = daysUntil(ts)
      if (n === null) return t('ui.time.never')
      if (n > 0) return t('ui.time.in_days', { n })
      if (n === 0) return t('ui.time.today_plain')
      return t('ui.time.days_ago', { n: -n })
    },
    duration: (s) => {
      if (s === null || s === undefined) return t('ui.time.never')
      const h = Math.floor(s / 3600)
      const m = Math.floor((s % 3600) / 60)
      if (h === 0) return t('ui.time.duration_m', { m })
      return t('ui.time.duration_hm', { h, m: String(m).padStart(2, '0') })
    },
    bytes: (n) => {
      if (n === null || n === undefined) return ''
      if (n < 1024) return `${n} B`
      if (n < 1024 * 1024) return `${Math.round(n / 1024)} KB`
      if (n < 1024 * 1024 * 1024) return `${Math.round(n / (1024 * 1024))} MB`
      return `${(n / (1024 * 1024 * 1024)).toFixed(1)} GB`
    },
    int: (n) => (n === null || n === undefined ? '' : num.format(n)),
    shortId: (id) => (id.length > 12 ? `${id.slice(0, 12)}…` : id),
    fingerprint: (fp) => { const h = fp.replace(/:/g, ''); return h.length > 16 ? `${h.slice(0, 8)}…${h.slice(-4)}` : fp },
    name: (v, fallback = '') => {
      if (!v) return fallback
      if (typeof v === 'string') return v
      return v[locale] ?? v[locale.split('-')[0] ?? ''] ?? v['en'] ?? Object.values(v)[0] ?? fallback
    },
  }
}

export function useFormat(): Fmt {
  const t = useT()
  const locale = typeof navigator !== 'undefined' ? navigator.language : 'en'
  return useMemo(() => makeFormat(t, locale), [t, locale])
}

/** State / lifecycle / outcome → pill tone. */
export function tone(v: string | undefined): '' | 'good' | 'bad' | 'warn' | 'info' {
  switch ((v ?? '').toLowerCase()) {
    case 'active': case 'trusted': case 'allow': case 'enabled': case 'intact': return 'good'
    case 'suspended': case 'deny': case 'revoked': case 'quarantined': case 'error': return 'bad'
    case 'applicant': case 'pending': case 'degraded': case 'staged': return 'warn'
    case 'offline': return 'info'
    case 'online': return 'warn'
    default: return ''
  }
}
