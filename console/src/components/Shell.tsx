import { NavLink, Outlet } from 'react-router'
import { useQuery } from '@tanstack/react-query'
import { api } from '../api'
import { useT } from '../i18n/catalog'
import { useSession } from '../auth/session'
import { useLive } from '../live/LiveProvider'
import { useFormat } from '../lib/format'
import { reloadApp, useVersion } from '../lib/version'
import { IconAccess, IconAudit, IconDevices, IconGroups, IconMe, IconPeople, IconPlugins, IconPortal, IconScripts, IconSystem, Mark } from './Icons'
import { ToastHost } from './Toast'

// `perm` hides an entry from admins who lack that permission; the others are open to any admin.
const NAV: Array<{ to: string; code: string; Icon: () => JSX.Element; perm?: string }> = [
  { to: '/portal', code: 'ui.nav.portal', Icon: IconPortal },
  { to: '/me', code: 'ui.nav.me', Icon: IconMe },
  { to: '/people', code: 'ui.nav.people', Icon: IconPeople },
  { to: '/groups', code: 'ui.nav.groups', Icon: IconGroups },
  { to: '/access', code: 'ui.nav.access', Icon: IconAccess },
  { to: '/devices', code: 'ui.nav.devices', Icon: IconDevices },
  { to: '/scripts', code: 'ui.nav.scripts', Icon: IconScripts, perm: 'scripts.read' },
  { to: '/audit', code: 'ui.nav.audit', Icon: IconAudit },
  { to: '/plugins', code: 'ui.nav.plugins', Icon: IconPlugins },
  { to: '/system', code: 'ui.nav.system', Icon: IconSystem },
]

/**
 * One app for everyone: an admin gets the rail, a member gets a minimal top
 * bar and only My account (the portal of tiles comes later, see SPEC-portal).
 */
export function Shell() {
  const t = useT()
  const f = useFormat()
  const { session, isAdmin, can, logout } = useSession()
  const live = useLive()
  const brand = useQuery({ queryKey: ['brand'], queryFn: () => api.brand(), staleTime: Infinity, retry: 1 })

  const name = f.name(session?.principal.display_name, session?.principal.username ?? '')
  const initials = name.split(/\s+/).map((s) => s[0] ?? '').join('').slice(0, 2)
  const liveLabel = live.state === 'connected'
    ? t('ui.live.connected', { time: live.at ? f.time(live.at) : '' })
    : t(`ui.live.${live.state}`)
  const host = typeof window !== 'undefined' ? window.location.host : ''
  const tenant = brand.data ? `${brand.data.tenant_name} · ${host}` : host
  // A GET /v1/admin/system answered with another version than this page loaded
  // with: a new build is serving the assets. Offer the reload; never force it mid-work.
  const version = useVersion()
  const banner = version.changed && !version.autoReloading ? (
    <div className="banner" role="status">
      <span>{t('ui.updates.new_version_banner', { version: version.current ?? '' })}</span>
      <button type="button" className="btn primary" onClick={reloadApp}>{t('ui.updates.reload')}</button>
    </div>
  ) : null

  const me = (
    <div className="me">
      <span className="avatar" aria-hidden="true">{initials}</span>
      <span className="who">
        <span>{name}</span>
        <span className="muted">{t('ui.me.role', { role: session?.principal.username ?? '', assurance: session?.assurance ?? '' })}</span>
      </span>
      <button className="btn quiet" type="button" onClick={() => void logout()}>{t('ui.me.sign_out')}</button>
    </div>
  )
  const liveDot = <div className="live" data-state={live.state} role="status" aria-live="polite"><i />{liveLabel}</div>

  if (!isAdmin) {
    return (
      <div className="app member">
        <header className="topbar">
          <NavLink to="/portal" className="wordmark"><Mark />ROSTOR</NavLink>
          <div className="tenant">{tenant}</div>
          <nav className="topnav" aria-label={t('ui.nav.sections')}>
            <NavLink to="/portal">{t('ui.nav.portal')}</NavLink>
            <NavLink to="/me">{t('ui.nav.me')}</NavLink>
          </nav>
          <div className="spacer" />
          {liveDot}
          {me}
        </header>
        <main>
          {banner}
          <Outlet />
        </main>
        <ToastHost />
      </div>
    )
  }

  return (
    <div className="app">
      <aside className="rail">
        <NavLink to="/portal" className="wordmark"><Mark />ROSTOR</NavLink>
        <div className="tenant">{tenant}</div>
        <nav className="nav" aria-label={t('ui.nav.sections')}>
          {NAV.filter(({ perm }) => !perm || can(perm)).map(({ to, code, Icon }) => (
            <NavLink key={to} to={to}><Icon />{t(code)}</NavLink>
          ))}
        </nav>
        <div className="spacer" />
        {liveDot}
        {me}
      </aside>
      <main>
        {banner}
        <Outlet />
      </main>
      <ToastHost />
    </div>
  )
}
