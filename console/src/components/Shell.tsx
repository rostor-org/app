import { NavLink, Outlet } from 'react-router'
import { useQuery } from '@tanstack/react-query'
import { api } from '../api'
import { useT } from '../i18n/catalog'
import { useSession } from '../auth/session'
import { useLive } from '../live/LiveProvider'
import { useFormat } from '../lib/format'
import { IconAccess, IconAudit, IconDevices, IconGroups, IconPeople, IconPlugins, IconSystem, Mark } from './Icons'
import { ToastHost } from './Toast'

const NAV = [
  { to: '/people', code: 'ui.nav.people', Icon: IconPeople },
  { to: '/groups', code: 'ui.nav.groups', Icon: IconGroups },
  { to: '/access', code: 'ui.nav.access', Icon: IconAccess },
  { to: '/devices', code: 'ui.nav.devices', Icon: IconDevices },
  { to: '/audit', code: 'ui.nav.audit', Icon: IconAudit },
  { to: '/plugins', code: 'ui.nav.plugins', Icon: IconPlugins },
  { to: '/system', code: 'ui.nav.system', Icon: IconSystem },
]

export function Shell() {
  const t = useT()
  const f = useFormat()
  const { session, logout } = useSession()
  const live = useLive()
  const brand = useQuery({ queryKey: ['brand'], queryFn: () => api.brand(), staleTime: Infinity, retry: 1 })

  const name = f.name(session?.principal.display_name, session?.principal.username ?? '')
  const initials = name.split(/\s+/).map((s) => s[0] ?? '').join('').slice(0, 2)
  const liveLabel = live.state === 'connected'
    ? t('ui.live.connected', { time: live.at ? f.time(live.at) : '' })
    : t(`ui.live.${live.state}`)
  const host = typeof window !== 'undefined' ? window.location.host : ''

  return (
    <div className="app">
      <aside className="rail">
        <NavLink to="/people" className="wordmark"><Mark />ROSTOR</NavLink>
        <div className="tenant">{brand.data ? `${brand.data.tenant_name} · ${host}` : host}</div>
        <nav className="nav" aria-label={t('ui.nav.sections')}>
          {NAV.map(({ to, code, Icon }) => (
            <NavLink key={to} to={to}><Icon />{t(code)}</NavLink>
          ))}
        </nav>
        <div className="spacer" />
        <div className="live" data-state={live.state} role="status" aria-live="polite"><i />{liveLabel}</div>
        <div className="me">
          <span className="avatar" aria-hidden="true">{initials}</span>
          <span className="who">
            <span>{name}</span>
            <span className="muted">{t('ui.me.role', { role: session?.principal.username ?? '', assurance: session?.assurance ?? '' })}</span>
          </span>
          <button className="btn quiet" type="button" onClick={() => void logout()}>{t('ui.me.sign_out')}</button>
        </div>
      </aside>
      <main>
        <Outlet />
      </main>
      <ToastHost />
    </div>
  )
}
