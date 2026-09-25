import { NavLink, Link } from 'react-router'
import { useQuery } from '@tanstack/react-query'
import { api, type Tile } from '../api'
import { useT } from '../i18n/catalog'
import { useSession } from '../auth/session'
import { ErrorNote, Head, Loading } from '../components/bits'
import { IconAccess, IconAudit, IconDevices, IconGroups, IconMe, IconPeople, IconPlugins, IconScripts, IconSystem, Mark } from '../components/Icons'

/** Built-in screen tiles carry an icon name; link tiles carry a short label an admin typed. */
const ICONS: Record<string, () => JSX.Element> = {
  me: IconMe, people: IconPeople, groups: IconGroups, access: IconAccess, devices: IconDevices, scripts: IconScripts, audit: IconAudit, plugins: IconPlugins, system: IconSystem,
}
const CATEGORY_ORDER = ['you', 'admin', 'links', 'public']

function TileIcon({ tile }: { tile: Tile }) {
  const Icon = ICONS[tile.icon]
  return <span className="tile-icon" aria-hidden="true">{Icon ? <Icon /> : (tile.icon || tile.title.slice(0, 1)).slice(0, 2)}</span>
}

function TileCard({ tile }: { tile: Tile }) {
  const inner = <><TileIcon tile={tile} /><span className="tile-text"><b>{tile.title}</b>{tile.description && <span className="muted">{tile.description}</span>}</span></>
  if (tile.kind === 'screen') return <NavLink to={tile.href} className="tile">{inner}</NavLink>
  const external = /^https?:\/\//.test(tile.href)
  return <a className="tile" href={tile.href} target={external ? '_blank' : undefined} rel={external ? 'noreferrer' : undefined}>{inner}</a>
}

/** Tiles grouped by category, in a fixed category order; unknown categories go last, alphabetically. */
export function TileGrid({ tiles }: { tiles: Tile[] }) {
  const t = useT()
  const cats = [...new Set(tiles.map((x) => x.category))].sort((a, b) => {
    const ia = CATEGORY_ORDER.indexOf(a), ib = CATEGORY_ORDER.indexOf(b)
    return (ia < 0 ? 99 : ia) - (ib < 0 ? 99 : ib) || a.localeCompare(b)
  })
  return (
    <>
      {cats.map((c) => (
        <div key={c} className="tile-category">
          <h3>{CATEGORY_ORDER.includes(c) ? t(`ui.portal.category.${c}`) : c}</h3>
          <div className="tiles">
            {tiles.filter((x) => x.category === c).sort((a, b) => a.order - b.order || a.title.localeCompare(b.title)).map((x) => <TileCard key={x.id} tile={x} />)}
          </div>
        </div>
      ))}
    </>
  )
}

/** The signed-in landing page (SPEC-portal). */
export function Portal() {
  const t = useT()
  const portal = useQuery({ queryKey: ['portal'], queryFn: () => api.portal() })
  return (
    <section>
      <Head titleCode="ui.portal.title" subCode="ui.portal.subtitle" />
      <ErrorNote error={portal.error} />
      {portal.isPending && <Loading />}
      {portal.data && portal.data.tiles.length === 0 && <p className="muted">{t('ui.portal.empty')}</p>}
      {portal.data && <TileGrid tiles={portal.data.tiles} />}
    </section>
  )
}

/**
 * What a visitor without a session sees at the root: the public tiles and a
 * way in. Signed-in people are routed to the portal proper by the router.
 */
export function PublicPortal() {
  const t = useT()
  const { loading } = useSession()
  const brand = useQuery({ queryKey: ['brand'], queryFn: () => api.brand(), staleTime: Infinity, retry: 1 })
  const portal = useQuery({ queryKey: ['portal', 'public'], queryFn: () => api.portal(), enabled: !loading })
  const tenant = brand.data?.tenant_name ?? ''
  return (
    <div className="public">
      <header className="topbar">
        <span className="wordmark"><Mark />ROSTOR</span>
        <div className="tenant">{tenant}</div>
        <div className="spacer" />
        <Link to="/login" className="btn primary">{t('ui.portal.sign_in')}</Link>
      </header>
      <main>
        <section>
          <Head titleCode="ui.portal.public_title" subCode="ui.portal.public_subtitle" />
          <ErrorNote error={portal.error} />
          {portal.isPending && <Loading />}
          {portal.data && portal.data.tiles.length === 0 && <p className="muted">{t('ui.portal.public_empty')}</p>}
          {portal.data && <TileGrid tiles={portal.data.tiles} />}
        </section>
      </main>
    </div>
  )
}
