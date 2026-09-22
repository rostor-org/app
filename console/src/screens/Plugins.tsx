import { useQuery } from '@tanstack/react-query'
import { api } from '../api'
import { useT } from '../i18n/catalog'
import { useToast } from '../components/Toast'
import { Chips, Empty, ErrorNote, Head, Loading, Pill } from '../components/bits'

export function Plugins() {
  const t = useT()
  const toast = useToast()
  const plugins = useQuery({ queryKey: ['plugins'], queryFn: () => api.plugins() })
  return (
    <section>
      <Head titleCode="ui.plugins.title" subCode="ui.plugins.subtitle">
        <button type="button" className="btn" onClick={() => toast(t('ui.common.not_available'))}>{t('ui.plugins.browse')}</button>
        <button type="button" className="btn primary" onClick={() => toast(t('ui.common.not_available'))}>{t('ui.plugins.install')}</button>
      </Head>
      <ErrorNote error={plugins.error} />
      <div className="tablewrap">
        <table>
          <thead><tr>
            <th>{t('ui.plugins.col.plugin')}</th><th>{t('ui.plugins.col.type')}</th><th>{t('ui.plugins.col.runtime')}</th>
            <th>{t('ui.plugins.col.masters')}</th><th>{t('ui.plugins.col.scopes')}</th><th>{t('ui.plugins.col.state')}</th>
          </tr></thead>
          <tbody>
            {plugins.isPending && <tr><td colSpan={6}><Loading /></td></tr>}
            {plugins.data?.items.length === 0 && <tr><td colSpan={6}><Empty code="ui.plugins.empty" /></td></tr>}
            {plugins.data?.items.map((p) => (
              <tr key={p.id}>
                <td><b>{p.name}</b><br /><span className="muted">{t('ui.plugins.publisher', { publisher: p.publisher, version: p.version })}</span></td>
                <td>{p.type}</td>
                <td>{p.runtime}</td>
                <td className={p.masters.length ? '' : 'muted'}>{p.masters.length ? p.masters.join(', ') : t('ui.common.none')}</td>
                <td><Chips items={p.scopes} /></td>
                <td><Pill value={p.state} label={p.state} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  )
}
