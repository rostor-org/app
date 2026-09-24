import { useSession } from '../auth/session'
import { Head } from '../components/bits'
import { PersonPanel } from '../components/PersonPanel'

/**
 * My account: the signed-in person's own record as a page (SPEC-admin-group).
 * Everyone lands here; the self-service rule lets a member read and manage
 * their own sign-in methods without admin permissions.
 */
export function MyAccount() {
  const { session } = useSession()
  if (!session) return null
  return (
    <section>
      <Head titleCode="ui.me.title" subCode="ui.me.subtitle" />
      <div className="panel">
        <PersonPanel id={session.principal.id} page />
      </div>
    </section>
  )
}
