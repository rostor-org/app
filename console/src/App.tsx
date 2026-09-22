import { useEffect } from 'react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { createBrowserRouter, createHashRouter, Navigate, Outlet, RouterProvider } from 'react-router'
import { CatalogProvider, useT } from './i18n/catalog'
import { SessionProvider, useSession } from './auth/session'
import { LiveProvider } from './live/LiveProvider'
import { ToastProvider } from './components/Toast'
import { Shell } from './components/Shell'
import { People } from './screens/People'
import { Groups } from './screens/Groups'
import { Access } from './screens/Access'
import { Devices } from './screens/Devices'
import { Audit } from './screens/Audit'
import { Plugins } from './screens/Plugins'
import { System } from './screens/System'
import { Login } from './screens/Login'

const queryClient = new QueryClient({
  defaultOptions: { queries: { staleTime: 10_000, retry: 1, refetchOnWindowFocus: false } },
})

function Boot() {
  return <div className="boot" aria-busy="true" />
}

/** Gate: everything under here needs a session; 401 anywhere routes to /login. */
function Authed() {
  const { session, loading } = useSession()
  if (loading) return <Boot />
  if (!session) return <Navigate to="/login" replace />
  return <LiveProvider><Outlet /></LiveProvider>
}

function Title() {
  const t = useT()
  useEffect(() => { document.title = t('ui.app.title') }, [t])
  return null
}

const routes = [
  {
    element: <><Title /><Outlet /></>,
    children: [
      { path: '/login', element: <Login /> },
      {
        element: <Authed />,
        children: [
          {
            element: <Shell />,
            children: [
              { path: '/', element: <Navigate to="/people" replace /> },
              { path: '/people', element: <People /> },
              { path: '/people/:id', element: <People /> },
              { path: '/groups', element: <Groups /> },
              { path: '/groups/:name', element: <Groups /> },
              { path: '/access', element: <Access /> },
              { path: '/devices', element: <Devices /> },
              { path: '/audit', element: <Audit /> },
              { path: '/plugins', element: <Plugins /> },
              { path: '/system', element: <System /> },
              { path: '*', element: <Navigate to="/people" replace /> },
            ],
          },
        ],
      },
    ],
  },
]

// History routing: the Go server serves the app at the root and falls back to
// index.html for unknown paths. VITE_ROUTER=hash is the escape hatch for hosts
// that cannot rewrite.
const router = import.meta.env.VITE_ROUTER === 'hash' ? createHashRouter(routes) : createBrowserRouter(routes)

export function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <CatalogProvider fallback={<Boot />}>
        <ToastProvider>
          <SessionProvider>
            <RouterProvider router={router} />
          </SessionProvider>
        </ToastProvider>
      </CatalogProvider>
    </QueryClientProvider>
  )
}
