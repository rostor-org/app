import { createContext, useContext, useEffect, useMemo, type ReactNode } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { api, onUnauthorized, type Session } from '../api'

interface SessionCtx {
  session: Session | null
  loading: boolean
  can: (action: string) => boolean
  /** True when the session holds any admin permission on directory:root; false for a plain member. */
  isAdmin: boolean
  refresh: () => Promise<unknown>
  logout: () => Promise<void>
}

const Ctx = createContext<SessionCtx>({ session: null, loading: true, can: () => false, isAdmin: false, refresh: async () => undefined, logout: async () => undefined })

export const SESSION_KEY = ['session'] as const

export function SessionProvider({ children }: { children: ReactNode }) {
  const qc = useQueryClient()
  const q = useQuery({ queryKey: SESSION_KEY, queryFn: () => api.session(), staleTime: 60_000, retry: false })

  useEffect(() => {
    onUnauthorized(() => {
      qc.setQueryData(SESSION_KEY, null)
      qc.removeQueries({ predicate: (query) => query.queryKey[0] !== 'catalog' && query.queryKey[0] !== 'session' })
    })
  }, [qc])

  const value = useMemo<SessionCtx>(() => {
    const session = q.data ?? null
    const perms = session?.permissions ?? []
    return {
      session,
      loading: q.isPending,
      can: (action) => perms.includes('*') || perms.includes(action),
      isAdmin: perms.length > 0,
      refresh: () => qc.invalidateQueries({ queryKey: SESSION_KEY }),
      logout: async () => {
        try { await api.logout() } finally {
          qc.setQueryData(SESSION_KEY, null)
          qc.removeQueries({ predicate: (query) => query.queryKey[0] !== 'catalog' && query.queryKey[0] !== 'session' })
        }
      },
    }
  }, [q.data, q.isPending, qc])

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>
}

export function useSession(): SessionCtx {
  return useContext(Ctx)
}
