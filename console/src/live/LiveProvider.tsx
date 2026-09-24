import { createContext, useContext, useEffect, useRef, useState, type ReactNode } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { api, type LiveEvent, type LiveState } from '../api'
import { useSession } from '../auth/session'

export interface Live {
  state: LiveState
  /** Wall-clock time of the last state change or event (ms epoch). */
  at: number | null
  /** Monotonic counter bumped on every audit.appended, for row highlighting. */
  auditTick: number
}

const Ctx = createContext<Live>({ state: 'off', at: null, auditTick: 0 })

const LAST_ID_KEY = 'rostor-console-last-event-id'

/** Event type prefix → query keys to invalidate. */
function keysFor(type: string): string[][] {
  if (type.startsWith('user.')) return [['users'], ['user'], ['summary'], ['why']]
  if (type.startsWith('grant.')) return [['grants'], ['group'], ['summary'], ['why']]
  if (type.startsWith('group.')) return [['groups'], ['group'], ['users'], ['summary'], ['why']]
  if (type.startsWith('device.')) return [['devices'], ['summary'], ['ca']]
  if (type === 'audit.appended') return [['audit'], ['user'], ['ca']]
  if (type === 'update.state') return [['updates'], ['system'], ['downloads']]
  return []
}

export function LiveProvider({ children }: { children: ReactNode }) {
  const qc = useQueryClient()
  const { session } = useSession()
  const [live, setLive] = useState<Live>({ state: 'off', at: null, auditTick: 0 })
  const lastId = useRef<string | null>(null)

  useEffect(() => {
    if (!session) { setLive({ state: 'off', at: null, auditTick: 0 }); return }
    try { lastId.current = sessionStorage.getItem(LAST_ID_KEY) } catch { lastId.current = null }
    const close = api.stream({
      onState: (state) => setLive((l) => ({ ...l, state, at: Date.now() })),
      onEvent: (e: LiveEvent) => {
        if (e.id) { lastId.current = e.id; try { sessionStorage.setItem(LAST_ID_KEY, e.id) } catch { /* ignore */ } }
        for (const k of keysFor(e.type)) void qc.invalidateQueries({ queryKey: k })
        setLive((l) => ({ ...l, at: Date.now(), auditTick: e.type === 'audit.appended' ? l.auditTick + 1 : l.auditTick }))
      },
    }, lastId.current)
    return close
  }, [session, qc])

  return <Ctx.Provider value={live}>{children}</Ctx.Provider>
}

export function useLive(): Live {
  return useContext(Ctx)
}
