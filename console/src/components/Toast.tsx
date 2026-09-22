import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from 'react'

type Show = (message: string) => void
const Ctx = createContext<Show>(() => {})
let hostSetter: ((m: string) => void) | null = null

export function ToastProvider({ children }: { children: ReactNode }) {
  const show = useCallback<Show>((m) => hostSetter?.(m), [])
  const value = useMemo(() => show, [show])
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>
}

export function useToast(): Show {
  return useContext(Ctx)
}

export function ToastHost() {
  const [msg, setMsg] = useState('')
  const [shown, setShown] = useState(false)
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null)
  useEffect(() => {
    hostSetter = (m) => {
      setMsg(m); setShown(true)
      if (timer.current) clearTimeout(timer.current)
      timer.current = setTimeout(() => setShown(false), 2600)
    }
    return () => { hostSetter = null }
  }, [])
  return <div className={shown ? 'toast show' : 'toast'} role="status" aria-live="polite">{msg}</div>
}
