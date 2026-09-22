import { createContext, useCallback, useContext, useMemo, type ReactNode } from 'react'
import { useQuery } from '@tanstack/react-query'
import { api } from '../api'

export type Params = Record<string, string | number | null | undefined>
export type T = (code: string, params?: Params) => string

const Ctx = createContext<T>((code) => code)

export function render(template: string, params?: Params): string {
  if (!params) return template
  return template.replace(/\{(\w+)\}/g, (m, k: string) => {
    const v = params[k]
    return v === undefined || v === null ? m : String(v)
  })
}

export function CatalogProvider({ children, fallback }: { children: ReactNode; fallback: ReactNode }) {
  const locale = typeof navigator !== 'undefined' ? navigator.language : 'en'
  const q = useQuery({
    queryKey: ['catalog', locale],
    queryFn: () => api.catalog(locale),
    staleTime: Infinity,
    retry: 2,
  })
  const strings = q.data?.strings
  const t = useCallback<T>((code, params) => {
    const tpl = strings?.[code]
    return tpl === undefined ? code : render(tpl, params)
  }, [strings])
  const value = useMemo(() => t, [t])
  // Unknown codes render as themselves, so a failed catalog fetch still yields a usable (if code-labelled) UI.
  if (q.isPending) return <>{fallback}</>
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>
}

export function useT(): T {
  return useContext(Ctx)
}
