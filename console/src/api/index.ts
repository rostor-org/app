import type { Api } from './types'
import { createHttpApi } from './client'
import { createMockApi } from './mock'

const MOCK_KEY = 'rostor-console-mock'

export function isMock(): boolean {
  if (import.meta.env.VITE_MOCK === '1') return true
  try {
    const p = new URLSearchParams(window.location.search)
    if (p.get('mock') === '1') { sessionStorage.setItem(MOCK_KEY, '1'); return true }
    if (p.get('mock') === '0') { sessionStorage.removeItem(MOCK_KEY); return false }
    return sessionStorage.getItem(MOCK_KEY) === '1'
  } catch {
    return false
  }
}

let unauthorized: () => void = () => {}
export function onUnauthorized(fn: () => void) { unauthorized = fn }

export const api: Api = isMock()
  ? createMockApi({ onUnauthorized: () => unauthorized() })
  : createHttpApi({ onUnauthorized: () => unauthorized() })

export { ApiError } from './client'
export type * from './types'
