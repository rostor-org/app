// Watches the appliance version the console is running against. The first
// successful GET /v1/admin/system fixes the "loaded" version; any later answer
// that differs means a new build is serving this page's assets. The System
// screen's install flow reloads on its own; elsewhere the shell shows a
// banner so nobody loses work mid-edit.
import { useSyncExternalStore } from 'react'
import { isMock } from '../api/index'

export interface VersionState {
  /** Version the page loaded with (first observed). */
  loaded: string | null
  /** Latest version observed. */
  current: string | null
  /** True once an install flow has taken over: the banner stays hidden while it reloads. */
  autoReloading: boolean
}

let state: VersionState = { loaded: null, current: null, autoReloading: false }
const subs = new Set<() => void>()
function set(next: Partial<VersionState>) {
  state = { ...state, ...next }
  for (const fn of subs) fn()
}

export function observeVersion(v: string) {
  if (!v) return
  if (state.loaded === null) { set({ loaded: v, current: v }); return }
  if (v !== state.current) set({ current: v })
}

export function loadedVersion(): string | null { return state.loaded }

/** Called by the System screen while it polls for the restarted core. */
export function setAutoReloading(on: boolean) { if (state.autoReloading !== on) set({ autoReloading: on }) }

declare global {
  interface Window {
    /** Mock mode only: set instead of reloading, so a test can see the flow completed. */
    __rostorReload?: { requested: true; from: string | null; to: string | null; at: string }
  }
}

/** Reload the console onto the new build. In mock mode, log and flag instead. */
export function reloadApp() {
  if (isMock()) {
    window.__rostorReload = { requested: true, from: state.loaded, to: state.current, at: new Date().toISOString() }
    console.info('[rostor mock] location.reload() suppressed', window.__rostorReload)
    // Drop the takeover so the banner shows: the only visible trace in mock mode.
    set({ autoReloading: false })
    return
  }
  location.reload()
}

export function useVersion(): VersionState & { changed: boolean } {
  const s = useSyncExternalStore(
    (fn) => { subs.add(fn); return () => { subs.delete(fn) } },
    () => state,
  )
  return { ...s, changed: s.loaded !== null && s.current !== null && s.current !== s.loaded }
}
