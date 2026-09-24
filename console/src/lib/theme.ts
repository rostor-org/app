/**
 * Console theme. Dark is the default whatever the OS prefers; light is an
 * opt-in kept per browser (System → Appearance). It is a viewer preference,
 * not a tenant setting, so it lives in localStorage and also applies on the
 * sign-in screen. Storage can be unavailable (private windows, blocked site
 * data); then the choice lasts only for the page.
 */
export type Theme = 'dark' | 'light'

const KEY = 'rostor.theme'

export function storedTheme(): Theme {
  try { return localStorage.getItem(KEY) === 'light' ? 'light' : 'dark' } catch { return 'dark' }
}

/** Reflect the theme on <html data-theme>; styles.css keys the light tokens off it. */
export function applyTheme(theme: Theme = storedTheme()) {
  document.documentElement.dataset.theme = theme
}

export function setTheme(theme: Theme) {
  try { localStorage.setItem(KEY, theme) } catch { /* storage unavailable: page-lifetime only */ }
  applyTheme(theme)
}
