// Inline SVG icons from the approved mockup. Decorative: aria-hidden.
const P = { viewBox: '0 0 16 16', 'aria-hidden': true, focusable: false } as const

export const Mark = () => (
  <svg viewBox="0 0 84.89 100" aria-hidden="true" focusable="false">
    <defs><clipPath id="rostor-mark-clip"><rect x="0" y="-13.64" width="129.55" height="127.27" /></clipPath></defs>
    <g fill="none" stroke="#e07a24" strokeWidth="13.64" strokeLinecap="butt">
      <path d="M 67.39 67.85 A 43.18 43.18 0 1 1 67.39 32.15" clipPath="url(#rostor-mark-clip)" />
      <path d="M 28.07 50 L 84.89 50" />
    </g>
  </svg>
)

export const IconPeople = () => (
  <svg {...P}><circle cx="8" cy="5" r="3" fill="currentColor" /><path d="M2 14c0-3 2.7-5 6-5s6 2 6 5" fill="currentColor" /></svg>
)
export const IconGroups = () => (
  <svg {...P}><circle cx="5" cy="6" r="2.4" fill="currentColor" /><circle cx="11" cy="6" r="2.4" fill="currentColor" /><path d="M1 14c0-2.5 1.8-4 4-4s4 1.5 4 4M7 14c0-2.5 1.8-4 4-4s4 1.5 4 4" fill="currentColor" /></svg>
)
export const IconAccess = () => (
  <svg {...P}><rect x="3" y="7" width="10" height="7" rx="1.5" fill="currentColor" /><path d="M5.5 7V5a2.5 2.5 0 0 1 5 0v2" fill="none" stroke="currentColor" strokeWidth="1.6" /></svg>
)
export const IconDevices = () => (
  <svg {...P}><rect x="2" y="3" width="12" height="8" rx="1.5" fill="currentColor" /><rect x="5" y="12" width="6" height="1.6" fill="currentColor" /></svg>
)
export const IconAudit = () => (
  <svg {...P}><path d="M3 2h10v12H3z" fill="currentColor" /><path d="M5 5h6M5 8h6M5 11h4" stroke="var(--rail)" strokeWidth="1.4" /></svg>
)
export const IconPlugins = () => (
  <svg {...P}><path d="M6 2h4v3h3v4h-3v5H6v-5H3V5h3z" fill="currentColor" /></svg>
)
export const IconSystem = () => (
  <svg {...P}><circle cx="8" cy="8" r="6" fill="none" stroke="currentColor" strokeWidth="1.8" /><circle cx="8" cy="8" r="2" fill="currentColor" /></svg>
)
