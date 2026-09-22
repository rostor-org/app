import { useId, type InputHTMLAttributes, type ReactNode, type SelectHTMLAttributes } from 'react'
import { useT } from '../i18n/catalog'

/** Labelled input for drawer forms. The label is a catalog code. */
export function Field({ labelCode, hintCode, children, ...props }: { labelCode: string; hintCode?: string; children?: ReactNode } & InputHTMLAttributes<HTMLInputElement>) {
  const t = useT()
  const id = useId()
  return (
    <div className="field">
      <label htmlFor={id}>{t(labelCode)}</label>
      {children ?? <input id={id} className="input" {...props} />}
      {hintCode && <small className="muted">{t(hintCode)}</small>}
    </div>
  )
}

/** Labelled select whose options are [value, catalog code] pairs, or plain values. */
export function SelectField({ labelCode, options, ...props }: { labelCode: string; options: Array<[string, string | undefined]> } & SelectHTMLAttributes<HTMLSelectElement>) {
  const t = useT()
  const id = useId()
  return (
    <div className="field">
      <label htmlFor={id}>{t(labelCode)}</label>
      <select id={id} className="input" {...props}>
        {options.map(([v, code]) => <option key={v} value={v}>{code ? t(code) : v}</option>)}
      </select>
    </div>
  )
}
