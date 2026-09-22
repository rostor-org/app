import { useEffect, useRef, useState, type FormEvent } from 'react'
import { useNavigate } from 'react-router'
import { useQuery } from '@tanstack/react-query'
import { api } from '../api'
import { useT } from '../i18n/catalog'
import { useSession } from '../auth/session'
import { Mark } from '../components/Icons'
import { ToastHost } from '../components/Toast'

/** Identifier-first (§7.6): username, then the password ceremony. */
export function Login() {
  const t = useT()
  const nav = useNavigate()
  const { session, refresh } = useSession()
  const brand = useQuery({ queryKey: ['brand'], queryFn: () => api.brand(), staleTime: Infinity, retry: 1 })
  const [identifier, setIdentifier] = useState('')
  const [password, setPassword] = useState('')
  const [step, setStep] = useState<'identifier' | 'password'>('identifier')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const pw = useRef<HTMLInputElement>(null)

  useEffect(() => { if (session) nav('/people', { replace: true }) }, [session, nav])
  useEffect(() => { if (step === 'password') pw.current?.focus() }, [step])

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    setError(null)
    if (step === 'identifier') { if (identifier.trim()) setStep('password'); return }
    setBusy(true)
    try {
      const r = await api.login({ identifier: identifier.trim(), method: 'password', fields: { password } })
      if ('code' in r) {
        setError(r.message ?? t(r.code, r.params as Record<string, string>))
        setPassword('')
        pw.current?.focus()
        return
      }
      await refresh()
      nav('/people', { replace: true })
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  const tenant = brand.data?.tenant_name ?? ''
  return (
    <div className="login">
      <form onSubmit={(e) => void submit(e)} aria-busy={busy}>
        <div className="wordmark"><Mark />ROSTOR</div>
        <h1>{t('ui.login.title', { tenant })}</h1>
        <div className="sub">{t('ui.login.subtitle')}</div>
        {step === 'identifier' ? (
          <>
            <label htmlFor="login-id">{t('ui.login.identifier')}</label>
            <input id="login-id" className="input" value={identifier} onChange={(e) => setIdentifier(e.target.value)} autoComplete="username" autoFocus required autoCapitalize="none" spellCheck={false} />
          </>
        ) : (
          <>
            <div className="who"><span>{identifier}</span><button type="button" className="btn quiet" onClick={() => { setStep('identifier'); setPassword(''); setError(null) }}>{t('ui.login.change_user')}</button></div>
            <label htmlFor="login-pw">{t('ui.login.password')}</label>
            <input id="login-pw" ref={pw} className="input" type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" required />
          </>
        )}
        {error && <p className="form-error" role="alert">{error}</p>}
        <div className="actions">
          <button type="submit" className="btn primary" disabled={busy}>
            {t(busy ? 'ui.login.working' : step === 'identifier' ? 'ui.login.continue' : 'ui.login.submit')}
          </button>
        </div>
      </form>
      <ToastHost />
    </div>
  )
}
