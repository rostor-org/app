import { useCallback, useEffect, useRef, useState, type FormEvent } from 'react'
import { useNavigate } from 'react-router'
import { useQuery } from '@tanstack/react-query'
import { api, ApiError, type LoginResponse } from '../api'
import { useT } from '../i18n/catalog'
import { useSession } from '../auth/session'
import { conditionalMediationAvailable, getPasskey, isCancelled, passkeysSupported } from '../auth/webauthn'
import { Mark } from '../components/Icons'
import { ToastHost } from '../components/Toast'

type Mode = 'password' | 'badge'

/**
 * Identifier-first (§7.6): username, then the password ceremony. Passkeys sit
 * beside it (a button, plus autofill via conditional mediation on the username
 * field), and a badge mode takes a reader burst: the card names the person,
 * and a PIN-protected card gets a second step (auth.continue).
 */
export function Login() {
  const t = useT()
  const nav = useNavigate()
  const { session, refresh } = useSession()
  const brand = useQuery({ queryKey: ['brand'], queryFn: () => api.brand(), staleTime: Infinity, retry: 1 })
  const [mode, setMode] = useState<Mode>('password')
  const [identifier, setIdentifier] = useState('')
  const [password, setPassword] = useState('')
  const [step, setStep] = useState<'identifier' | 'password'>('identifier')
  const [number, setNumber] = useState('')
  const [pin, setPin] = useState('')
  const [needPin, setNeedPin] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [condGen, setCondGen] = useState(0) // bump to restart the autofill request
  const pw = useRef<HTMLInputElement>(null)
  const num = useRef<HTMLInputElement>(null)
  const pinRef = useRef<HTMLInputElement>(null)
  const conditional = useRef<AbortController | null>(null)
  const passkeys = passkeysSupported()

  useEffect(() => { if (session) nav('/people', { replace: true }) }, [session, nav])
  useEffect(() => { if (step === 'password') pw.current?.focus() }, [step])
  useEffect(() => { if (mode === 'badge') (needPin ? pinRef : num).current?.focus() }, [mode, needPin])

  const done = useCallback(async () => { await refresh(); nav('/people', { replace: true }) }, [refresh, nav])
  const message = useCallback((r: { code: string; params?: Record<string, unknown>; message?: string }) =>
    r.message ?? t(r.code, r.params as Record<string, string>), [t])
  const fail = (err: unknown) => setError(err instanceof Error ? err.message : String(err))
  const abortConditional = () => { conditional.current?.abort(); conditional.current = null }

  // ---- passkeys -------------------------------------------------------------

  const passkeyLogin = useCallback(async (opts: { mediation?: CredentialMediationRequirement; signal?: AbortSignal }): Promise<LoginResponse> => {
    const id = identifier.trim()
    const c = await api.passkeyLoginBegin(id ? { identifier: id } : {})
    const response = await getPasskey(c.options, opts)
    return api.passkeyLoginFinish({ ceremony_id: c.ceremony_id, response })
  }, [identifier])

  // Autofill: while the username field is showing, keep a conditional request
  // pending so the browser can offer passkeys in its suggestions. Going on to
  // the password step (or leaving) aborts it; a modal prompt aborts it first.
  useEffect(() => {
    if (!passkeys || mode !== 'password' || step !== 'identifier') return
    const ctrl = new AbortController()
    conditional.current = ctrl
    void (async () => {
      if (!(await conditionalMediationAvailable()) || ctrl.signal.aborted) return
      try {
        const r = await passkeyLogin({ mediation: 'conditional', signal: ctrl.signal })
        if (ctrl.signal.aborted) return
        if ('code' in r) setError(message(r)); else await done()
      } catch (err) {
        if (!ctrl.signal.aborted && !isCancelled(err)) {
          // A server-side refusal (passkeys not configured) is not the user's doing: stay quiet.
          if (!(err instanceof ApiError)) fail(err)
        }
      }
    })()
    return () => { ctrl.abort(); if (conditional.current === ctrl) conditional.current = null }
    // passkeyLogin changes with every keystroke in the username field; the pending request must not, so it is not a dependency.
  }, [passkeys, mode, step, condGen])

  const usePasskey = async () => {
    setError(null)
    abortConditional()
    setBusy(true)
    try {
      const r = await passkeyLogin({})
      if ('code' in r) { setError(message(r)); setCondGen((g) => g + 1); return }
      await done()
    } catch (err) {
      if (err instanceof ApiError) setError(message(err.body))
      else if (!isCancelled(err)) setError(t('ui.login.passkey_failed'))
      setCondGen((g) => g + 1)
    } finally {
      setBusy(false)
    }
  }

  // ---- password and badge -----------------------------------------------------

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    setError(null)
    if (mode === 'password' && step === 'identifier') { if (identifier.trim()) { abortConditional(); setStep('password') } return }
    setBusy(true)
    try {
      const r = mode === 'badge'
        ? await api.login({ method: 'badge', fields: needPin ? { number: number.trim(), pin } : { number: number.trim() } })
        : await api.login({ identifier: identifier.trim(), method: 'password', fields: { password } })
      if ('code' in r) {
        if (r.code === 'auth.continue') { setNeedPin(true); return }
        setError(message(r))
        if (mode === 'badge') { setPin(''); if (!needPin) setNumber(''); (needPin ? pinRef : num).current?.focus() }
        else { setPassword(''); pw.current?.focus() }
        return
      }
      await done()
    } catch (err) {
      fail(err)
    } finally {
      setBusy(false)
    }
  }

  const switchMode = (m: Mode) => {
    setMode(m); setError(null); setNeedPin(false); setPin(''); setNumber(''); setPassword(''); setStep('identifier')
  }

  const tenant = brand.data?.tenant_name ?? ''
  return (
    <div className="login">
      <form onSubmit={(e) => void submit(e)} aria-busy={busy}>
        <div className="wordmark"><Mark />ROSTOR</div>
        <h1>{t('ui.login.title', { tenant })}</h1>
        <div className="sub">{t('ui.login.subtitle')}</div>
        {mode === 'badge' ? (
          <>
            <label htmlFor="login-badge">{t('ui.login.badge')}</label>
            <input id="login-badge" ref={num} className="input mono" value={number} onChange={(e) => setNumber(e.target.value)} readOnly={needPin}
              autoComplete="off" autoCapitalize="none" spellCheck={false} inputMode="numeric" required />
            {!needPin && <div className="sub">{t('ui.login.badge_hint')}</div>}
            {needPin && (
              <>
                <label htmlFor="login-pin">{t('ui.login.pin')}</label>
                <input id="login-pin" ref={pinRef} className="input" type="password" value={pin} onChange={(e) => setPin(e.target.value)} inputMode="numeric" autoComplete="off" required />
              </>
            )}
          </>
        ) : step === 'identifier' ? (
          <>
            <label htmlFor="login-id">{t('ui.login.identifier')}</label>
            <input id="login-id" className="input" value={identifier} onChange={(e) => setIdentifier(e.target.value)} autoComplete="username webauthn" autoFocus required autoCapitalize="none" spellCheck={false} />
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
            {t(busy ? 'ui.login.working' : mode === 'password' && step === 'identifier' ? 'ui.login.continue' : 'ui.login.submit')}
          </button>
        </div>
        <div className="alt">
          {mode === 'password' && passkeys && <button type="button" className="btn quiet" disabled={busy} onClick={() => void usePasskey()}>{t('ui.login.use_passkey')}</button>}
          {mode === 'password'
            ? <button type="button" className="btn quiet" disabled={busy} onClick={() => switchMode('badge')}>{t('ui.login.use_badge')}</button>
            : <button type="button" className="btn quiet" disabled={busy} onClick={() => switchMode('password')}>{t('ui.login.use_password')}</button>}
        </div>
      </form>
      <ToastHost />
    </div>
  )
}
