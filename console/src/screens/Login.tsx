import { useCallback, useEffect, useRef, useState, type FormEvent } from 'react'
import { useNavigate } from 'react-router'
import { useQuery } from '@tanstack/react-query'
import { api, ApiError, type LoginResponse, type SetupRequest } from '../api'
import { useT } from '../i18n/catalog'
import { useSession } from '../auth/session'
import { conditionalMediationAvailable, getPasskey, isCancelled, passkeysSupported } from '../auth/webauthn'
import { Mark } from '../components/Icons'
import { ToastHost } from '../components/Toast'
import { Field } from '../components/Form'

type Mode = 'password' | 'badge' | 'setup'
const emptySetup: SetupRequest & { confirm: string } = { bootstrap_token: '', username: '', display_name: '', password: '', confirm: '' }

/**
 * Identifier-first (§7.6): username, then the password ceremony. Passkeys sit
 * beside it (a button, plus autofill via conditional mediation on the username
 * field), and a badge mode takes a reader burst: the card names the person,
 * and a PIN-protected card gets a second step (auth.continue). While the
 * install has no human administrator (GET /v1/auth/setup), the page also
 * offers "Set up the first administrator", gated by the bootstrap token.
 */
export function Login() {
  const t = useT()
  const nav = useNavigate()
  const { session, refresh } = useSession()
  const brand = useQuery({ queryKey: ['brand'], queryFn: () => api.brand(), staleTime: Infinity, retry: 1 })
  const setupStatus = useQuery({ queryKey: ['setup'], queryFn: () => api.setupStatus(), staleTime: 0, retry: 1 })
  const setupNeeded = setupStatus.data?.needed === true
  const [mode, setMode] = useState<Mode>('password')
  const [setup, setSetup] = useState(emptySetup)
  const [identifier, setIdentifier] = useState('')
  const [password, setPassword] = useState('')
  const [step, setStep] = useState<'identifier' | 'password'>('identifier')
  const [number, setNumber] = useState('')
  const [pin, setPin] = useState('')
  const [needPin, setNeedPin] = useState(false)
  const [typeBadge, setTypeBadge] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [condGen, setCondGen] = useState(0) // bump to restart the autofill request
  const pw = useRef<HTMLInputElement>(null)
  const num = useRef<HTMLInputElement>(null)
  const pinRef = useRef<HTMLInputElement>(null)
  const conditional = useRef<AbortController | null>(null)
  const passkeys = passkeysSupported()

  useEffect(() => { if (session) nav('/me', { replace: true }) }, [session, nav])
  // The offer disappears once setup is done (or was never needed).
  useEffect(() => { if (mode === 'setup' && setupStatus.data && !setupStatus.data.needed) setMode('password') }, [mode, setupStatus.data])
  // Open on the tenant's default method (Sign-in settings) until the person
  // picks another. Badge mode focuses the reader field so a tap needs no click.
  const [chosen, setChosen] = useState(false)
  useEffect(() => {
    if (chosen || !setupStatus.data || setupStatus.data.needed) return
    if (setupStatus.data.default_method === 'badge' && mode === 'password') setMode('badge')
  }, [chosen, setupStatus.data, mode])
  useEffect(() => { if (step === 'password') pw.current?.focus() }, [step])
  useEffect(() => { if (mode === 'badge') (needPin ? pinRef : num).current?.focus() }, [mode, needPin])

  const done = useCallback(async () => { await refresh(); nav('/me', { replace: true }) }, [refresh, nav])
  const message = useCallback((r: { code: string; params?: Record<string, unknown>; message?: string }) =>
    r.message ?? t(r.code, r.params as Record<string, string>), [t])
  // Server errors (HTTP client or mock) carry a body with a rendered message; anything else shows as is.
  const fail = (err: unknown) => {
    if (err && typeof err === 'object' && 'body' in err) { setError(message((err as { body: { code: string; params?: Record<string, unknown>; message?: string } }).body)); return }
    setError(err instanceof Error ? err.message : String(err))
  }
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
    // Wait until the tenant's default method is known: starting an autofill
    // request that is aborted a moment later (default = badge) leaves the
    // browser refusing the next one with "a request is already pending".
    if (!passkeys || mode !== 'password' || step !== 'identifier' || !setupStatus.data) return
    const ctrl = new AbortController()
    const previous = conditional.current
    conditional.current = ctrl
    void (async () => {
      if (previous) { previous.abort(); await new Promise((r) => setTimeout(r, 250)) } // let the browser settle the abort
      if (!(await conditionalMediationAvailable()) || ctrl.signal.aborted) return
      for (let attempt = 0; attempt < 2; attempt++) {
        try {
          const r = await passkeyLogin({ mediation: 'conditional', signal: ctrl.signal })
          if (ctrl.signal.aborted) return
          if ('code' in r) setError(message(r)); else await done()
          return
        } catch (err) {
          if (ctrl.signal.aborted || isCancelled(err)) return
          // Chrome reports a not-yet-settled abort as "a request is already
          // pending"; one retry after a short wait clears it.
          if (attempt === 0 && err instanceof DOMException && /already pending/i.test(err.message)) { await new Promise((r) => setTimeout(r, 400)); continue }
          // A server-side refusal (passkeys not configured) is not the user's doing: stay quiet.
          if (!(err instanceof ApiError)) fail(err)
          return
        }
      }
    })()
    return () => { ctrl.abort(); if (conditional.current === ctrl) conditional.current = null }
    // passkeyLogin changes with every keystroke in the username field; the pending request must not, so it is not a dependency.
  }, [passkeys, mode, step, condGen, setupStatus.data])

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

  const submitSetup = async (e: FormEvent) => {
    e.preventDefault()
    setError(null)
    if (setup.password !== setup.confirm) { setError(t('ui.common.password_mismatch')); return }
    setBusy(true)
    try {
      const { confirm: _c, ...body } = setup
      await api.setup({ ...body, bootstrap_token: body.bootstrap_token.trim(), username: body.username.trim(), display_name: body.display_name.trim() || body.username.trim() })
      await done()
    } catch (err) {
      fail(err)
      void setupStatus.refetch() // setup.already_done: the offer goes away
    } finally {
      setBusy(false)
    }
  }

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
    setChosen(true); setMode(m); setError(null); setNeedPin(false); setTypeBadge(false); setPin(''); setNumber(''); setPassword(''); setStep('identifier'); setSetup(emptySetup)
  }

  const tenant = brand.data?.tenant_name ?? ''
  const set = (k: keyof typeof setup) => (e: { target: { value: string } }) => setSetup({ ...setup, [k]: e.target.value })
  if (mode === 'setup') {
    return (
      <div className="login">
        <form className="setup" onSubmit={(e) => void submitSetup(e)} aria-busy={busy}>
          <div className="wordmark"><Mark />ROSTOR</div>
          <h1>{t('ui.setup.title', { tenant })}</h1>
          <div className="sub">{t('ui.setup.subtitle')}</div>
          <Field labelCode="ui.setup.token" hintCode="ui.setup.token_hint" className="input mono" value={setup.bootstrap_token} onChange={set('bootstrap_token')} required autoFocus autoComplete="off" autoCapitalize="none" spellCheck={false} />
          <Field labelCode="ui.setup.username" value={setup.username} onChange={set('username')} required autoComplete="username" autoCapitalize="none" spellCheck={false} />
          <Field labelCode="ui.setup.display_name" value={setup.display_name} onChange={set('display_name')} autoComplete="name" />
          <Field labelCode="ui.setup.password" hintCode="ui.person.new_password_rule" type="password" value={setup.password} onChange={set('password')} required minLength={8} autoComplete="new-password" />
          <Field labelCode="ui.setup.password_confirm" type="password" value={setup.confirm} onChange={set('confirm')} required autoComplete="new-password" />
          {error && <p className="form-error" role="alert">{error}</p>}
          <div className="actions">
            <button type="button" className="btn quiet" disabled={busy} onClick={() => switchMode('password')}>{t('ui.setup.back')}</button>
            <button type="submit" className="btn primary" disabled={busy}>{t(busy ? 'ui.setup.working' : 'ui.setup.submit')}</button>
          </div>
        </form>
        <ToastHost />
      </div>
    )
  }
  return (
    <div className="login">
      <form onSubmit={(e) => void submit(e)} aria-busy={busy}>
        <div className="wordmark"><Mark />ROSTOR</div>
        <h1>{t('ui.login.title', { tenant })}</h1>
        <div className="sub">{t('ui.login.subtitle')}</div>
        {mode === 'badge' ? (
          <>
            {!needPin && !typeBadge ? (
              // "Tap to access": the reader types into an invisible field
              // that keeps focus; nothing to click. Typing the number by
              // hand is one link away.
              <div className="tap" onClick={() => num.current?.focus()}>
                <div className="tap-mark" aria-hidden="true"><Mark /></div>
                <div className="tap-text">{t('ui.login.tap_to_access')}</div>
                <input id="login-badge" ref={num} className="tap-input" value={number} onChange={(e) => setNumber(e.target.value)}
                  onBlur={() => setTimeout(() => { if (mode === 'badge' && !needPin && !typeBadge) num.current?.focus() }, 50)}
                  autoComplete="off" autoCapitalize="none" spellCheck={false} inputMode="none" aria-label={t('ui.login.badge')} required />
                <button type="button" className="btn quiet" onClick={(e) => { e.stopPropagation(); setTypeBadge(true) }}>{t('ui.login.type_badge_instead')}</button>
              </div>
            ) : (
              <>
                <label htmlFor="login-badge">{t('ui.login.badge')}</label>
                <input id="login-badge" ref={num} className="input mono" value={number} onChange={(e) => setNumber(e.target.value)} readOnly={needPin}
                  autoComplete="off" autoCapitalize="none" spellCheck={false} inputMode="numeric" required />
                {!needPin && <div className="sub">{t('ui.login.badge_hint')}</div>}
              </>
            )}
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
        {!(mode === 'badge' && !needPin && !typeBadge) && (
          <div className="actions">
            <button type="submit" className="btn primary" disabled={busy}>
              {t(busy ? 'ui.login.working' : mode === 'password' && step === 'identifier' ? 'ui.login.continue' : 'ui.login.submit')}
            </button>
          </div>
        )}
        <div className="alt">
          {mode === 'password' && passkeys && <button type="button" className="btn quiet" disabled={busy} onClick={() => void usePasskey()}>{t('ui.login.use_passkey')}</button>}
          {mode === 'password'
            ? <button type="button" className="btn quiet" disabled={busy} onClick={() => switchMode('badge')}>{t('ui.login.use_badge')}</button>
            : <button type="button" className="btn quiet" disabled={busy} onClick={() => switchMode('password')}>{t('ui.login.use_password')}</button>}
        </div>
        {setupNeeded && (
          <div className="setup-offer">
            <p className="note">{t('ui.setup.offer_note')}</p>
            <button type="button" className="btn" disabled={busy} onClick={() => switchMode('setup')}>{t('ui.setup.offer')}</button>
          </div>
        )}
      </form>
      <ToastHost />
    </div>
  )
}
