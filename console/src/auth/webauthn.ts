// Browser side of the passkey ceremonies. The server hands out the WebAuthn
// JSON options (base64url fields, wrapped as {publicKey: …} by go-webauthn);
// this module turns them into what navigator.credentials wants and turns the
// credential back into the JSON the server parses. It prefers the WebAuthn
// Level 3 JSON helpers and falls back to manual base64url handling on
// browsers that lack them (older Safari/Firefox).
import { isMock } from '../api'
import type { CreationOptionsJSON, OptionsWrapper, RequestOptionsJSON } from '../api'

// ---- base64url --------------------------------------------------------------

export function b64urlDecode(s: string): ArrayBuffer {
  const pad = s.length % 4 === 0 ? '' : '='.repeat(4 - (s.length % 4))
  const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/') + pad)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out.buffer
}

export function b64urlEncode(buf: ArrayBuffer | ArrayBufferView): string {
  const bytes = buf instanceof ArrayBuffer ? new Uint8Array(buf) : new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength)
  let bin = ''
  for (const b of bytes) bin += String.fromCharCode(b)
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

// ---- feature detection ------------------------------------------------------

type PKC = typeof PublicKeyCredential & {
  parseCreationOptionsFromJSON?: (o: CreationOptionsJSON) => PublicKeyCredentialCreationOptions
  parseRequestOptionsFromJSON?: (o: RequestOptionsJSON) => PublicKeyCredentialRequestOptions
  isConditionalMediationAvailable?: () => Promise<boolean>
}

function pkc(): PKC | null {
  if (typeof window === 'undefined' || !('PublicKeyCredential' in window) || !window.isSecureContext) return null
  return window.PublicKeyCredential as PKC
}

/** True when this page can run a passkey ceremony (secure context + WebAuthn). */
export function passkeysSupported(): boolean {
  return isMock() || pkc() !== null
}

/** True when the browser can offer passkeys in the username field's autofill. Never in mock mode: it would sign in on page load. */
export async function conditionalMediationAvailable(): Promise<boolean> {
  if (isMock()) return false
  const c = pkc()
  if (!c?.isConditionalMediationAvailable) return false
  try { return await c.isConditionalMediationAvailable() } catch { return false }
}

/** A default label for a new passkey: the browser brand, else a generic name. */
export function defaultPasskeyLabel(fallback: string): string {
  const uad = (navigator as Navigator & { userAgentData?: { brands?: Array<{ brand: string }> } }).userAgentData
  // Skip the GREASE entry ("Not?A_Brand" and friends) and prefer the product over the engine.
  const brands = (uad?.brands ?? []).map((b) => b.brand).filter((b) => !/not.?a.?brand/i.test(b))
  const brand = brands.find((b) => !/chromium/i.test(b)) ?? brands[0]
  return brand ? `${fallback} (${brand})` : fallback
}

// ---- options: JSON → the dictionaries navigator.credentials wants -----------

function unwrap<O>(o: OptionsWrapper<O>): O {
  return (o && typeof o === 'object' && 'publicKey' in o) ? (o as { publicKey: O }).publicKey : (o as O)
}

function toCreationOptions(json: CreationOptionsJSON): PublicKeyCredentialCreationOptions {
  const c = pkc()
  if (c?.parseCreationOptionsFromJSON) return c.parseCreationOptionsFromJSON(json)
  const { challenge, user, excludeCredentials, ...rest } = json
  return {
    ...rest,
    challenge: b64urlDecode(challenge),
    user: { ...user, id: b64urlDecode(user.id) },
    excludeCredentials: (excludeCredentials ?? []).map((d) => ({ ...d, id: b64urlDecode(d.id) } as PublicKeyCredentialDescriptor)),
  } as PublicKeyCredentialCreationOptions
}

function toRequestOptions(json: RequestOptionsJSON): PublicKeyCredentialRequestOptions {
  const c = pkc()
  if (c?.parseRequestOptionsFromJSON) return c.parseRequestOptionsFromJSON(json)
  const { challenge, allowCredentials, ...rest } = json
  return {
    ...rest,
    challenge: b64urlDecode(challenge),
    allowCredentials: (allowCredentials ?? []).map((d) => ({ ...d, id: b64urlDecode(d.id) } as PublicKeyCredentialDescriptor)),
  } as PublicKeyCredentialRequestOptions
}

// ---- credential → JSON -------------------------------------------------------

function credentialToJSON(cred: PublicKeyCredential): PublicKeyCredentialJSON {
  const c = cred as PublicKeyCredential & { toJSON?: () => PublicKeyCredentialJSON; authenticatorAttachment?: string | null }
  if (typeof c.toJSON === 'function') return c.toJSON()
  const r = cred.response
  const response: Record<string, unknown> = { clientDataJSON: b64urlEncode(r.clientDataJSON) }
  if ('attestationObject' in r) {
    const a = r as AuthenticatorAttestationResponse & { getTransports?: () => string[] }
    response['attestationObject'] = b64urlEncode(a.attestationObject)
    response['transports'] = a.getTransports?.() ?? []
  } else {
    const a = r as AuthenticatorAssertionResponse
    response['authenticatorData'] = b64urlEncode(a.authenticatorData)
    response['signature'] = b64urlEncode(a.signature)
    if (a.userHandle) response['userHandle'] = b64urlEncode(a.userHandle)
  }
  return {
    id: cred.id, rawId: b64urlEncode(cred.rawId), type: cred.type, response,
    authenticatorAttachment: c.authenticatorAttachment ?? undefined,
    clientExtensionResults: cred.getClientExtensionResults(),
  } as unknown as PublicKeyCredentialJSON
}

// ---- ceremonies --------------------------------------------------------------

/** Registration: the browser creates a credential for the server's options. */
export async function createPasskey(options: OptionsWrapper<CreationOptionsJSON>): Promise<PublicKeyCredentialJSON> {
  if (isMock()) return mockCredential('attestation')
  const cred = await navigator.credentials.create({ publicKey: toCreationOptions(unwrap(options)) })
  if (!(cred instanceof PublicKeyCredential)) throw new DOMException('no credential', 'NotAllowedError')
  return credentialToJSON(cred)
}

/**
 * Assertion. `mediation: "conditional"` keeps the request pending in the
 * username field's autofill until the user picks a passkey or the signal
 * aborts; anything else shows the browser's modal right away.
 */
export async function getPasskey(options: OptionsWrapper<RequestOptionsJSON>, opts: { mediation?: CredentialMediationRequirement; signal?: AbortSignal } = {}): Promise<PublicKeyCredentialJSON> {
  if (isMock()) return mockCredential('assertion')
  const cred = await navigator.credentials.get({ publicKey: toRequestOptions(unwrap(options)), mediation: opts.mediation, signal: opts.signal })
  if (!(cred instanceof PublicKeyCredential)) throw new DOMException('no credential', 'NotAllowedError')
  return credentialToJSON(cred)
}

/** The user dismissed the prompt, or we aborted it: nothing to report. */
export function isCancelled(err: unknown): boolean {
  return err instanceof DOMException && (err.name === 'NotAllowedError' || err.name === 'AbortError')
}

// Mock mode has no server to verify anything, so the ceremony resolves at
// once with a well-formed but meaningless credential.
function mockCredential(kind: 'attestation' | 'assertion'): PublicKeyCredentialJSON {
  const id = b64urlEncode(crypto.getRandomValues(new Uint8Array(16)))
  const response = kind === 'attestation'
    ? { clientDataJSON: '', attestationObject: '', transports: ['internal'] }
    : { clientDataJSON: '', authenticatorData: '', signature: '' }
  return { id, rawId: id, type: 'public-key', response, clientExtensionResults: {} } as unknown as PublicKeyCredentialJSON
}
