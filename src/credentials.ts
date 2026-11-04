import { randomUUID } from 'node:crypto'
import type { PrivateKey } from '@libp2p/interface'
import { didFromPublicKeyRaw, keyForKid, parseDidKey, toDid } from './did.js'
import type { CredentialRow, Store } from './store.js'

/**
 * Verifiable credentials as compact JWTs (W3C VC Data Model 1.1, "VC-JWT"), signed with the issuer's Ed25519 identity
 * key (`alg: EdDSA`) and addressed by did:key. JWTs avoid JSON-LD canonicalisation, which is the usual source of
 * verifier bugs: the signature covers the exact bytes that are transmitted.
 *
 *   credential   header {alg:EdDSA, typ:JWT, kid:<iss>#<key>}  payload {iss, sub, jti, nbf, iat, exp?, vc:{@context,type,credentialSubject}}
 *   presentation header {alg:EdDSA, typ:JWT, kid}              payload {iss=holder, jti, nonce, aud?, iat, exp, vp:{@context,type,verifiableCredential:[jwt]}}
 *   revocation   header {alg:EdDSA, typ:frenet-revocation+jwt} payload {iss, iat, revokes:<credential jti>}
 *
 * Every verifier pins `alg` to EdDSA (no `none`, no algorithm confusion), pins `typ` per kind, requires the claim shapes
 * of that kind to be mutually exclusive (a credential cannot be replayed as a presentation or a revocation), and takes
 * the verification key from the issuer DID itself, never from a field the sender controls.
 */
const VC_CONTEXT = 'https://www.w3.org/2018/credentials/v1'
const VP_TYPE = 'VerifiablePresentation'
const VC_TYPE = 'VerifiableCredential'
const REVOCATION_TYP = 'frenet-revocation+jwt'
const MAX_JWT_BYTES = 16 * 1024
const MAX_VP_BYTES = 96 * 1024
const MAX_CLAIMS_BYTES = 8 * 1024
const MAX_SKEW_S = 5 * 60
const MAX_VP_CREDENTIALS = 10
const MAX_VP_TTL_MS = 60 * 60 * 1000
const DEFAULT_VP_TTL_MS = 5 * 60 * 1000
const MAX_CRED_TTL_MS = 10 * 365 * 24 * 60 * 60 * 1000
const TYPE_RE = /^[A-Za-z][A-Za-z0-9]{0,63}$/
const ID_RE = /^[A-Za-z0-9:._-]{1,100}$/
const NONCE_RE = /^[A-Za-z0-9._~+/=-]{1,128}$/
const AUD_RE = /^[\x21-\x7e]{1,200}$/   // eslint-disable-line no-control-regex
const B64U_RE = /^[A-Za-z0-9_-]+$/

export interface VerifiedCredential {
  id: string
  issuer: string
  subject: string
  types: string[]
  claims: Record<string, unknown>
  issued: number
  expires: number | null
}
export type CredentialCheck = { valid: true, credential: VerifiedCredential } | { valid: false, error: string }
export type PresentationCheck = { valid: true, holder: string, credentials: VerifiedCredential[], expires: number } | { valid: false, error: string }
export type RevocationCheck = { valid: true, issuer: string, id: string } | { valid: false, error: string }

interface Parsed { header: Record<string, unknown>, payload: Record<string, unknown>, input: Uint8Array, sig: Uint8Array }

const isObj = (x: unknown): x is Record<string, unknown> => typeof x === 'object' && x !== null && !Array.isArray(x)
const b64u = (b: Uint8Array | string): string => Buffer.from(b).toString('base64url')
const canonicalB64u = (s: string): boolean => B64U_RE.test(s) && Buffer.from(s, 'base64url').toString('base64url') === s

async function signJwt (key: PrivateKey, header: object, payload: object): Promise<string> {
  const input = `${b64u(JSON.stringify(header))}.${b64u(JSON.stringify(payload))}`
  return `${input}.${b64u(await key.sign(Buffer.from(input, 'utf8')))}`
}

/** Structure only (no trust): three canonical base64url parts, JSON objects, 64-byte signature. Throws on anything off. */
function parseJwt (jwt: unknown, max: number): Parsed {
  if (typeof jwt !== 'string' || jwt.length === 0) throw new Error('missing token')
  if (jwt.length > max) throw new Error('token too large')
  const parts = jwt.split('.')
  if (parts.length !== 3 || !parts.every((p) => canonicalB64u(p))) throw new Error('malformed token')
  const header = JSON.parse(Buffer.from(parts[0]!, 'base64url').toString('utf8'))
  const payload = JSON.parse(Buffer.from(parts[1]!, 'base64url').toString('utf8'))
  const sig = Buffer.from(parts[2]!, 'base64url')
  if (!isObj(header) || !isObj(payload) || sig.length !== 64) throw new Error('malformed token')
  return { header, payload, input: Buffer.from(`${parts[0]}.${parts[1]}`, 'utf8'), sig }
}

/** Pin alg and typ, take the key from the issuer DID, verify the signature. Returns the issuer DID. */
async function checkSignature (p: Parsed, typ: string): Promise<string> {
  if (p.header.alg !== 'EdDSA') throw new Error('unsupported alg (only EdDSA)')
  if (p.header.typ !== typ) throw new Error('wrong token type')
  const iss = p.payload.iss
  if (typeof iss !== 'string') throw new Error('missing issuer')
  const did = parseDidKey(iss).did
  const pub = keyForKid(did, p.header.kid)
  if (!(await pub.verify(p.input, p.sig))) throw new Error('bad signature')
  return did
}

const seconds = (x: unknown): x is number => Number.isSafeInteger(x) && (x as number) > 0
const msg = (e: unknown): string => (e instanceof Error ? e.message : 'invalid')

function checkJson (v: unknown, depth = 0): void {
  if (depth > 10) throw new Error('claims nested too deeply')
  if (v === null || typeof v === 'string' || typeof v === 'boolean') return
  if (typeof v === 'number') { if (!Number.isFinite(v)) throw new Error('claims must be JSON'); return }
  if (Array.isArray(v)) { for (const x of v) checkJson(x, depth + 1); return }
  if (isObj(v)) {
    for (const [k, x] of Object.entries(v)) { if (k === '__proto__') throw new Error('invalid claim name'); checkJson(x, depth + 1) }
    return
  }
  throw new Error('claims must be JSON')
}

/** Verify a credential JWT. Never throws; returns the first reason it is not acceptable. */
export async function verifyCredential (jwt: unknown, opts: { now?: number, isRevoked?: (issuer: string, id: string) => boolean } = {}): Promise<CredentialCheck> {
  try {
    const now = opts.now ?? Date.now()
    const p = parseJwt(jwt, MAX_JWT_BYTES)
    const issuer = await checkSignature(p, 'JWT')
    const pl = p.payload
    if ('vp' in pl || 'revokes' in pl) throw new Error('not a credential')
    const subject = typeof pl.sub === 'string' ? parseDidKey(pl.sub).did : (() => { throw new Error('missing subject') })()
    if (typeof pl.jti !== 'string' || !ID_RE.test(pl.jti)) throw new Error('invalid credential id')
    if (!seconds(pl.nbf) || (pl.iat !== undefined && !seconds(pl.iat))) throw new Error('invalid time claims')
    if (pl.exp !== undefined && (!seconds(pl.exp) || pl.exp < pl.nbf)) throw new Error('invalid time claims')
    const nowS = Math.floor(now / 1000)
    if (pl.nbf > nowS + MAX_SKEW_S) throw new Error('not yet valid')
    if (pl.exp !== undefined && pl.exp <= nowS) throw new Error('expired')
    const vc = pl.vc
    if (!isObj(vc)) throw new Error('missing vc')
    const ctx = vc['@context']
    if (!Array.isArray(ctx) || ctx[0] !== VC_CONTEXT) throw new Error('unsupported @context')
    const type = vc.type
    if (!Array.isArray(type) || type.length < 2 || type.length > 4 || !type.every((t) => typeof t === 'string') || !type.includes(VC_TYPE)) throw new Error('invalid type')
    const types = (type as string[]).filter((t) => t !== VC_TYPE)
    if (types.length !== type.length - 1 || !types.every((t) => TYPE_RE.test(t))) throw new Error('invalid type')
    const subj = vc.credentialSubject
    if (!isObj(subj)) throw new Error('missing credentialSubject')
    if ('id' in subj && subj.id !== subject) throw new Error('credentialSubject.id does not match sub')
    const { id: _id, ...claims } = subj
    if (opts.isRevoked?.(issuer, pl.jti)) throw new Error('revoked')
    return { valid: true, credential: { id: pl.jti, issuer, subject, types, claims, issued: pl.nbf * 1000, expires: pl.exp === undefined ? null : pl.exp * 1000 } }
  } catch (e) { return { valid: false, error: msg(e) } }
}

export async function verifyRevocation (jwt: unknown): Promise<RevocationCheck> {
  try {
    const p = parseJwt(jwt, 2048)
    const issuer = await checkSignature(p, REVOCATION_TYP)
    const pl = p.payload
    if ('vc' in pl || 'vp' in pl) throw new Error('not a revocation')
    if (typeof pl.revokes !== 'string' || !ID_RE.test(pl.revokes)) throw new Error('invalid credential id')
    if (!seconds(pl.iat)) throw new Error('invalid time claims')
    return { valid: true, issuer, id: pl.revokes }
  } catch (e) { return { valid: false, error: msg(e) } }
}

/**
 * Verify a presentation. The verifier must supply the `nonce` it handed to the holder (a fresh challenge per request),
 * which is what stops a captured presentation being replayed; if the presentation names an audience, the verifier
 * must name itself and it must match. Every embedded credential must verify and be about the presenting holder.
 */
export async function verifyPresentation (jwt: unknown, opts: { nonce: string, audience?: string, now?: number, isRevoked?: (issuer: string, id: string) => boolean }): Promise<PresentationCheck> {
  try {
    if (typeof opts.nonce !== 'string' || !NONCE_RE.test(opts.nonce)) throw new Error('verifier nonce required')
    const now = opts.now ?? Date.now()
    const p = parseJwt(jwt, MAX_VP_BYTES)
    const holder = await checkSignature(p, 'JWT')
    const pl = p.payload
    if ('vc' in pl || 'revokes' in pl) throw new Error('not a presentation')
    if (pl.nonce !== opts.nonce) throw new Error('nonce mismatch')
    if (pl.aud !== undefined && pl.aud !== opts.audience) throw new Error('audience mismatch')
    if (typeof pl.jti !== 'string' || !ID_RE.test(pl.jti)) throw new Error('invalid presentation id')
    if (!seconds(pl.iat) || !seconds(pl.exp) || pl.exp < pl.iat) throw new Error('invalid time claims')
    const nowS = Math.floor(now / 1000)
    if (pl.iat > nowS + MAX_SKEW_S) throw new Error('not yet valid')
    if (pl.exp <= nowS) throw new Error('expired')
    const vp = pl.vp
    if (!isObj(vp)) throw new Error('missing vp')
    const type = vp.type
    if (!Array.isArray(type) || !type.includes(VP_TYPE)) throw new Error('invalid type')
    const list = vp.verifiableCredential
    if (!Array.isArray(list) || list.length === 0 || list.length > MAX_VP_CREDENTIALS) throw new Error('invalid credential list')
    const credentials: VerifiedCredential[] = []
    for (const c of list) {
      const r = await verifyCredential(c, { now, ...(opts.isRevoked ? { isRevoked: opts.isRevoked } : {}) })
      if (!r.valid) throw new Error(`credential: ${r.error}`)
      if (r.credential.subject !== holder) throw new Error('credential is not about the presenter')
      credentials.push(r.credential)
    }
    return { valid: true, holder, credentials, expires: pl.exp * 1000 }
  } catch (e) { return { valid: false, error: msg(e) } }
}

/** Issuer, holder and verifier operations for this node's identity key, backed by the local store. */
export class Credentials {
  readonly did: string

  constructor (private store: Store, private key: PrivateKey) {
    this.did = didFromPublicKeyRaw(key.publicKey.raw)
  }

  private get kid (): string { return `${this.did}#${parseDidKey(this.did).keyId}` }
  private isRevoked = (issuer: string, id: string): boolean => this.store.isRevoked(issuer, id)

  /** Sign a credential about `subject` (a did:key or an Ed25519 peer ID). `claims` is plain JSON (<= 8 KB, no `id`). */
  async issue (subject: string, type: string, claims: unknown, opts: { ttlMs?: number } = {}): Promise<{ id: string, jwt: string, credential: VerifiedCredential }> {
    const sub = toDid(subject)
    if (typeof type !== 'string' || !TYPE_RE.test(type) || type === VC_TYPE) throw new Error('invalid credential type (letters and digits, starting with a letter, max 64)')
    if (!isObj(claims)) throw new Error('claims must be an object')
    if ('id' in claims) throw new Error('claims may not contain "id" (the subject is set from the DID)')
    const raw = JSON.stringify(claims)
    if (raw === undefined || Buffer.byteLength(raw) > MAX_CLAIMS_BYTES) throw new Error(`claims must be JSON of at most ${MAX_CLAIMS_BYTES} bytes`)
    const clean = JSON.parse(raw) as Record<string, unknown>
    checkJson(clean)
    if (opts.ttlMs !== undefined && (!Number.isFinite(opts.ttlMs) || opts.ttlMs <= 0 || opts.ttlMs > MAX_CRED_TTL_MS)) throw new Error('invalid expiry')
    const nowS = Math.floor(Date.now() / 1000)
    const id = `urn:uuid:${randomUUID()}`
    const payload = {
      iss: this.did,
      sub,
      jti: id,
      iat: nowS,
      nbf: nowS,
      ...(opts.ttlMs ? { exp: nowS + Math.max(1, Math.floor(opts.ttlMs / 1000)) } : {}),
      vc: { '@context': [VC_CONTEXT], type: [VC_TYPE, type], credentialSubject: clean }
    }
    const jwt = await signJwt(this.key, { alg: 'EdDSA', typ: 'JWT', kid: this.kid }, payload)
    const check = await verifyCredential(jwt)
    if (!check.valid) throw new Error(`internal error: produced an invalid credential (${check.error})`)
    const c = check.credential
    this.store.addCredential({ id, role: 'issued', issuer: this.did, subject: sub, type, issued: c.issued, expires: c.expires, jwt })
    return { id, jwt, credential: c }
  }

  /** Verify any credential JWT against the revocations this node knows. */
  verify (jwt: unknown): Promise<CredentialCheck> { return verifyCredential(jwt, { isRevoked: this.isRevoked }) }

  /** Keep a credential issued to us. Only valid credentials about our own DID are stored. */
  async hold (jwt: unknown): Promise<VerifiedCredential> {
    const r = await this.verify(jwt)
    if (!r.valid) throw new Error(`credential rejected: ${r.error}`)
    if (r.credential.subject !== this.did) throw new Error('credential is not addressed to this identity')
    this.store.addCredential({ id: r.credential.id, role: 'held', issuer: r.credential.issuer, subject: r.credential.subject, type: r.credential.types[0] ?? '', issued: r.credential.issued, expires: r.credential.expires, jwt: jwt as string })
    return r.credential
  }

  list (role?: 'issued' | 'held'): Array<CredentialRow & { revoked: boolean, expired: boolean }> {
    const now = Date.now()
    return this.store.listCredentials(role).map((c) => ({ ...c, revoked: this.store.isRevoked(c.issuer, c.id), expired: c.expires !== null && c.expires <= now }))
  }

  remove (id: string, role: 'issued' | 'held'): boolean { return this.store.deleteCredential(id, role) }

  /** Revoke a credential we issued. Returns a signed statement that verifiers import with `importRevocation`. */
  async revoke (id: string): Promise<{ id: string, jwt: string }> {
    if (!this.store.getCredential(id, 'issued')) throw new Error('no such credential issued by this identity')
    const jwt = await signJwt(this.key, { alg: 'EdDSA', typ: REVOCATION_TYP, kid: this.kid }, { iss: this.did, iat: Math.floor(Date.now() / 1000), revokes: id })
    this.store.addRevocation(this.did, id, jwt)
    return { id, jwt }
  }

  /** Accept a signed revocation statement from any issuer. It only ever affects that issuer's own credentials. */
  async importRevocation (jwt: unknown): Promise<{ issuer: string, id: string }> {
    const r = await verifyRevocation(jwt)
    if (!r.valid) throw new Error(`revocation rejected: ${r.error}`)
    this.store.addRevocation(r.issuer, r.id, jwt as string)
    return { issuer: r.issuer, id: r.id }
  }

  /** Present held credentials (by id) to a verifier. `nonce` is the verifier's challenge; short-lived by default. */
  async present (ids: string[], nonce: string, opts: { audience?: string, ttlMs?: number } = {}): Promise<{ jwt: string, expires: number }> {
    if (!Array.isArray(ids) || ids.length === 0 || ids.length > MAX_VP_CREDENTIALS) throw new Error(`choose 1-${MAX_VP_CREDENTIALS} credentials`)
    if (typeof nonce !== 'string' || !NONCE_RE.test(nonce)) throw new Error('nonce required (1-128 chars: letters, digits, . _ ~ + / = -)')
    if (opts.audience !== undefined && !AUD_RE.test(opts.audience)) throw new Error('invalid audience')
    const ttl = opts.ttlMs ?? DEFAULT_VP_TTL_MS
    if (!Number.isFinite(ttl) || ttl < 1000 || ttl > MAX_VP_TTL_MS) throw new Error('presentation lifetime must be 1 s to 1 h')
    const jwts: string[] = []
    for (const id of new Set(ids)) {
      const row = this.store.getCredential(String(id), 'held')
      if (!row) throw new Error('credential not held by this identity')
      const r = await this.verify(row.jwt)   // re-check: it may have expired or been revoked since it was stored
      if (!r.valid) throw new Error(`credential ${row.id} is no longer valid: ${r.error}`)
      jwts.push(row.jwt)
    }
    const nowS = Math.floor(Date.now() / 1000)
    const expS = nowS + Math.floor(ttl / 1000)
    const payload = {
      iss: this.did,
      jti: `urn:uuid:${randomUUID()}`,
      nonce,
      ...(opts.audience ? { aud: opts.audience } : {}),
      iat: nowS,
      exp: expS,
      vp: { '@context': [VC_CONTEXT], type: [VP_TYPE], verifiableCredential: jwts }
    }
    return { jwt: await signJwt(this.key, { alg: 'EdDSA', typ: 'JWT', kid: this.kid }, payload), expires: expS * 1000 }
  }

  verifyPresentation (jwt: unknown, nonce: string, audience?: string): Promise<PresentationCheck> {
    return verifyPresentation(jwt, { nonce, ...(audience !== undefined ? { audience } : {}), isRevoked: this.isRevoked })
  }
}
