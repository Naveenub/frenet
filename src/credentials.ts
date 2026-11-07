import { randomUUID } from 'node:crypto'
import type { PrivateKey } from '@libp2p/interface'
import { didFromPublicKeyRaw, frenetId, isFrenetDid, keyForKid, parseDidKey, toDid } from './did.js'
import { isWebDid, webKeyForKid, type WebDids } from './webid.js'
import { keyForSignature, type IdentityLogs, type IdentityState } from './identity-log.js'
import type { Revocations } from './revocations.js'
import type { CredentialRow, Store } from './store.js'

/**
 * Verifiable credentials as compact JWTs (W3C VC Data Model 1.1, "VC-JWT"), signed with the issuer's Ed25519 identity
 * key (`alg: EdDSA`) and addressed by DID: `did:key` (fixed key) or `did:frenet` (rotatable, see identity-log.ts). JWTs
 * avoid JSON-LD canonicalisation, which is the usual source of verifier bugs: the signature covers the exact bytes sent.
 *
 *   credential   header {alg:EdDSA, typ:JWT, kid:<iss>#<key>}  payload {iss, sub, jti, nbf, iat, exp?, vc:{@context,type,credentialSubject}}
 *   presentation header {alg:EdDSA, typ:JWT, kid}              payload {iss=holder, jti, nonce, aud?, iat, exp, vp:{@context,type,verifiableCredential:[jwt]}}
 *   revocation   header {alg:EdDSA, typ:frenet-revocation+jwt} payload {iss, iat, revokes:<credential jti>}
 *
 * Every verifier pins `alg` to EdDSA (no `none`, no algorithm confusion), pins `typ` per kind, requires the claim shapes
 * of that kind to be mutually exclusive (a credential cannot be replayed as a presentation or a revocation), and takes
 * the verification key from the issuer DID itself (for did:frenet: from its verified key log), never from a field the
 * sender controls. For did:frenet the kid is `<did>#<seq>` (the key epoch) and `iat` is required: a superseded key is
 * accepted only for signatures dated before its rotation (never under `strict`).
 */
const VC_CONTEXT = 'https://www.w3.org/2018/credentials/v1'
const VP_TYPE = 'VerifiablePresentation'
const VC_TYPE = 'VerifiableCredential'
const REVOCATION_TYP = 'frenet-revocation+jwt'
const MAX_JWT_BYTES = 16 * 1024
export const MAX_REVOCATION_JWT = 2048
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

/** Finds the key log of a did:frenet id (null if unknown). `minSeq` asks for at least that key epoch. */
export type LogResolver = (id: string, opts?: { minSeq?: number }) => Promise<IdentityState | null>
export interface VerifyOptions {
  now?: number
  isRevoked?: (issuer: string, id: string) => boolean
  /** Needed to verify did:frenet signers; without it they are rejected. */
  resolveLog?: LogResolver
  /** Needed to verify did:web signers; without it they are rejected. */
  web?: WebDids
  /** Refuse signatures by superseded keys even if dated before the rotation. */
  strict?: boolean
}

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

const seconds = (x: unknown): x is number => Number.isSafeInteger(x) && (x as number) > 0
const msg = (e: unknown): string => (e instanceof Error ? e.message : 'invalid')

/** Pin alg and typ, take the key from the issuer DID (or its verified key log), verify the signature. Returns the issuer DID. */
async function checkSignature (p: Parsed, typ: string, o: VerifyOptions): Promise<string> {
  if (p.header.alg !== 'EdDSA') throw new Error('unsupported alg (only EdDSA)')
  if (p.header.typ !== typ) throw new Error('wrong token type')
  const iss = p.payload.iss
  if (typeof iss !== 'string') throw new Error('missing issuer')
  if (isFrenetDid(iss)) {
    const kid = p.header.kid
    const m = typeof kid === 'string' && kid.startsWith(`${iss}#`) ? /^(0|[1-9][0-9]{0,3})$/.exec(kid.slice(iss.length + 1)) : null
    if (!m) throw new Error('kid does not match issuer')
    const seq = Number(m[1])
    if (!seconds(p.payload.iat)) throw new Error('iat is required for did:frenet signers')
    if (!o.resolveLog) throw new Error('cannot resolve did:frenet here')
    const id = frenetId(iss)
    let st = await o.resolveLog(id)
    if (st && seq > st.seq) st = await o.resolveLog(id, { minSeq: seq })   // the signer may have rotated since we last looked
    if (!st) throw new Error('unknown identity (no key log available)')
    if (!(await keyForSignature(st, seq, p.payload.iat * 1000, o.strict).verify(p.input, p.sig))) throw new Error('bad signature')
    return iss
  }
  if (isWebDid(iss)) {
    if (!o.web) throw new Error('cannot resolve did:web here')
    if (!(await webKeyForKid(await o.web.resolve(iss), p.header.kid).verify(p.input, p.sig))) throw new Error('bad signature')
    return iss
  }
  const did = parseDidKey(iss).did
  if (!(await keyForKid(did, p.header.kid).verify(p.input, p.sig))) throw new Error('bad signature')
  return did
}

const subjectDid = (sub: unknown): string => {
  if (typeof sub !== 'string') throw new Error('missing subject')
  return isFrenetDid(sub) || isWebDid(sub) ? sub : parseDidKey(sub).did
}

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
export async function verifyCredential (jwt: unknown, opts: VerifyOptions = {}): Promise<CredentialCheck> {
  try {
    const now = opts.now ?? Date.now()
    const p = parseJwt(jwt, MAX_JWT_BYTES)
    const issuer = await checkSignature(p, 'JWT', opts)
    const pl = p.payload
    if ('vp' in pl || 'revokes' in pl) throw new Error('not a credential')
    const subject = subjectDid(pl.sub)
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

export async function verifyRevocation (jwt: unknown, opts: Pick<VerifyOptions, 'resolveLog' | 'strict' | 'web'> = {}): Promise<RevocationCheck> {
  try {
    const p = parseJwt(jwt, MAX_REVOCATION_JWT)
    const issuer = await checkSignature(p, REVOCATION_TYP, opts)
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
export async function verifyPresentation (jwt: unknown, opts: VerifyOptions & { nonce: string, audience?: string }): Promise<PresentationCheck> {
  try {
    if (typeof opts.nonce !== 'string' || !NONCE_RE.test(opts.nonce)) throw new Error('verifier nonce required')
    const now = opts.now ?? Date.now()
    const p = parseJwt(jwt, MAX_VP_BYTES)
    const holder = await checkSignature(p, 'JWT', opts)
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
      const r = await verifyCredential(c, { ...opts, now })
      if (!r.valid) throw new Error(`credential: ${r.error}`)
      if (r.credential.subject !== holder) throw new Error('credential is not about the presenter')
      credentials.push(r.credential)
    }
    return { valid: true, holder, credentials, expires: pl.exp * 1000 }
  } catch (e) { return { valid: false, error: msg(e) } }
}

export interface CredentialsOptions {
  /** The node's rotatable identity, if it has one; credentials are then issued under its did:frenet. */
  identity?: IdentityState | null
  /** Where unknown did:frenet logs come from (network). Without it, only our own log is known. */
  logs?: IdentityLogs
  /** Revocation distribution (network). Without it, only locally imported statements count. */
  revocations?: Revocations
  /** did:web resolver (network). Without it, did:web issuers are rejected. */
  web?: WebDids
}

/** Issuer, holder and verifier operations for this node's identity key, backed by the local store. */
export class Credentials {
  /** Primary DID: did:frenet when the identity has a key log, otherwise did:key. */
  readonly did: string
  /** did:key of the current signing key (always exists; also what held credentials from before rotation setup name). */
  readonly keyDid: string
  private identity: IdentityState | null

  constructor (private store: Store, private key: PrivateKey, private opts: CredentialsOptions = {}) {
    this.keyDid = didFromPublicKeyRaw(key.publicKey.raw)
    this.identity = opts.identity ?? null
    this.did = this.identity ? this.identity.did : this.keyDid
  }

  private kidFor (did: string): string {
    if (did === this.keyDid) return `${did}#${parseDidKey(did).keyId}`
    if (this.identity && did === this.identity.did) return `${did}#${this.identity.seq}`
    throw new Error('this identity does not control that DID (its key was rotated?)')
  }

  private resolver (online: boolean): LogResolver {
    return async (id, o) => {
      const own = this.identity && this.identity.id === id ? this.identity : null
      if (own && (o?.minSeq === undefined || own.seq >= o.minSeq)) return own
      return this.opts.logs ? this.opts.logs.resolve(id, { network: online, ...(o?.minSeq !== undefined ? { minSeq: o.minSeq } : {}) }) : null
    }
  }

  private isRevoked = (issuer: string, id: string): boolean => this.store.isRevoked(issuer, id)

  /** Sign a credential about `subject` (a DID or an Ed25519 peer ID). `claims` is plain JSON (<= 8 KB, no `id`). */
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
    const jwt = await signJwt(this.key, { alg: 'EdDSA', typ: 'JWT', kid: this.kidFor(this.did) }, payload)
    const check = await verifyCredential(jwt, { resolveLog: this.resolver(false) })
    if (!check.valid) throw new Error(`internal error: produced an invalid credential (${check.error})`)
    const c = check.credential
    this.store.addCredential({ id, role: 'issued', issuer: this.did, subject: sub, type, issued: c.issued, expires: c.expires, jwt })
    return { id, jwt, credential: c }
  }

  /**
   * Verify any credential JWT: signature and claims, then revocations we hold, then (unless `online: false`) a lookup of
   * revocations on the network. "Valid" means not known to be revoked; see revocations.ts for what that cannot show.
   */
  async verify (jwt: unknown, opts: { online?: boolean, strict?: boolean } = {}): Promise<CredentialCheck> {
    const online = opts.online !== false
    const r = await verifyCredential(jwt, { isRevoked: this.isRevoked, resolveLog: this.resolver(online), ...(this.opts.web && online ? { web: this.opts.web } : {}), ...(opts.strict ? { strict: true } : {}) })
    if (r.valid && online && this.opts.revocations && await this.opts.revocations.lookup(r.credential.issuer, r.credential.id)) return { valid: false, error: 'revoked' }
    return r
  }

  /** Keep a credential issued to us. Only valid credentials about one of our own DIDs are stored. */
  async hold (jwt: unknown): Promise<VerifiedCredential> {
    const r = await this.verify(jwt)
    if (!r.valid) throw new Error(`credential rejected: ${r.error}`)
    if (r.credential.subject !== this.did && r.credential.subject !== this.keyDid) throw new Error('credential is not addressed to this identity')
    this.store.addCredential({ id: r.credential.id, role: 'held', issuer: r.credential.issuer, subject: r.credential.subject, type: r.credential.types[0] ?? '', issued: r.credential.issued, expires: r.credential.expires, jwt: jwt as string })
    return r.credential
  }

  list (role?: 'issued' | 'held'): Array<CredentialRow & { revoked: boolean, expired: boolean }> {
    const now = Date.now()
    return this.store.listCredentials(role).map((c) => ({ ...c, revoked: this.store.isRevoked(c.issuer, c.id), expired: c.expires !== null && c.expires <= now }))
  }

  remove (id: string, role: 'issued' | 'held'): boolean { return this.store.deleteCredential(id, role) }

  /**
   * Revoke a credential we issued. Returns a signed statement; it is also kept locally, announced on the DHT and pushed
   * to connected peers (`pushed` = how many accepted it). Anyone can import it with `importRevocation`.
   */
  async revoke (id: string): Promise<{ id: string, jwt: string, pushed: number }> {
    const row = this.store.getCredential(id, 'issued')
    if (!row) throw new Error('no such credential issued by this identity')
    const jwt = await signJwt(this.key, { alg: 'EdDSA', typ: REVOCATION_TYP, kid: this.kidFor(row.issuer) }, { iss: row.issuer, iat: Math.floor(Date.now() / 1000), revokes: id })
    this.store.addRevocation(row.issuer, id, jwt, true)
    let pushed = 0
    if (this.opts.revocations) {
      void this.opts.revocations.announce(row.issuer, id)
      pushed = await this.opts.revocations.push(jwt)
    }
    return { id, jwt, pushed }
  }

  /** Accept a signed revocation statement from any issuer. It only ever affects that issuer's own credentials. */
  async importRevocation (jwt: unknown): Promise<{ issuer: string, id: string }> {
    const r = await verifyRevocation(jwt, { resolveLog: this.resolver(true), ...(this.opts.web ? { web: this.opts.web } : {}) })
    if (!r.valid) throw new Error(`revocation rejected: ${r.error}`)
    if (this.opts.revocations) await this.opts.revocations.accept(r.issuer, r.id, jwt as string)
    else this.store.addRevocation(r.issuer, r.id, jwt as string)
    return { issuer: r.issuer, id: r.id }
  }

  /** Verifier for revocation statements, for the network handler (shares the DID resolver). */
  checkRevocation = (jwt: unknown): Promise<RevocationCheck> => verifyRevocation(jwt, { resolveLog: this.resolver(true), ...(this.opts.web ? { web: this.opts.web } : {}) })

  /**
   * Present held credentials (by id) to a verifier. `nonce` is the verifier's challenge; short-lived by default. All
   * credentials must name the same subject, which must be a DID this identity currently controls; the presentation is
   * signed as that DID.
   */
  async present (ids: string[], nonce: string, opts: { audience?: string, ttlMs?: number } = {}): Promise<{ jwt: string, expires: number }> {
    if (!Array.isArray(ids) || ids.length === 0 || ids.length > MAX_VP_CREDENTIALS) throw new Error(`choose 1-${MAX_VP_CREDENTIALS} credentials`)
    if (typeof nonce !== 'string' || !NONCE_RE.test(nonce)) throw new Error('nonce required (1-128 chars: letters, digits, . _ ~ + / = -)')
    if (opts.audience !== undefined && !AUD_RE.test(opts.audience)) throw new Error('invalid audience')
    const ttl = opts.ttlMs ?? DEFAULT_VP_TTL_MS
    if (!Number.isFinite(ttl) || ttl < 1000 || ttl > MAX_VP_TTL_MS) throw new Error('presentation lifetime must be 1 s to 1 h')
    const jwts: string[] = []
    const subjects = new Set<string>()
    for (const id of new Set(ids)) {
      const row = this.store.getCredential(String(id), 'held')
      if (!row) throw new Error('credential not held by this identity')
      const r = await this.verify(row.jwt)   // re-check: it may have expired or been revoked since it was stored
      if (!r.valid) throw new Error(`credential ${row.id} is no longer valid: ${r.error}`)
      subjects.add(r.credential.subject)
      jwts.push(row.jwt)
    }
    if (subjects.size !== 1) throw new Error('credentials in one presentation must all be about the same DID')
    const holder = [...subjects][0]!
    const kid = this.kidFor(holder)
    const nowS = Math.floor(Date.now() / 1000)
    const expS = nowS + Math.floor(ttl / 1000)
    const payload = {
      iss: holder,
      jti: `urn:uuid:${randomUUID()}`,
      nonce,
      ...(opts.audience ? { aud: opts.audience } : {}),
      iat: nowS,
      exp: expS,
      vp: { '@context': [VC_CONTEXT], type: [VP_TYPE], verifiableCredential: jwts }
    }
    return { jwt: await signJwt(this.key, { alg: 'EdDSA', typ: 'JWT', kid }, payload), expires: expS * 1000 }
  }

  async verifyPresentation (jwt: unknown, nonce: string, audience?: string, opts: { online?: boolean, strict?: boolean } = {}): Promise<PresentationCheck> {
    const online = opts.online !== false
    const r = await verifyPresentation(jwt, { nonce, ...(audience !== undefined ? { audience } : {}), isRevoked: this.isRevoked, resolveLog: this.resolver(online), ...(this.opts.web && online ? { web: this.opts.web } : {}), ...(opts.strict ? { strict: true } : {}) })
    if (r.valid && online && this.opts.revocations) {
      for (const c of r.credentials) if (await this.opts.revocations.lookup(c.issuer, c.id)) return { valid: false, error: `credential: revoked` }
    }
    return r
  }
}
