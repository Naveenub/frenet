import { createHash, randomBytes } from 'node:crypto'
import type { PrivateKey } from '@libp2p/interface'
import { ed25519, ed25519_hasher } from '@noble/curves/ed25519.js'
import { base32 } from 'multiformats/bases/base32'
import { isFrenetDid, frenetId, parseDidKey, didFromPeerId } from './did.js'
import type { Store } from './store.js'

/**
 * Zero-knowledge membership authentication: "I am one of these N identities, and this is my one-per-scope tag", without
 * saying which. It is a *linkable ring signature* (LSAG, Liu-Wei-Wong 2004) made non-interactive with Fiat-Shamir, over
 * the same Ed25519 keys as every other FRENET identity (group law from @noble/curves; no new key, no new curve, no
 * proprietary primitive). Formally it is a non-interactive proof of knowledge of x such that
 *
 *     P_i = x*G for SOME i in the ring        and        I = x*H(scope)
 *
 * which is zero-knowledge for the index i (the transcript of an honest prover is distributed independently of i), and
 * sound under discrete log in the random-oracle model.
 *
 * What a verifier learns: the signer is in the ring; the tag I. Same member + same scope => same tag, so a verifier can
 * enforce "once per scope" (a vote, a claim, a rate limit) and cannot tell *who*. Different scopes give tags that are
 * unlinkable to each other (DDH on Ed25519). The proof is bound to scope, a verifier nonce, an optional audience and the
 * exact ring, so it cannot be replayed elsewhere, to another verifier, or against a bigger or smaller ring.
 *
 * Proof (bytes): 0x01 | I (32) | c0 (32) | s_0 .. s_{n-1} (32 each); all points compressed Edwards, all scalars canonical
 * little-endian. Size 65 + 32n. Verification and signing cost O(n) scalar multiplications; the ring is capped at 1024.
 *
 * Limits, stated plainly: the anonymity set is the ring, so a ring of 2 hides little, and a verifier can pad a ring with
 * keys it knows belong to nobody, which shrinks the set to the real members: a prover should check that the ring is the
 * one it expects. A tag is a stable pseudonym inside its scope (never reuse a scope for things that must stay unlinkable).
 * did:frenet members count by their *current* key. This is not a general-purpose zk-SNARK, proves nothing about the
 * contents of credentials, and has not been independently audited.
 */
const DOM = 'frenet/zk-ring/v1'
const VERSION = 1
export const MIN_RING = 2
export const MAX_RING = 1024
/** Policy default for ZkAuth: a ring smaller than this hides too little to be worth calling anonymous. */
export const DEFAULT_MIN_RING = 5
const NONCE_RE = /^[A-Za-z0-9._~+/=-]{1,128}$/
const TEXT_RE = /^[\x21-\x7e]{1,200}$/   // eslint-disable-line no-control-regex
const CHALLENGE_TTL_MS = 2 * 60 * 1000
const MAX_CHALLENGES = 1000

const Point = ed25519.Point
type Pt = InstanceType<typeof Point>
const G = Point.BASE
const Fn = Point.Fn
const L = Fn.ORDER

const leToBig = (b: Uint8Array): bigint => { let n = 0n; for (let i = b.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(b[i]!); return n }
const bigToLe32 = (n: bigint): Uint8Array => { const o = new Uint8Array(32); for (let i = 0; i < 32; i++) { o[i] = Number(n & 0xffn); n >>= 8n } return o }
const eq = (a: Uint8Array, b: Uint8Array): boolean => a.length === b.length && Buffer.compare(a, b) === 0

/** Length-prefixed concatenation, so no two different tuples hash the same bytes. */
function lp (...parts: Array<Uint8Array | string>): Buffer {
  const out: Buffer[] = []
  for (const p of parts) {
    const b = typeof p === 'string' ? Buffer.from(p, 'utf8') : Buffer.from(p)
    const len = Buffer.alloc(4); len.writeUInt32BE(b.length)
    out.push(len, b)
  }
  return Buffer.concat(out)
}
const sha512 = (...parts: Array<Uint8Array | string>): Buffer => createHash('sha512').update(lp(...parts)).digest()
const hashScalar = (...parts: Array<Uint8Array | string>): bigint => Fn.create(leToBig(sha512(...parts)))
const randomScalar = (): bigint => { for (;;) { const k = Fn.create(leToBig(randomBytes(64))); if (k !== 0n) return k } }

/** Everything the proof is bound to, hashed once. */
function context (ring: Uint8Array[], scope: string, nonce: string, audience: string): Buffer {
  return sha512(`${DOM}/ctx`, String(ring.length), scope, nonce, audience, ...ring)
}
const challenge = (ctx: Uint8Array, tag: Uint8Array, l: Pt, r: Pt): bigint => hashScalar(`${DOM}/c`, ctx, tag, l.toBytes(), r.toBytes())

/** The scope's base point H: RFC 9380 hash-to-curve (cofactor cleared), so nobody knows log_G(H). */
const scopePoint = (scope: string): Pt => ed25519_hasher.hashToCurve(Buffer.from(scope, 'utf8'), { DST: `${DOM}/scope` })

/** Strict decode: on the curve, canonical, in the prime-order subgroup, not the identity. */
function decodePoint (raw: Uint8Array, what: string): Pt {
  let p: Pt
  try { p = Point.fromBytes(raw) } catch { throw new Error(`${what}: not a valid point`) }
  if (!eq(p.toBytes(), raw)) throw new Error(`${what}: non-canonical encoding`)
  if (p.is0() || !p.isTorsionFree()) throw new Error(`${what}: not in the prime-order subgroup`)
  return p
}

/** Short fingerprint of a canonical ring (SHA-256, hex). Two parties can compare it out of band to be sure they mean the same ring. */
export const ringId = (ring: Uint8Array[]): string => createHash('sha256').update(lp(`${DOM}/ring`, ...ring)).digest('hex').slice(0, 32)

export interface ScopeParams { scope: string, nonce: string, audience?: string }

function checkParams (p: ScopeParams): { scope: string, nonce: string, audience: string } {
  if (typeof p.scope !== 'string' || !TEXT_RE.test(p.scope)) throw new Error('scope required (1-200 printable ASCII characters, no spaces)')
  if (typeof p.nonce !== 'string' || !NONCE_RE.test(p.nonce)) throw new Error('nonce required (1-128 chars: letters, digits, . _ ~ + / = -)')
  if (p.audience !== undefined && (typeof p.audience !== 'string' || !TEXT_RE.test(p.audience))) throw new Error('invalid audience')
  return { scope: p.scope, nonce: p.nonce, audience: p.audience ?? '' }
}

/**
 * Ring members from DIDs (did:key) or Ed25519 peer IDs: de-duplicated and put in a canonical order, so the same set of
 * members gives the same ring however it was listed. did:frenet members need `resolveRing`.
 */
export function ringFromMembers (members: unknown): Uint8Array[] {
  if (!Array.isArray(members)) throw new Error('ring must be a list of DIDs or peer IDs')
  if (members.length > MAX_RING * 4) throw new Error(`ring too large (max ${MAX_RING})`)
  return canonicalRing(members.map((m) => rawKey(m)))
}

function rawKey (m: unknown): Uint8Array {
  if (typeof m !== 'string' || m === '') throw new Error('ring member must be a DID or peer ID')
  if (isFrenetDid(m)) throw new Error('did:frenet members need resolveRing')
  return parseDidKey(m.startsWith('did:') ? m : didFromPeerId(m)).raw
}

/** Resolves a did:frenet id to its *current* public key (null if unknown). */
export type FrenetKeyResolver = (id: string) => Promise<Uint8Array | null>

export async function resolveRing (members: unknown, resolveFrenet?: FrenetKeyResolver): Promise<Uint8Array[]> {
  if (!Array.isArray(members)) throw new Error('ring must be a list of DIDs or peer IDs')
  if (members.length > MAX_RING * 4) throw new Error(`ring too large (max ${MAX_RING})`)
  const raws: Uint8Array[] = []
  for (const m of members) {
    if (typeof m === 'string' && isFrenetDid(m)) {
      const raw = resolveFrenet ? await resolveFrenet(frenetId(m)) : null
      if (!raw) throw new Error(`cannot resolve ${m}`)
      raws.push(raw)
    } else raws.push(rawKey(m))
  }
  return canonicalRing(raws)
}

function canonicalRing (raws: Uint8Array[]): Uint8Array[] {
  const seen = new Set<string>()
  const ring: Uint8Array[] = []
  for (const r of raws) { const k = Buffer.from(r).toString('hex'); if (!seen.has(k)) { seen.add(k); ring.push(r) } }
  if (ring.length < MIN_RING) throw new Error(`ring needs at least ${MIN_RING} distinct members`)
  if (ring.length > MAX_RING) throw new Error(`ring too large (max ${MAX_RING})`)
  ring.sort(Buffer.compare)
  for (const r of ring) decodePoint(r, 'ring member')
  return ring
}

/** The member's one-per-scope tag (hex). Anyone holding the key can compute it, nobody else can. */
export function tagFor (key: PrivateKey, scope: string): string {
  if (typeof scope !== 'string' || !TEXT_RE.test(scope)) throw new Error('invalid scope')
  return Buffer.from(scopePoint(scope).multiply(secretScalar(key)).toBytes()).toString('hex')
}

function secretScalar (key: PrivateKey): bigint {
  if (key.type !== 'Ed25519' || key.raw.length !== 64) throw new Error('an Ed25519 key is required')
  const { scalar, pointBytes } = ed25519.utils.getExtendedPublicKey(key.raw.slice(0, 32))
  if (!eq(pointBytes, key.publicKey.raw)) throw new Error('key pair mismatch')
  return scalar
}

/**
 * Prove you hold one of the ring's keys. `ring` is canonical raw keys (`ringFromMembers`). The result is base64url and
 * reveals neither which member signed nor the signer's key; it does reveal the scope tag.
 */
export function proveMembership (key: PrivateKey, ring: Uint8Array[], params: ScopeParams): { proof: string, tag: string } {
  const { scope, nonce, audience } = checkParams(params)
  if (ring.length < MIN_RING || ring.length > MAX_RING) throw new Error(`ring needs ${MIN_RING}-${MAX_RING} members`)
  const pts = ring.map((r) => decodePoint(r, 'ring member'))
  const x = secretScalar(key)
  const mine = key.publicKey.raw
  const idx = ring.findIndex((r) => eq(r, mine))
  if (idx < 0) throw new Error('this identity is not in the ring')
  for (let i = 1; i < ring.length; i++) if (Buffer.compare(ring[i - 1]!, ring[i]!) >= 0) throw new Error('ring must be canonical (sorted, distinct)')

  const n = ring.length
  const H = scopePoint(scope)
  const I = H.multiply(x)
  const tag = I.toBytes()
  const ctx = context(ring, scope, nonce, audience)
  const s: bigint[] = new Array(n).fill(0n)
  const c: bigint[] = new Array(n).fill(0n)
  const alpha = randomScalar()
  c[(idx + 1) % n] = challenge(ctx, tag, G.multiply(alpha), H.multiply(alpha))
  for (let k = 1; k < n; k++) {
    const i = (idx + k) % n
    s[i] = randomScalar()
    // A zero challenge (probability 2^-252) would make `multiply` throw; the caller can just retry.
    c[(i + 1) % n] = challenge(ctx, tag, G.multiply(s[i]!).add(pts[i]!.multiplyUnsafe(c[i]!)), H.multiply(s[i]!).add(I.multiplyUnsafe(c[i]!)))
  }
  s[idx] = Fn.create(alpha - c[idx]! * x)
  const out = Buffer.concat([Buffer.of(VERSION), tag, bigToLe32(c[0]!), ...s.map(bigToLe32)])
  return { proof: out.toString('base64url'), tag: Buffer.from(tag).toString('hex') }
}

export type MembershipCheck = { valid: true, tag: string } | { valid: false, error: string }

/** Verify a membership proof against the verifier's own ring, scope, nonce and audience. Never throws. */
export function verifyMembership (proof: unknown, ring: Uint8Array[], params: ScopeParams): MembershipCheck {
  try {
    const { scope, nonce, audience } = checkParams(params)
    const n = ring.length
    if (n < MIN_RING || n > MAX_RING) throw new Error('bad ring size')
    for (let i = 1; i < n; i++) if (Buffer.compare(ring[i - 1]!, ring[i]!) >= 0) throw new Error('ring must be canonical')
    if (typeof proof !== 'string' || !/^[A-Za-z0-9_-]+$/.test(proof) || proof.length > 4 * (65 + 32 * MAX_RING)) throw new Error('malformed proof')
    const bytes = Buffer.from(proof, 'base64url')
    if (bytes.toString('base64url') !== proof) throw new Error('malformed proof')
    if (bytes.length !== 65 + 32 * n) throw new Error('proof does not match the ring size')
    if (bytes[0] !== VERSION) throw new Error('unsupported proof version')
    const tag = bytes.subarray(1, 33)
    const I = decodePoint(tag, 'tag')
    const scalars: bigint[] = []
    for (let o = 33; o < bytes.length; o += 32) {
      const v = leToBig(bytes.subarray(o, o + 32))
      if (v >= L) throw new Error('non-canonical scalar')
      scalars.push(v)
    }
    const c0 = scalars[0]!
    const pts = ring.map((r) => decodePoint(r, 'ring member'))
    const H = scopePoint(scope)
    const ctx = context(ring, scope, nonce, audience)
    let c = c0
    for (let i = 0; i < n; i++) {
      const s = scalars[i + 1]!
      c = challenge(ctx, tag, G.multiplyUnsafe(s).add(pts[i]!.multiplyUnsafe(c)), H.multiplyUnsafe(s).add(I.multiplyUnsafe(c)))
    }
    if (c !== c0) throw new Error('proof does not verify')
    return { valid: true, tag: Buffer.from(tag).toString('hex') }
  } catch (e) { return { valid: false, error: e instanceof Error ? e.message : 'invalid' } }
}

export interface PolicyParams {
  /** Refuse rings with fewer members than this (default DEFAULT_MIN_RING, lowest allowed 2). */
  minRing?: number
  /** Refuse unless the ring's fingerprint (`ringId`) is exactly this: defends against a ring padded or swapped behind your back. */
  ringId?: string
}
export function checkPolicy (ring: Uint8Array[], p: PolicyParams): void {
  const min = p.minRing ?? DEFAULT_MIN_RING
  if (!Number.isInteger(min) || min < MIN_RING || min > MAX_RING) throw new Error(`minRing must be ${MIN_RING}-${MAX_RING}`)
  if (ring.length < min) throw new Error(`ring has ${ring.length} members but at least ${min} are required: a small ring hides little (lower minRing only if you accept that)`)
  if (p.ringId !== undefined && p.ringId !== ringId(ring)) throw new Error('ring does not match the expected ringId')
}

export interface ZkAuthOptions { resolveFrenet?: FrenetKeyResolver }
export interface VerifyOptions extends ScopeParams, PolicyParams {
  /** Accept the nonce although this node did not issue it (the caller guarantees it is fresh and single-use). */
  externalNonce?: boolean
  /** Record the tag and refuse the same member in the same scope a second time. */
  once?: boolean
}

/**
 * Prover and verifier for this node. As a verifier it hands out single-use challenges (so a captured proof cannot be
 * replayed) and, with `once`, remembers per-scope tags in SQLite so each anonymous member can act once.
 */
export class ZkAuth {
  private challenges = new Map<string, number>()
  constructor (private store: Store, private key: PrivateKey, private opts: ZkAuthOptions = {}) {}

  /** A fresh, single-use, short-lived nonce for a prover to bind its proof to. */
  challenge (ttlMs = CHALLENGE_TTL_MS): { nonce: string, expires: number } {
    if (!Number.isFinite(ttlMs) || ttlMs < 1000 || ttlMs > 60 * 60 * 1000) throw new Error('challenge lifetime must be 1 s to 1 h')
    const now = Date.now()
    for (const [k, e] of this.challenges) if (e <= now) this.challenges.delete(k)
    if (this.challenges.size >= MAX_CHALLENGES) throw new Error('too many outstanding challenges')
    const nonce = randomBytes(18).toString('base64url')
    this.challenges.set(nonce, now + ttlMs)
    return { nonce, expires: now + ttlMs }
  }

  /** Size and fingerprint of a ring, and whether this identity is in it, without proving anything. */
  async describeRing (members: unknown): Promise<{ ringSize: number, ringId: string, includesMe: boolean, minRing: number }> {
    const ring = await resolveRing(members, this.opts.resolveFrenet)
    return { ringSize: ring.length, ringId: ringId(ring), includesMe: ring.some((r) => eq(r, this.key.publicKey.raw)), minRing: DEFAULT_MIN_RING }
  }

  async prove (members: unknown, params: ScopeParams & PolicyParams): Promise<{ proof: string, tag: string, ringSize: number, ringId: string }> {
    const ring = await resolveRing(members, this.opts.resolveFrenet)
    checkPolicy(ring, params)
    return { ...proveMembership(this.key, ring, params), ringSize: ring.length, ringId: ringId(ring) }
  }

  async verify (proof: unknown, members: unknown, opts: VerifyOptions): Promise<MembershipCheck & { ringSize?: number, ringId?: string }> {
    let ring: Uint8Array[]
    try { ring = await resolveRing(members, this.opts.resolveFrenet); checkPolicy(ring, opts) } catch (e) { return { valid: false, error: e instanceof Error ? e.message : 'invalid ring' } }
    const issued = this.challenges.get(String(opts.nonce))
    if (!opts.externalNonce && (issued === undefined || issued <= Date.now())) return { valid: false, error: 'unknown or expired challenge (request one with challenge())' }
    const r = verifyMembership(proof, ring, opts)
    if (!r.valid) return r
    // From here to the return there is no await, so the nonce and tag are claimed atomically.
    if (!opts.externalNonce) this.challenges.delete(opts.nonce)
    if (opts.once && !this.store.claimZkTag(opts.scope, r.tag)) return { valid: false, error: 'this member has already acted in this scope' }
    return { ...r, ringSize: ring.length, ringId: ringId(ring) }
  }
}

/** Key resolver for did:frenet members, from the node's key-log store (offline, current key only). */
export const frenetKeyResolver = (resolve: (id: string) => Promise<{ key: string } | null>): FrenetKeyResolver => async (id) => {
  const st = await resolve(id)
  return st ? base32.baseDecode(st.key) : null
}
