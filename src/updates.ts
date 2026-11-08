import { createHash, timingSafeEqual } from 'node:crypto'
import { generateKeyPair } from '@libp2p/crypto/keys'
import type { PrivateKey } from '@libp2p/interface'
import { didFromPublicKeyRaw, parseDidKey } from './did.js'
import type { Store } from './store.js'

/**
 * Secure software updates (a small TUF-style design, verification side).
 *
 * A release is described by a *manifest* (version, artifact names / sizes / SHA-256, sequence number, expiry)
 * that is signed by release keys. A client holds *trust roots*: a set of release did:key identifiers and a
 * threshold t. An update is accepted only if
 *   - at least t distinct trusted keys signed the exact payload bytes (verified before the payload is parsed),
 *   - the manifest is for this product and channel, has not expired (freeze-attack window <= 90 days),
 *   - its sequence number is not lower than the highest one this node has accepted, and its version is not
 *     lower than the running version (rollback / downgrade protection),
 *   - every artifact byte stream matches the signed size and SHA-256.
 * Nothing in this file downloads or installs anything (that is `installer.ts`, operator-initiated only): it decides whether bytes that arrived by any channel
 * (HTTPS, a FRENET content block, a USB stick) are the release the maintainers signed. With no trust roots
 * configured it refuses everything (fail closed).
 *
 * Not covered: key rotation of the roots themselves (roots are pinned out of band), compromise of >= t release
 * keys, and build reproducibility. See docs/ARCHITECTURE.md.
 */

export const UPDATE_PRODUCT = 'frenet'
export const MAX_ENVELOPE_BYTES = 64 * 1024
export const MAX_SIGNATURES = 32
export const MAX_ARTIFACTS = 64
export const MAX_ARTIFACT_BYTES = 2 * 1024 ** 3
export const MAX_VALIDITY_MS = 90 * 86_400_000
const SKEW_MS = 5 * 60_000
const DOMAIN = 'frenet-update/v1\n'
const NAME_RE = /^[A-Za-z0-9_][A-Za-z0-9._-]{0,99}$/
const SEMVER_RE = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/
const CHANNEL_RE = /^[a-z0-9-]{1,32}$/

export interface UpdateArtifact { name: string, size: number, sha256: string }
export interface UpdateManifest {
  v: 1
  product: typeof UPDATE_PRODUCT
  channel: string
  version: string
  /** Strictly increasing per channel across releases. */
  seq: number
  created: number
  expires: number
  artifacts: UpdateArtifact[]
  notes?: string
}
export interface UpdateEnvelope { payload: string, signatures: Array<{ keyid: string, sig: string }> }
export interface TrustRoots { threshold: number, keys: string[] }

export type UpdateCheck =
  | { ok: true, manifest: UpdateManifest, signers: string[] }
  | { ok: false, error: string }

const b64u = (b: Uint8Array): string => Buffer.from(b).toString('base64url')
const fromB64u = (s: string): Buffer | null => {
  if (!/^[A-Za-z0-9_-]*$/.test(s)) return null
  const b = Buffer.from(s, 'base64url')
  return b.toString('base64url') === s ? b : null   // canonical only
}
const signedBytes = (payload: string): Uint8Array => Buffer.from(DOMAIN + payload, 'utf8')

export function compareSemver (a: string, b: string): number {
  const pa = SEMVER_RE.exec(a); const pb = SEMVER_RE.exec(b)
  if (!pa || !pb) throw new Error('invalid version')
  for (let i = 1; i <= 3; i++) { const d = Number(pa[i]) - Number(pb[i]); if (d !== 0) return d < 0 ? -1 : 1 }
  return 0
}

export function validateRoots (x: unknown): TrustRoots {
  const r = x as TrustRoots
  if (!r || !Array.isArray(r.keys) || !Number.isInteger(r.threshold)) throw new Error('trust roots must be {threshold, keys[]}')
  if (r.keys.length === 0 || r.keys.length > 32) throw new Error('trust roots need 1..32 keys')
  const keys = r.keys.map((k) => parseDidKey(k).did)
  if (new Set(keys).size !== keys.length) throw new Error('duplicate key in trust roots')
  if (r.threshold < 1 || r.threshold > keys.length) throw new Error(`threshold must be 1..${keys.length}`)
  return { threshold: r.threshold, keys }
}

function parseManifest (text: string, now: number): UpdateManifest | string {
  let o: any
  try { o = JSON.parse(text) } catch { return 'manifest is not JSON' }
  if (!o || typeof o !== 'object' || Array.isArray(o)) return 'manifest must be an object'
  if (o.v !== 1) return 'unsupported manifest version'
  if (o.product !== UPDATE_PRODUCT) return 'manifest is for another product'
  if (typeof o.channel !== 'string' || !CHANNEL_RE.test(o.channel)) return 'bad channel'
  if (typeof o.version !== 'string' || !SEMVER_RE.test(o.version)) return 'bad version (use MAJOR.MINOR.PATCH)'
  if (!Number.isSafeInteger(o.seq) || o.seq < 1) return 'bad seq'
  if (!Number.isSafeInteger(o.created) || !Number.isSafeInteger(o.expires)) return 'bad timestamps'
  if (o.created > now + SKEW_MS) return 'manifest is dated in the future'
  if (o.expires <= o.created || o.expires - o.created > MAX_VALIDITY_MS) return 'bad validity window (max 90 days)'
  if (!Array.isArray(o.artifacts) || o.artifacts.length < 1 || o.artifacts.length > MAX_ARTIFACTS) return `artifacts must be 1..${MAX_ARTIFACTS} entries`
  const names = new Set<string>()
  const artifacts: UpdateArtifact[] = []
  for (const a of o.artifacts) {
    if (!a || typeof a.name !== 'string' || !NAME_RE.test(a.name) || names.has(a.name)) return 'bad or duplicate artifact name'
    if (!Number.isSafeInteger(a.size) || a.size < 1 || a.size > MAX_ARTIFACT_BYTES) return 'bad artifact size'
    if (typeof a.sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(a.sha256)) return 'bad artifact sha256 (64 lowercase hex)'
    names.add(a.name); artifacts.push({ name: a.name, size: a.size, sha256: a.sha256 })
  }
  if (o.notes !== undefined && (typeof o.notes !== 'string' || o.notes.length > 2000)) return 'bad notes'
  return { v: 1, product: UPDATE_PRODUCT, channel: o.channel, version: o.version, seq: o.seq, created: o.created, expires: o.expires, artifacts, ...(o.notes !== undefined ? { notes: o.notes } : {}) }
}

export interface VerifyOptions {
  roots: TrustRoots
  channel?: string
  /** The running version: a manifest for a lower version is refused (no downgrade). */
  currentVersion: string
  /** Highest seq already accepted on this channel (from the store), if any. */
  lastSeq?: number
  lastVersion?: string
  now?: number
}

/** Verify an envelope against trust roots and freshness rules. Signatures are checked before the payload is parsed. */
export async function verifyEnvelope (envelope: unknown, o: VerifyOptions): Promise<UpdateCheck> {
  const now = o.now ?? Date.now()
  const fail = (error: string): UpdateCheck => ({ ok: false, error })
  let roots: TrustRoots
  try { roots = validateRoots(o.roots) } catch (e) { return fail(`no usable trust roots: ${(e as Error).message}`) }
  const env = envelope as UpdateEnvelope
  if (!env || typeof env.payload !== 'string' || !Array.isArray(env.signatures)) return fail('malformed envelope')
  if (env.payload.length > MAX_ENVELOPE_BYTES || env.signatures.length > MAX_SIGNATURES) return fail('envelope too large')
  const payloadBytes = fromB64u(env.payload)
  if (!payloadBytes) return fail('payload is not canonical base64url')

  const signers = new Set<string>()
  const bytes = signedBytes(env.payload)
  for (const s of env.signatures) {
    if (!s || typeof s.keyid !== 'string' || typeof s.sig !== 'string' || !roots.keys.includes(s.keyid) || signers.has(s.keyid)) continue   // unknown or repeated key: ignored
    const sig = fromB64u(s.sig)
    if (!sig || sig.length !== 64) continue
    try { if (await parseDidKey(s.keyid).publicKey.verify(bytes, sig)) signers.add(s.keyid) } catch { /* invalid signature */ }
  }
  if (signers.size < roots.threshold) return fail(`only ${signers.size} of the required ${roots.threshold} trusted signatures verified`)

  const m = parseManifest(payloadBytes.toString('utf8'), now)
  if (typeof m === 'string') return fail(m)
  if (o.channel && m.channel !== o.channel) return fail(`manifest is for channel "${m.channel}", not "${o.channel}"`)
  if (m.expires <= now) return fail('manifest has expired (possible freeze attack or stale mirror)')
  if (o.lastSeq !== undefined) {
    if (m.seq < o.lastSeq) return fail(`rollback: manifest seq ${m.seq} is older than the accepted seq ${o.lastSeq}`)
    if (m.seq === o.lastSeq && o.lastVersion !== undefined && m.version !== o.lastVersion) return fail('conflicting manifest: same seq, different version')
  }
  if (compareSemver(m.version, o.currentVersion) < 0) return fail(`downgrade: ${m.version} is older than the running ${o.currentVersion}`)
  return { ok: true, manifest: m, signers: [...signers] }
}

/** Check artifact bytes against the signed manifest (name, size, SHA-256). */
export function verifyArtifact (m: UpdateManifest, name: string, bytes: Uint8Array): { ok: true } | { ok: false, error: string } {
  const a = m.artifacts.find((x) => x.name === name)
  if (!a) return { ok: false, error: `"${name}" is not listed in the signed manifest` }
  if (bytes.byteLength !== a.size) return { ok: false, error: `size ${bytes.byteLength} does not match signed size ${a.size}` }
  const got = createHash('sha256').update(bytes).digest()
  return timingSafeEqual(got, Buffer.from(a.sha256, 'hex')) ? { ok: true } : { ok: false, error: 'SHA-256 does not match the signed manifest' }
}

export function sha256Hex (bytes: Uint8Array): string { return createHash('sha256').update(bytes).digest('hex') }

// --- publisher side -------------------------------------------------------------------------------------------

export async function generateReleaseKey (): Promise<{ key: PrivateKey, did: string }> {
  const key = await generateKeyPair('Ed25519')
  return { key, did: didFromPublicKeyRaw(key.publicKey.raw) }
}

/** Add (or replace) this key's signature on a manifest or an existing envelope. Use offline, with the key on an air-gapped machine or HSM. */
export async function signManifest (input: UpdateManifest | UpdateEnvelope, key: PrivateKey): Promise<UpdateEnvelope> {
  const env: UpdateEnvelope = 'payload' in input ? { payload: input.payload, signatures: [...input.signatures] } : { payload: b64u(Buffer.from(JSON.stringify(input), 'utf8')), signatures: [] }
  const keyid = didFromPublicKeyRaw(key.publicKey.raw)
  const sig = b64u(await key.sign(signedBytes(env.payload)))
  env.signatures = [...env.signatures.filter((s) => s.keyid !== keyid), { keyid, sig }]
  return env
}

// --- node side ------------------------------------------------------------------------------------------------

/** Stateful wrapper: remembers the highest accepted seq per channel so an old (but validly signed) release cannot be replayed. */
export class Updates {
  constructor (private store: Store, private roots: TrustRoots | null, private currentVersion: string) {}

  get configured (): boolean { return this.roots !== null }

  async check (envelope: unknown, channel = 'stable', now = Date.now()): Promise<UpdateCheck> {
    if (!this.roots) return { ok: false, error: 'no update trust roots are configured; refusing all updates' }
    const last = this.store.getUpdateState(channel)
    return verifyEnvelope(envelope, { roots: this.roots, channel, currentVersion: this.currentVersion, ...(last ? { lastSeq: last.seq, lastVersion: last.version } : {}), now })
  }

  /** Record a manifest as accepted (call only after its artifacts verified and the update was applied or staged). */
  accept (m: UpdateManifest): void { this.store.putUpdateState(m.channel, m.seq, m.version) }
}
