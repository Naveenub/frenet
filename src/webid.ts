import { lookup } from 'node:dns/promises'
import { request } from 'node:https'
import { BlockList, isIP } from 'node:net'
import { publicKeyFromRaw } from '@libp2p/crypto/keys'
import type { PrivateKey, PublicKey } from '@libp2p/interface'
import { base58btc } from 'multiformats/bases/base58'
import { base64url } from 'multiformats/bases/base64'
import { frenetId, isFrenetDid, parseDidKey } from './did.js'
import type { IdentityState } from './identity-log.js'
import { base32 } from 'multiformats/bases/base32'

/**
 * `did:web` (Ed25519 only) and domain-anchored handles (`alice@example.com`).
 *
 * did:web: `did:web:example.com` -> https://example.com/.well-known/did.json, `did:web:example.com:users:alice` ->
 * https://example.com/users/alice/did.json. The document must name itself (`id` === the DID) and list Ed25519 keys
 * (Multikey / Ed25519VerificationKey2020 multibase, or JsonWebKey2020 OKP). No ports, no IP literals, https only.
 *
 * Handles: `local@domain` is looked up in https://domain/.well-known/frenet-names.json
 *   { "v": 1, "names": { "alice": "did:key:z6Mk…" | { "did": "did:…", "proof": "<base64url sig>" } } }
 * The domain owner decides who owns `alice@domain` (uniqueness comes from DNS, like NIP-05/WebFinger). The optional
 * `proof` is the DID key's signature over `frenet-handle/v1\n<handle>\n<did>`: with it, the DID holder has consented
 * to that handle, so a domain cannot attach a name to a key that never agreed to it.
 *
 * Trust: both depend on DNS and the web PKI (TLS certificates). That is a deliberate trade for global, human-memorable
 * names; the self-certifying `<name>.<key>` names and did:key / did:frenet keep working with no such dependency.
 * Fetches refuse non-public addresses (SSRF), redirects, non-200 replies, and bodies over 64 KB, and time out at 5 s.
 */
export const MAX_DOC_BYTES = 64 * 1024
const FETCH_MS = 5000
const CACHE_MS = 5 * 60 * 1000
const MAX_METHODS = 16
const ED25519_PREFIX = [0xed, 0x01]
const HANDLE_DOMAIN = 'frenet-handle/v1'
const LABEL = '(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)'
const DOMAIN_RE = new RegExp(`^(?:${LABEL}\\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])$`)
export const HANDLE_RE = new RegExp(`^([a-z0-9][a-z0-9._-]{0,63})@((?:${LABEL}\\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9]))$`)
const SEG_RE = /^[A-Za-z0-9._-]{1,64}$/

export type JsonFetcher = (url: URL) => Promise<unknown>

const blocked = new BlockList()
for (const [a, p] of [['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16], ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15], ['198.51.100.0', 24], ['203.0.113.0', 24], ['224.0.0.0', 4], ['240.0.0.0', 4]] as const) blocked.addSubnet(a, p, 'ipv4')
for (const [a, p] of [['::', 128], ['::1', 128], ['fc00::', 7], ['fe80::', 10], ['ff00::', 8], ['2001:db8::', 32], ['64:ff9b::', 96]] as const) blocked.addSubnet(a, p, 'ipv6')

/** True for loopback, private, link-local, multicast, documentation and other non-public addresses. */
export function isNonPublicAddress (addr: string): boolean {
  const v = isIP(addr)
  if (v === 0) return true
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(addr)
  if (mapped) return blocked.check(mapped[1]!, 'ipv4')
  if (/^::ffff:/i.test(addr)) return true
  return blocked.check(addr, v === 4 ? 'ipv4' : 'ipv6')
}

export const validDomain = (d: unknown): d is string => typeof d === 'string' && d.length <= 253 && DOMAIN_RE.test(d) && isIP(d) === 0

/** Default fetcher: resolve, refuse non-public addresses, connect to the vetted IP with the hostname as TLS name. */
export const httpsJson: JsonFetcher = async (url) => {
  if (url.protocol !== 'https:' || url.username || url.password || url.port !== '' || !validDomain(url.hostname)) throw new Error('refused: not a plain https URL')
  const addrs = await lookup(url.hostname, { all: true })
  if (addrs.length === 0 || addrs.some((a) => isNonPublicAddress(a.address))) throw new Error('refused: host resolves to a non-public address')
  const ip = addrs[0]!.address
  return await new Promise<unknown>((resolve, reject) => {
    const req = request({ host: ip, servername: url.hostname, port: 443, path: url.pathname, method: 'GET', headers: { host: url.hostname, accept: 'application/json' }, timeout: FETCH_MS }, (res) => {
      if (res.statusCode !== 200) { res.resume(); reject(new Error(`unexpected HTTP status ${res.statusCode}`)); return }
      const chunks: Buffer[] = []
      let n = 0
      res.on('data', (c: Buffer) => { n += c.length; if (n > MAX_DOC_BYTES) { req.destroy(new Error('response too large')); return }; chunks.push(c) })
      res.on('end', () => { try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))) } catch { reject(new Error('response is not JSON')) } })
      res.on('error', reject)
    })
    req.on('timeout', () => req.destroy(new Error('timeout')))
    req.on('error', reject)
    req.end()
  })
}

// ---------------------------------------------------------------------------------------------------------------
const WEB_DID_RE = /^did:web:([a-z0-9.-]+)((?::[A-Za-z0-9._-]{1,64}){0,8})$/

export const isWebDid = (s: unknown): boolean => {
  if (typeof s !== 'string' || s.length > 400) return false
  const m = WEB_DID_RE.exec(s)
  return !!m && validDomain(m[1]) && m[2]!.split(':').slice(1).every((x) => SEG_RE.test(x) && x !== '.' && x !== '..')
}

export function webDidUrl (did: string): URL {
  if (!isWebDid(did)) throw new Error('invalid did:web (lowercase domain, no port, no IP address)')
  const [, host, rest] = WEB_DID_RE.exec(did)!
  const segs = rest!.split(':').slice(1)
  return new URL(`https://${host}/${segs.length ? `${segs.join('/')}/did.json` : '.well-known/did.json'}`)
}

export interface WebKey { kid: string, publicKey: PublicKey, authentication: boolean, assertion: boolean }
export interface WebDidResolution { did: string, document: Record<string, unknown>, keys: WebKey[] }

function ed25519FromMultibase (mb: unknown): PublicKey | null {
  if (typeof mb !== 'string' || !mb.startsWith('z')) return null
  try {
    const b = base58btc.decode(mb)
    if (b.length !== 34 || b[0] !== ED25519_PREFIX[0] || b[1] !== ED25519_PREFIX[1]) return null
    return publicKeyFromRaw(b.slice(2))
  } catch { return null }
}

function ed25519FromJwk (j: any): PublicKey | null {
  try {
    if (j?.kty !== 'OKP' || j.crv !== 'Ed25519' || typeof j.x !== 'string') return null
    const raw = base64url.baseDecode(j.x)
    return raw.length === 32 && base64url.baseEncode(raw) === j.x ? publicKeyFromRaw(raw) : null
  } catch { return null }
}

/** Validate a fetched did:web document. Pure; throws unless it names itself and lists at least one usable Ed25519 key. */
export function parseWebDidDocument (did: string, x: unknown): WebDidResolution {
  const d = x as any
  if (typeof d !== 'object' || d === null || Array.isArray(d) || d.id !== did) throw new Error('DID document does not name this DID')
  if (!Array.isArray(d.verificationMethod) || d.verificationMethod.length === 0 || d.verificationMethod.length > MAX_METHODS) throw new Error('DID document has no usable verification methods')
  const abs = (id: unknown): string | null => typeof id === 'string' ? (id.startsWith('#') ? `${did}${id}` : id) : null
  const rel = (name: string): Set<string> => new Set((Array.isArray(d[name]) ? d[name] : []).map((e: unknown) => abs(typeof e === 'string' ? e : (e as any)?.id)).filter((e: string | null): e is string => e !== null))
  const auth = rel('authentication')
  const assertion = rel('assertionMethod')
  const keys: WebKey[] = []
  for (const m of d.verificationMethod) {
    const kid = abs(m?.id)
    if (!kid || !kid.startsWith(`${did}#`) || kid.length > 300 || keys.some((k) => k.kid === kid)) continue
    if (m.controller !== undefined && m.controller !== did) continue
    const pk = (m.type === 'Multikey' || m.type === 'Ed25519VerificationKey2020') ? ed25519FromMultibase(m.publicKeyMultibase)
      : m.type === 'JsonWebKey2020' ? ed25519FromJwk(m.publicKeyJwk) : null
    if (pk) keys.push({ kid, publicKey: pk, authentication: auth.has(kid), assertion: assertion.has(kid) })
  }
  if (keys.length === 0) throw new Error('DID document lists no Ed25519 key')
  return { did, document: d, keys }
}

/** The signing key for `kid`, which must be one of the document's keys and be allowed to authenticate or assert. */
export function webKeyForKid (r: WebDidResolution, kid: unknown): PublicKey {
  const k = typeof kid === 'string' ? r.keys.find((x) => x.kid === kid) : undefined
  if (!k) throw new Error('kid is not a key of this did:web')
  if (!k.authentication && !k.assertion) throw new Error('key is not authorised for authentication or assertion')
  return k.publicKey
}

export class WebDids {
  private cache = new Map<string, { r: WebDidResolution, at: number }>()
  constructor (private fetchJson: JsonFetcher = httpsJson) {}

  async resolve (did: string, opts: { fresh?: boolean } = {}): Promise<WebDidResolution> {
    const url = webDidUrl(did)
    const hit = this.cache.get(did)
    if (hit && !opts.fresh && Date.now() - hit.at < CACHE_MS) return hit.r
    const r = parseWebDidDocument(did, await this.fetchJson(url))
    if (this.cache.size > 256) this.cache.clear()
    this.cache.set(did, { r, at: Date.now() })
    return r
  }
}

// ---------------------------------------------------------------------------------------------------------------
export interface HandleResolution { handle: string, did: string, domain: string, proof: 'verified' | 'none', pin: 'new' | 'match' | 'repinned' | 'off' }

/** The domain now answers with a different DID than the one this node pinned for the handle. */
export class HandleChanged extends Error {
  constructor (readonly handle: string, readonly pinned: string, readonly now: string) { super(`handle ${handle} now points at a different DID than the one pinned (${pinned} -> ${now}); verify out of band, then resolve again with repin`); this.name = 'HandleChanged' }
}

/** Local trust-on-first-use memory: the first DID a handle resolved to. */
export interface HandlePins { get: (handle: string) => string | null, set: (handle: string, did: string) => void }

export const validHandle = (h: unknown): h is string => typeof h === 'string' && h.length <= 253 && HANDLE_RE.test(h)
export const normalizeHandle = (h: string): string => h.trim().replace(/^@/, '').toLowerCase()

const proofBytes = (handle: string, did: string): Buffer => Buffer.from(`${HANDLE_DOMAIN}\n${handle}\n${did}`, 'utf8')

/** Consent proof for `handle` -> `did`, to be placed next to the entry in the domain's frenet-names.json. */
export async function signHandleProof (key: PrivateKey, handle: string, did: string): Promise<string> {
  if (!validHandle(handle)) throw new Error('invalid handle (local@domain, lowercase)')
  return Buffer.from(await key.sign(proofBytes(handle, did))).toString('base64url')
}

export class Handles {
  private cache = new Map<string, { r: HandleResolution, at: number }>()
  constructor (
    private web: WebDids,
    private opts: { fetchJson?: JsonFetcher, keyForDid?: (did: string) => Promise<PublicKey | null>, pins?: HandlePins, resolveLog?: (id: string) => Promise<IdentityState | null> } = {}
  ) {}

  /**
   * A did:frenet proof is bound to the key epoch (`kseq`) that signed it and is valid only while that epoch is the
   * identity's *current* key: after a rotation the old proof dies and the holder re-signs, so a stolen old key
   * cannot keep vouching for a handle.
   */
  private async frenetProofKey (did: string, kseq: unknown): Promise<PublicKey> {
    if (!this.opts.resolveLog) throw new Error('cannot check a did:frenet proof here (no key log resolver)')
    if (!Number.isSafeInteger(kseq) || (kseq as number) < 0) throw new Error('did:frenet proof needs the key epoch (kseq)')
    const st = await this.opts.resolveLog(frenetId(did))
    if (!st) throw new Error('unknown did:frenet identity (no key log available)')
    if (kseq !== st.seq) throw new Error('proof was made by a superseded key (or one not yet seen); the holder must sign it again')
    return publicKeyFromRaw(base32.baseDecode(st.events[st.seq]!.key))
  }

  private async proofKey (did: string): Promise<PublicKey | null> {
    if (this.opts.keyForDid) { const k = await this.opts.keyForDid(did); if (k) return k }
    if (isWebDid(did)) { const r = await this.web.resolve(did); return (r.keys.find((k) => k.authentication) ?? r.keys[0])!.publicKey }
    return null
  }

  /**
   * `alice@example.com` -> DID. With `requireProof` the entry must carry a valid consent proof; a proof that is present
   * but wrong is always an error, so a domain cannot mislabel someone's key.
   */
  async resolve (input: string, opts: { requireProof?: boolean, fresh?: boolean, repin?: boolean } = {}): Promise<HandleResolution> {
    const handle = normalizeHandle(String(input))
    const m = HANDLE_RE.exec(handle)
    if (!m) throw new Error('invalid handle (local@domain, lowercase letters/digits/._-)')
    const [, local, domain] = m as unknown as [string, string, string]
    const hit = this.cache.get(handle)
    if (hit && !opts.fresh && !opts.repin && Date.now() - hit.at < CACHE_MS && (!opts.requireProof || hit.r.proof === 'verified')) return hit.r
    const url = new URL(`https://${domain}/.well-known/frenet-names.json`)
    const doc = await (this.opts.fetchJson ?? httpsJson)(url) as any
    if (typeof doc !== 'object' || doc === null || doc.v !== 1 || typeof doc.names !== 'object' || doc.names === null || Array.isArray(doc.names)) throw new Error('domain has no valid frenet-names.json')
    if (!Object.hasOwn(doc.names, local)) throw new Error('handle not found at that domain')
    const e = doc.names[local]
    const did: unknown = typeof e === 'string' ? e : e?.did
    const proof: unknown = typeof e === 'object' && e !== null ? e.proof : undefined
    if (typeof did !== 'string' || !(did.startsWith('did:key:') || did.startsWith('did:frenet:') || isWebDid(did))) throw new Error('handle points at an unsupported DID')
    let status: 'verified' | 'none' = 'none'
    if (proof !== undefined) {
      if (typeof proof !== 'string' || !/^[A-Za-z0-9_-]{86}$/.test(proof)) throw new Error('malformed handle proof')
      const key = did.startsWith('did:key:') ? parseDidKey(did).publicKey : isFrenetDid(did) ? await this.frenetProofKey(did, typeof e === 'object' ? e.kseq : undefined) : await this.proofKey(did)
      if (!key) throw new Error('cannot check the proof for this DID here (no key available)')
      if (!(await key.verify(proofBytes(handle, did), Buffer.from(proof, 'base64url')))) throw new Error('handle proof does not match the DID')
      status = 'verified'
    }
    if (opts.requireProof && status !== 'verified') throw new Error('handle entry carries no consent proof')
    // Trust on first use: a domain can re-point a handle at any time, so remember the first DID and refuse silent changes.
    let pin: HandleResolution['pin'] = 'off'
    const pins = this.opts.pins
    if (pins) {
      const known = pins.get(handle)
      if (known === null) { pins.set(handle, did); pin = 'new' }
      else if (known === did) pin = 'match'
      else if (opts.repin) { pins.set(handle, did); pin = 'repinned' }
      else throw new HandleChanged(handle, known, did)
    }
    const r: HandleResolution = { handle, did, domain, proof: status, pin }
    if (this.cache.size > 256) this.cache.clear()
    this.cache.set(handle, { r, at: Date.now() })
    return r
  }
}
