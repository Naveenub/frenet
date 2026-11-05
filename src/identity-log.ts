import { createHash } from 'node:crypto'
import { publicKeyFromRaw } from '@libp2p/crypto/keys'
import type { Libp2p, PrivateKey, PublicKey } from '@libp2p/interface'
import { peerIdFromPublicKey } from '@libp2p/peer-id'
import { base32 } from 'multiformats/bases/base32'
import { cidFor } from './blocks.js'
import { didFromPublicKeyRaw, frenetDid, validB32 } from './did.js'
import { RateLimiter } from './messaging.js'
import { ask, readJson } from './rpc.js'
import type { Store } from './store.js'

/**
 * Rotatable identity: `did:frenet:<id>`, backed by a hash-chained key event log with *pre-rotation* (the KERI idea).
 *
 *   icp  seq 0   key = K0   next = H(K1)          signed by K0           id = digest(icp)
 *   rot  seq 1   key = K1   next = H(K2)          signed by K1, and H(K1) must equal the previous `next`
 *   rot  seq 2   key = K2   next = H(K3)          ...
 *
 * Every event commits to the *hash* of the key that may take over next, and K(n+1) is kept offline (an encrypted
 * file, never on the node). Consequences:
 *  - Someone who steals only the current key cannot rotate, truncate or fork the log: they would need the next key,
 *    whose public half is not even revealed until the rotation happens.
 *  - If the current key is lost or stolen, the holder of the next key rotates and the DID stays the same. Peers that
 *    follow the log see the new key; the thief's key stops being the identity's current key.
 *  - The log is public and self-certifying: anyone can verify it from the events alone, with no registry.
 *
 * What a rotation changes: the node's libp2p key (so the peer ID) and everything addressed by key, e.g. `<name>.<pub>`
 * site names, which must be republished. The DID and the credentials issued under it carry over.
 *
 * Limits: a signature made with a superseded key is accepted only if its `iat` is earlier than the rotation event's
 * timestamp. Both are signer-claimed, so someone holding the old key can backdate; `strict` verification refuses
 * superseded keys outright. If the current key AND the next key are both stolen there is no recovery.
 */
export const DID_PROTOCOL = '/frenet/did/1.0.0'
const DOMAIN = 'frenet-identity/v1'
const SIG_RE = /^[A-Za-z0-9+/]{86}==$/
const MAX_EVENTS = 64
const MAX_SKEW_MS = 5 * 60 * 1000
const MAX_REQUEST_BYTES = 256
const MAX_RESPONSE_BYTES = 64 * 1024
const PROVIDERS_PER_LOOKUP = 8
const REANNOUNCE_MS = 6 * 60 * 60 * 1000
const NETWORK_CACHE_MS = 15_000

export interface IdentityEvent { v: 1, t: 'icp' | 'rot', seq: number, prev: string | null, key: string, next: string, ts: number, sig: string }
export interface IdentityState { id: string, did: string, events: IdentityEvent[], seq: number, key: string, next: string, ts: number }

const b32 = (raw: Uint8Array): string => base32.baseEncode(raw)
const sha256 = (data: Uint8Array | string): Buffer => createHash('sha256').update(data).digest()

/** Commitment to a key: base32 of sha256(raw public key). */
export const keyDigest = (raw: Uint8Array): string => b32(sha256(raw))

function signedBytes (e: Omit<IdentityEvent, 'sig'>): Buffer {
  return Buffer.from(`${DOMAIN}\n${e.t}\n${e.seq}\n${e.prev ?? ''}\n${e.key}\n${e.next}\n${e.ts}`, 'utf8')
}

/** Digest of a whole signed event: this is what the next event's `prev` points at, and what the DID id is for `icp`. */
export const eventDigest = (e: IdentityEvent): string => b32(sha256(`${signedBytes(e).toString('utf8')}\n${e.sig}`))

/**
 * Verify a complete log from nothing but its events. Checks structure, the hash chain, every signature, that each
 * rotation was made by the key committed to in the previous event, and monotonic timestamps. Throws on anything off.
 */
export async function verifyLog (x: unknown, now = Date.now()): Promise<IdentityState> {
  if (!Array.isArray(x) || x.length === 0 || x.length > MAX_EVENTS) throw new Error('invalid identity log')
  const events: IdentityEvent[] = []
  for (let i = 0; i < x.length; i++) {
    const r = x[i] as any
    if (typeof r !== 'object' || r === null || r.v !== 1 || r.t !== (i === 0 ? 'icp' : 'rot') || r.seq !== i) throw new Error(`invalid event ${i}`)
    if (!validB32(r.key) || !validB32(r.next) || typeof r.sig !== 'string' || !SIG_RE.test(r.sig)) throw new Error(`invalid event ${i}`)
    if (!Number.isSafeInteger(r.ts) || r.ts <= 0 || r.ts > now + MAX_SKEW_MS) throw new Error(`invalid timestamp in event ${i}`)
    const prev = i === 0 ? null : events[i - 1]!
    if (r.prev !== (prev ? eventDigest(prev) : null)) throw new Error(`broken chain at event ${i}`)
    if (prev && r.ts < prev.ts) throw new Error(`timestamp goes backwards at event ${i}`)
    const e: IdentityEvent = { v: 1, t: r.t, seq: i, prev: r.prev, key: r.key, next: r.next, ts: r.ts, sig: r.sig }
    const raw = base32.baseDecode(e.key)
    if (e.next === keyDigest(raw)) throw new Error(`event ${i} commits to its own key`)
    if (prev && keyDigest(raw) !== prev.next) throw new Error(`event ${i} was not made by the pre-committed key`)
    if (!(await publicKeyFromRaw(raw).verify(signedBytes(e), Buffer.from(e.sig, 'base64')))) throw new Error(`bad signature on event ${i}`)
    events.push(e)
  }
  const last = events[events.length - 1]!
  const id = eventDigest(events[0]!)
  return { id, did: frenetDid(id), events, seq: last.seq, key: last.key, next: last.next, ts: last.ts }
}

async function sign (key: PrivateKey, e: Omit<IdentityEvent, 'sig'>): Promise<IdentityEvent> {
  return { ...e, sig: Buffer.from(await key.sign(signedBytes(e))).toString('base64') }
}

/** First event: `key` becomes the current key; `nextPublic` (kept offline) is committed to by hash. */
export async function createInception (key: PrivateKey, nextPublic: PublicKey, ts = Date.now()): Promise<IdentityState> {
  const e = await sign(key, { v: 1, t: 'icp', seq: 0, prev: null, key: b32(key.publicKey.raw), next: keyDigest(nextPublic.raw), ts })
  return verifyLog([e])
}

/** Rotate: `newKey` must be the key the previous event committed to. Returns the extended, verified state. */
export async function createRotation (state: IdentityState, newKey: PrivateKey, nextPublic: PublicKey, ts = Date.now()): Promise<IdentityState> {
  if (keyDigest(newKey.publicKey.raw) !== state.next) throw new Error('this is not the pre-committed next key for this identity')
  if (state.events.length >= MAX_EVENTS) throw new Error('identity log is full')
  const last = state.events[state.events.length - 1]!
  const e = await sign(newKey, { v: 1, t: 'rot', seq: state.seq + 1, prev: eventDigest(last), key: b32(newKey.publicKey.raw), next: keyDigest(nextPublic.raw), ts: Math.max(ts, last.ts) })
  return verifyLog([...state.events, e])
}

/**
 * The public key that may have signed something at `iatMs` under key epoch `seq` (the `#seq` in the kid).
 * A superseded epoch is accepted only for signatures dated before the rotation (and never when `strict`).
 */
export function keyForSignature (state: IdentityState, seq: unknown, iatMs: number, strict = false): PublicKey {
  if (!Number.isInteger(seq) || (seq as number) < 0 || (seq as number) > state.seq) throw new Error('unknown key for this identity')
  const s = seq as number
  const sup = state.events[s + 1]
  if (sup) {
    if (strict) throw new Error('signed with a key that has been rotated')
    if (iatMs >= sup.ts) throw new Error('signed with a key that had already been rotated')
  }
  return publicKeyFromRaw(base32.baseDecode(state.events[s]!.key))
}

/** True if `longer` is `shorter` plus more events (same history). */
export const extendsLog = (shorter: IdentityEvent[], longer: IdentityEvent[]): boolean =>
  longer.length >= shorter.length && shorter.every((e, i) => eventDigest(e) === eventDigest(longer[i]!))

export function didDocumentFor (state: IdentityState): object {
  const raw = base32.baseDecode(state.key)
  const vm = `${state.did}#${state.seq}`
  return {
    '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/multikey/v1'],
    id: state.did,
    verificationMethod: [{ id: vm, type: 'Multikey', controller: state.did, publicKeyMultibase: didFromPublicKeyRaw(raw).slice('did:key:'.length) }],
    authentication: [vm],
    assertionMethod: [vm],
    capabilityInvocation: [vm],
    capabilityDelegation: [vm],
    alsoKnownAs: [`frenet-peer://${peerIdFromPublicKey(publicKeyFromRaw(raw)).toString()}`],
    rotation: { seq: state.seq, events: state.events.length, nextKeyDigest: state.next, updated: state.ts }
  }
}

const idCid = (id: string) => cidFor(Buffer.from(`frenet-did/v1\n${id}`))

/**
 * Distribution of identity logs, modelled on names: holders announce a provider record under `frenet-did/v1\n<id>` and
 * serve the (public, self-certifying) log over `/frenet/did/1.0.0`. Whatever is fetched is fully verified, and a log only
 * ever replaces a stored one if it extends the same history, so a forged or diverging log cannot displace what we know.
 */
export class IdentityLogs {
  private limiter = new RateLimiter(30, 5)
  private checked = new Map<string, number>()
  private mem = new Map<string, IdentityState>()
  private timer: NodeJS.Timeout | null = null
  private first: NodeJS.Timeout | null = null
  private closed = false

  constructor (private node: Libp2p, private store: Store) {}

  async start (): Promise<void> {
    await this.node.handle(DID_PROTOCOL, async (stream, connection) => {
      try {
        if (!this.limiter.allow(connection.remotePeer.toString())) { stream.abort(new Error('rate limited')); return }
        const req = await readJson(stream as any, MAX_REQUEST_BYTES)
        if (!validB32(req?.id)) { stream.abort(new Error('bad request')); return }
        const row = this.store.getIdentityLog(req.id)
        stream.send(Buffer.from(JSON.stringify(row ? row.events : null)))
        await stream.close()
      } catch { stream.abort(new Error('bad request')) }
    }, { maxInboundStreams: 16, maxOutboundStreams: 16, runOnLimitedConnection: true })
    this.timer = setInterval(() => { void this.announceOwn() }, REANNOUNCE_MS)
    this.timer.unref()
    // the DHT usually has no peers yet at start-up: try once shortly after, then every 6 h
    this.first = setTimeout(() => { void this.announceOwn() }, 30_000)
    this.first.unref()
  }

  async stop (): Promise<void> {
    this.closed = true
    if (this.timer) clearInterval(this.timer)
    if (this.first) clearTimeout(this.first)
    await this.node.unhandle(DID_PROTOCOL)
  }

  /** Verify and remember a log (ours or someone else's). Returns the best known state for its id, or null if invalid. */
  async adopt (events: unknown, own = false): Promise<IdentityState | null> {
    let st: IdentityState
    try { st = await verifyLog(events) } catch { return null }
    const have = this.known(st.id)
    if (have && (have.seq >= st.seq || !extendsLog(have.events, st.events))) return have   // never displace history we hold
    this.store.putIdentityLog(st.id, st.seq, JSON.stringify(st.events), own)
    this.mem.set(st.id, st)
    return st
  }

  known (id: string): IdentityState | null {
    const hit = this.mem.get(id)
    if (hit) return hit
    const row = this.store.getIdentityLog(id)
    return row ? ({ id, did: frenetDid(id), events: row.events, seq: row.seq, key: row.events[row.seq]!.key, next: row.events[row.seq]!.next, ts: row.events[row.seq]!.ts }) : null
  }

  /**
   * Best known log for `id`. With `network` (default), providers are asked at most once per 15 s so a rotation we have
   * not heard about is noticed; `minSeq` forces a lookup when a signature names a newer key than we know.
   */
  async resolve (id: string, opts: { network?: boolean, minSeq?: number, timeoutMs?: number } = {}): Promise<IdentityState | null> {
    if (!validB32(id)) return null
    let have = this.known(id)
    const stale = !have || (opts.minSeq !== undefined && have.seq < opts.minSeq) || Date.now() - (this.checked.get(id) ?? 0) > NETWORK_CACHE_MS
    if (opts.network !== false && stale) {
      this.checked.set(id, Date.now())
      const signal = AbortSignal.timeout(opts.timeoutMs ?? 3000)
      let asked = 0
      try {
        for await (const prov of this.node.contentRouting.findProviders(idCid(id), { signal })) {
          if (prov.id.equals(this.node.peerId)) continue
          if (++asked > PROVIDERS_PER_LOOKUP) break
          const st = await this.adopt(await ask(this.node, prov, DID_PROTOCOL, { id }, signal, MAX_RESPONSE_BYTES))
          if (st && st.id === id) have = st
        }
      } catch { /* no providers / timeout: use what we have */ }
      have = this.known(id) ?? have
    }
    return have
  }

  async announce (id: string): Promise<boolean> {
    try { await this.node.contentRouting.provide(idCid(id), { signal: AbortSignal.timeout(5000) }); return true } catch { return false }
  }

  async announceOwn (): Promise<void> {
    try {
      for (const l of this.store.listIdentityLogs(true)) { if (this.closed) return; await this.announce(l.id) }
    } catch { /* store closed during shutdown */ }
  }
}
