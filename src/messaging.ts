import { randomUUID } from 'node:crypto'
import { EventEmitter } from 'node:events'
import { peerIdFromString } from '@libp2p/peer-id'
import type { Libp2p, PeerId, PrivateKey } from '@libp2p/interface'
import type { Store } from './store.js'

export const MSG_PROTOCOL = '/frenet/msg/1.0.0'
export const MAX_BODY_BYTES = 16 * 1024
const MAX_FRAME_BYTES = 32 * 1024
const MAX_SKEW_MS = 5 * 60 * 1000
const SEEN_CAP = 10_000

interface Wire { v: 2, id: string, ts: number, to: string, body: string, sig: string }

const SIG_DOMAIN = 'frenet-msg/v2'
const ID_RE = /^[A-Za-z0-9-]{1,64}$/

/**
 * Canonical signed bytes. Binds sender, recipient, id and timestamp as well as the body,
 * so a signature cannot be replayed to another recipient or re-labelled. Fields before
 * `body` cannot contain newlines (peer IDs are base58, id is [A-Za-z0-9-], ts is an integer).
 */
function signedBytes (from: string, to: string, id: string, ts: number, body: string): Uint8Array {
  return Buffer.from(`${SIG_DOMAIN}\n${from}\n${to}\n${id}\n${ts}\n${body}`, 'utf8')
}

export async function signMessage (key: PrivateKey, from: string, to: string, id: string, ts: number, body: string): Promise<string> {
  return Buffer.from(await key.sign(signedBytes(from, to, id, ts, body))).toString('base64')
}

/** Verify a message against the signer's public key (derived from their Ed25519 peer ID). Works for any third party. */
export async function verifyMessage (m: { sender: string, recipient: string, id: string, ts: number, body: string, sig: string }): Promise<boolean> {
  try {
    const pub = peerIdFromString(m.sender).publicKey
    if (!pub) return false
    return await pub.verify(signedBytes(m.sender, m.recipient, m.id, m.ts, m.body), Buffer.from(m.sig, 'base64'))
  } catch { return false }
}

/** Token bucket per peer: `burst` messages, refilled at `perSec`. */
export class RateLimiter {
  private buckets = new Map<string, { tokens: number, last: number }>()
  constructor (private burst = 20, private perSec = 2, private now = () => Date.now()) {}
  allow (key: string): boolean {
    const t = this.now()
    const b = this.buckets.get(key) ?? { tokens: this.burst, last: t }
    b.tokens = Math.min(this.burst, b.tokens + ((t - b.last) / 1000) * this.perSec)
    b.last = t
    const ok = b.tokens >= 1
    if (ok) b.tokens -= 1
    this.buckets.set(key, b)
    return ok
  }
}

/** Replay protection: bounded set of recently seen (peer,id) pairs + timestamp window. */
export class ReplayGuard {
  private seen = new Set<string>()
  check (peer: string, id: string, ts: number, now = Date.now()): 'ok' | 'replay' | 'stale' {
    if (Math.abs(now - ts) > MAX_SKEW_MS) return 'stale'
    const k = `${peer}:${id}`
    if (this.seen.has(k)) return 'replay'
    this.seen.add(k)
    if (this.seen.size > SEEN_CAP) this.seen.delete(this.seen.values().next().value as string)
    return 'ok'
  }
}

export interface InboundMessage { id: string, peer: string, ts: number, body: string, sig: string }

/**
 * One message per stream over a Noise-authenticated, encrypted connection, and additionally
 * signed per message with the sender's Ed25519 identity key. The sender is the connection's
 * remotePeer, never a claimed field; the signature must verify under that peer's key and
 * name us as recipient. Stored signatures let third parties verify messages later.
 */
export class Messaging extends EventEmitter<{ message: [InboundMessage], dropped: [{ peer: string, reason: string }] }> {
  private limiter = new RateLimiter()
  private replay = new ReplayGuard()

  constructor (private node: Libp2p, private store: Store, private key: PrivateKey) { super() }

  async start (): Promise<void> {
    await this.node.handle(MSG_PROTOCOL, async (stream, connection) => {
      const peer = connection.remotePeer.toString()
      try {
        if (!this.limiter.allow(peer)) { this.drop(peer, 'rate-limited'); stream.abort(new Error('rate limited')); return }
        const chunks: Uint8Array[] = []
        let size = 0
        for await (const c of stream) {
          const b = c.subarray()
          size += b.length
          if (size > MAX_FRAME_BYTES) { this.drop(peer, 'oversize'); stream.abort(new Error('too large')); return }
          chunks.push(b)
        }
        const w = parse(Buffer.concat(chunks))
        if (!w) { this.drop(peer, 'malformed'); return }
        const self = this.node.peerId.toString()
        if (w.to !== self) { this.drop(peer, 'wrong-recipient'); return }
        if (!(await verifyMessage({ sender: peer, recipient: self, id: w.id, ts: w.ts, body: w.body, sig: w.sig }))) { this.drop(peer, 'bad-signature'); return }
        const verdict = this.replay.check(peer, w.id, w.ts)
        if (verdict !== 'ok') { this.drop(peer, verdict); return }
        if (this.store.add({ id: w.id, peer, direction: 'in', ts: w.ts, body: w.body, sender: peer, recipient: self, sig: w.sig })) {
          this.emit('message', { id: w.id, peer, ts: w.ts, body: w.body, sig: w.sig })
        }
      } catch (err) {
        this.drop(peer, `error: ${(err as Error).message}`)
      }
    }, { maxInboundStreams: 64, maxOutboundStreams: 64, runOnLimitedConnection: true })
  }

  async stop (): Promise<void> { await this.node.unhandle(MSG_PROTOCOL) }

  async send (to: PeerId, body: string): Promise<{ id: string, ts: number }> {
    if (Buffer.byteLength(body) > MAX_BODY_BYTES) throw new Error(`message exceeds ${MAX_BODY_BYTES} bytes`)
    if (body.length === 0) throw new Error('empty message')
    const self = this.node.peerId.toString()
    const id = randomUUID()
    const ts = Date.now()
    const sig = await signMessage(this.key, self, to.toString(), id, ts, body)
    const w: Wire = { v: 2, id, ts, to: to.toString(), body, sig }
    const stream = await this.node.dialProtocol(to, MSG_PROTOCOL, { runOnLimitedConnection: true })
    stream.send(Buffer.from(JSON.stringify(w)))
    await stream.close()
    this.store.add({ id: w.id, peer: to.toString(), direction: 'out', ts: w.ts, body, sender: self, recipient: to.toString(), sig })
    return { id: w.id, ts: w.ts }
  }

  private drop (peer: string, reason: string): void { this.emit('dropped', { peer, reason }) }
}

function parse (buf: Buffer): Wire | null {
  try {
    const o = JSON.parse(buf.toString('utf8'))
    if (o?.v !== 2 || typeof o.id !== 'string' || typeof o.ts !== 'number' || typeof o.body !== 'string' || typeof o.to !== 'string' || typeof o.sig !== 'string') return null
    if (!ID_RE.test(o.id) || o.to.length > 128 || o.sig.length > 128 || o.body.length === 0 || Buffer.byteLength(o.body) > MAX_BODY_BYTES) return null
    if (!Number.isFinite(o.ts)) return null
    return { v: 2, id: o.id, ts: o.ts, to: o.to, body: o.body, sig: o.sig }
  } catch { return null }
}
