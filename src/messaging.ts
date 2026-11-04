import { randomUUID } from 'node:crypto'
import { EventEmitter } from 'node:events'
import type { Libp2p, PeerId } from '@libp2p/interface'
import type { Store } from './store.js'

export const MSG_PROTOCOL = '/frenet/msg/1.0.0'
export const MAX_BODY_BYTES = 16 * 1024
const MAX_FRAME_BYTES = 32 * 1024
const MAX_SKEW_MS = 5 * 60 * 1000
const SEEN_CAP = 10_000

interface Wire { v: 1, id: string, ts: number, body: string }

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

export interface InboundMessage { id: string, peer: string, ts: number, body: string }

/**
 * One message per stream over an already Noise-authenticated, encrypted connection.
 * The sender identity is the connection's remotePeer (cryptographically authenticated),
 * never a field the sender claims.
 */
export class Messaging extends EventEmitter<{ message: [InboundMessage], dropped: [{ peer: string, reason: string }] }> {
  private limiter = new RateLimiter()
  private replay = new ReplayGuard()

  constructor (private node: Libp2p, private store: Store) { super() }

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
        const verdict = this.replay.check(peer, w.id, w.ts)
        if (verdict !== 'ok') { this.drop(peer, verdict); return }
        if (this.store.add({ id: w.id, peer, direction: 'in', ts: w.ts, body: w.body })) {
          this.emit('message', { id: w.id, peer, ts: w.ts, body: w.body })
        }
      } catch (err) {
        this.drop(peer, `error: ${(err as Error).message}`)
      }
    }, { maxInboundStreams: 64, maxOutboundStreams: 64 })
  }

  async stop (): Promise<void> { await this.node.unhandle(MSG_PROTOCOL) }

  async send (to: PeerId, body: string): Promise<{ id: string, ts: number }> {
    if (Buffer.byteLength(body) > MAX_BODY_BYTES) throw new Error(`message exceeds ${MAX_BODY_BYTES} bytes`)
    if (body.length === 0) throw new Error('empty message')
    const w: Wire = { v: 1, id: randomUUID(), ts: Date.now(), body }
    const stream = await this.node.dialProtocol(to, MSG_PROTOCOL)
    stream.send(Buffer.from(JSON.stringify(w)))
    await stream.close()
    this.store.add({ id: w.id, peer: to.toString(), direction: 'out', ts: w.ts, body })
    return { id: w.id, ts: w.ts }
  }

  private drop (peer: string, reason: string): void { this.emit('dropped', { peer, reason }) }
}

function parse (buf: Buffer): Wire | null {
  try {
    const o = JSON.parse(buf.toString('utf8'))
    if (o?.v !== 1 || typeof o.id !== 'string' || typeof o.ts !== 'number' || typeof o.body !== 'string') return null
    if (o.id.length > 64 || o.body.length === 0 || Buffer.byteLength(o.body) > MAX_BODY_BYTES) return null
    if (!Number.isFinite(o.ts)) return null
    return { v: 1, id: o.id, ts: o.ts, body: o.body }
  } catch { return null }
}
