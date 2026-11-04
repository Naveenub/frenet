import { randomUUID } from 'node:crypto'
import { EventEmitter } from 'node:events'
import type { Libp2p, PeerId, PrivateKey } from '@libp2p/interface'
import { canon, ID_RE, readFrame, signBytes, verifyBytes } from './channel.js'
import { RateLimiter, ReplayGuard } from './messaging.js'

export const CALL_PROTOCOL = '/frenet/call/1.0.0'
export const MAX_SIGNAL_BYTES = 16 * 1024
const DOMAIN = 'frenet-call/v1'
export const CALL_KINDS = ['offer', 'answer', 'ice', 'hangup', 'decline'] as const
export type CallKind = typeof CALL_KINDS[number]

interface Wire { v: 1, id: string, call: string, to: string, kind: CallKind, ts: number, data: string, sig: string }
export interface CallSignal { id: string, peer: string, call: string, kind: CallKind, ts: number, data: string }

const head = (from: string, to: string, call: string, kind: string, id: string, ts: number): string[] => [from, to, call, kind, id, String(ts)]

/**
 * WebRTC signalling only: SDP/ICE blobs relayed between browsers over the Noise-authenticated
 * libp2p link, signed per signal. Media never touches the node. Signals are ephemeral (not stored).
 */
export class Calls extends EventEmitter<{ signal: [CallSignal], dropped: [{ peer: string, reason: string }] }> {
  private limiter = new RateLimiter(60, 20)      // ICE candidates arrive in bursts
  private offers = new RateLimiter(3, 0.2)       // a peer cannot ring us more than ~1 per 5 s
  private replay = new ReplayGuard()

  constructor (private node: Libp2p, private key: PrivateKey) { super() }

  async start (): Promise<void> {
    await this.node.handle(CALL_PROTOCOL, async (stream, connection) => {
      const peer = connection.remotePeer.toString()
      try {
        if (!this.limiter.allow(peer)) { this.drop(peer, 'rate-limited'); stream.abort(new Error('rate limited')); return }
        const buf = await readFrame(stream)
        if (!buf) { this.drop(peer, 'oversize'); return }
        const w = parse(buf)
        if (!w) { this.drop(peer, 'malformed'); return }
        const self = this.node.peerId.toString()
        if (w.to !== self) { this.drop(peer, 'wrong-recipient'); return }
        if (!(await verifyBytes(peer, canon(DOMAIN, head(peer, self, w.call, w.kind, w.id, w.ts), w.data), w.sig))) { this.drop(peer, 'bad-signature'); return }
        const verdict = this.replay.check(peer, w.id, w.ts)
        if (verdict !== 'ok') { this.drop(peer, verdict); return }
        if (w.kind === 'offer' && !this.offers.allow(peer)) { this.drop(peer, 'offer-rate-limited'); return }
        this.emit('signal', { id: w.id, peer, call: w.call, kind: w.kind, ts: w.ts, data: w.data })
      } catch (err) {
        this.drop(peer, `error: ${(err as Error).message}`)
      }
    }, { maxInboundStreams: 64, maxOutboundStreams: 64, runOnLimitedConnection: true })
  }

  async stop (): Promise<void> { await this.node.unhandle(CALL_PROTOCOL) }

  async send (to: PeerId, call: string, kind: string, data: string): Promise<void> {
    if (!ID_RE.test(call)) throw new Error('invalid call id')
    if (!(CALL_KINDS as readonly string[]).includes(kind)) throw new Error('invalid signal kind')
    if (Buffer.byteLength(data) > MAX_SIGNAL_BYTES) throw new Error(`signal exceeds ${MAX_SIGNAL_BYTES} bytes`)
    const self = this.node.peerId.toString()
    const id = randomUUID()
    const ts = Date.now()
    const sig = await signBytes(this.key, canon(DOMAIN, head(self, to.toString(), call, kind, id, ts), data))
    const w: Wire = { v: 1, id, call, to: to.toString(), kind: kind as CallKind, ts, data, sig }
    const stream = await this.node.dialProtocol(to, CALL_PROTOCOL, { runOnLimitedConnection: true })
    stream.send(Buffer.from(JSON.stringify(w)))
    await stream.close()
  }

  private drop (peer: string, reason: string): void { this.emit('dropped', { peer, reason }) }
}

function parse (buf: Buffer): Wire | null {
  try {
    const o = JSON.parse(buf.toString('utf8'))
    if (o?.v !== 1 || typeof o.id !== 'string' || typeof o.call !== 'string' || typeof o.to !== 'string' || typeof o.kind !== 'string' ||
        typeof o.ts !== 'number' || typeof o.data !== 'string' || typeof o.sig !== 'string') return null
    if (!ID_RE.test(o.id) || !ID_RE.test(o.call) || !(CALL_KINDS as readonly string[]).includes(o.kind)) return null
    if (o.to.length > 128 || o.sig.length > 128 || !Number.isFinite(o.ts) || Buffer.byteLength(o.data) > MAX_SIGNAL_BYTES) return null
    return o as Wire
  } catch { return null }
}
