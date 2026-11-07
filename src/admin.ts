import { randomUUID } from 'node:crypto'
import { EventEmitter } from 'node:events'
import { multiaddr } from '@multiformats/multiaddr'
import { peerIdFromString } from '@libp2p/peer-id'
import type { Libp2p, PrivateKey } from '@libp2p/interface'
import { canon, ID_RE, isPeerId, MAX_SKEW_MS, readFrame, signBytes, verifyBytes } from './channel.js'
import { RateLimiter, ReplayGuard } from './messaging.js'
import { readJson } from './rpc.js'
import type { Moderation } from './moderation.js'
import type { Operator } from './operator.js'
import type { Blocks } from './blocks.js'
import type { Store } from './store.js'

export const ADMIN_PROTOCOL = '/frenet/admin/1.0.0'
const DOMAIN = 'frenet-admin/v1'
const MAX_REQUEST_BYTES = 8 * 1024
const MAX_ARGS_BYTES = 4 * 1024
const MAX_RESPONSE_BYTES = 512 * 1024
/** The whole remote surface. No keys, messages, files, identity, credentials, config or updates. */
export const ADMIN_COMMANDS = ['status', 'bans', 'ban', 'unban', 'disconnect', 'sweep', 'reannounce', 'block', 'unblock'] as const
export type AdminCommand = typeof ADMIN_COMMANDS[number]

interface Wire { v: 1, id: string, ts: number, to: string, cmd: string, args: string, sig: string }

/**
 * Remote administration of a node by pre-approved peers.
 *
 * Off unless the operator lists admin peer IDs (`--admin-peer`); with none, the protocol is not even registered.
 * A request is honoured only if ALL hold: the connection's authenticated remote peer (Noise) is on the list; the
 * request is signed by that same key over (sender, target, id, time, command, arguments), so it cannot be replayed
 * to another node or re-labelled; the timestamp is within 5 minutes and the id has not been seen; the per-peer rate
 * limit allows it; and the command is on a short allow-list. Every attempt that gets past the peer check is written
 * to a local audit log. The admin list is a startup flag, so no remote peer can add itself or anyone else.
 *
 * Limits: an admin can ban, unban, disconnect, sweep, re-announce and edit the content blocklist, and read the stats
 * snapshot. It cannot read data or keys. Admin traffic is protected by the same Noise link as everything else; the
 * admin's identity key is its node key, so protect that machine.
 */
export class Admin extends EventEmitter<{ dropped: [{ peer: string, reason: string }] }> {
  private limiter = new RateLimiter(10, 1)
  private replay = new ReplayGuard()
  readonly admins: Set<string>

  constructor (private node: Libp2p, private store: Store, private key: PrivateKey, private ops: { operator: Operator, moderation: Moderation, blocks: Blocks }, admins: string[] = []) {
    super()
    for (const a of admins) if (!isPeerId(a)) throw new Error(`invalid admin peer ID "${a}"`)
    this.admins = new Set(admins)
    if (this.admins.has(node.peerId.toString())) throw new Error('this node cannot be its own remote admin')
  }

  get enabled (): boolean { return this.admins.size > 0 }

  async start (): Promise<void> {
    if (!this.enabled) return
    await this.node.handle(ADMIN_PROTOCOL, async (stream, connection) => {
      const peer = connection.remotePeer.toString()
      try {
        if (!this.admins.has(peer)) return this.reject(stream, peer, 'not-admin')
        if (!this.limiter.allow(peer)) return this.reject(stream, peer, 'rate-limited')
        const frame = await readFrame(stream, MAX_REQUEST_BYTES)
        if (!frame) { this.drop(peer, 'oversize'); return }   // readFrame already aborted the stream
        const w = parse(frame)
        if (!w) return this.reject(stream, peer, 'malformed')
        const self = this.node.peerId.toString()
        if (w.to !== self) return this.reject(stream, peer, 'wrong-target')
        if (!(await verifyBytes(peer, canon(DOMAIN, [peer, self, w.id, String(w.ts), w.cmd], w.args), w.sig))) return this.reject(stream, peer, 'bad-signature')
        const verdict = this.replay.check(peer, w.id, w.ts)
        if (verdict !== 'ok') return this.reject(stream, peer, verdict)
        let reply: { ok: boolean, result?: unknown, error?: string }
        try {
          reply = { ok: true, result: await this.exec(w.cmd as AdminCommand, JSON.parse(w.args), peer) }
          this.store.addAdminLog(peer, w.cmd, true, summary(w.cmd, w.args))
        } catch (e) {
          reply = { ok: false, error: (e as Error).message.slice(0, 300) }
          this.store.addAdminLog(peer, w.cmd, false, `${summary(w.cmd, w.args)}: ${reply.error}`)
        }
        stream.send(Buffer.from(JSON.stringify(reply)))
        await stream.close()
      } catch (err) {
        this.reject(stream, peer, `error: ${(err as Error).message}`)
      }
    }, { maxInboundStreams: 8, maxOutboundStreams: 8, runOnLimitedConnection: true })
  }

  async stop (): Promise<void> { if (this.enabled) await this.node.unhandle(ADMIN_PROTOCOL) }

  private async exec (cmd: AdminCommand, a: any, requester: string): Promise<unknown> {
    const o = this.ops.operator
    const self = this.node.peerId.toString()
    const target = (): string => {
      if (!isPeerId(a?.peer)) throw new Error('invalid peer ID')
      return a.peer
    }
    switch (cmd) {
      case 'status': return o.snapshot()
      case 'bans': return this.store.listBans()
      case 'ban': {
        const p = target()
        if (this.admins.has(p) || p === self) throw new Error('refusing to ban an admin peer or this node')
        await o.ban(p, `remote:${requester.slice(0, 12)}: ${String(a.reason ?? '')}`)
        return { ok: true }
      }
      case 'unban': return { removed: o.unban(target()) }
      case 'disconnect': {
        const p = target()
        if (p === requester) throw new Error('refusing to disconnect the requesting admin')
        await o.disconnect(p)
        return { ok: true }
      }
      case 'sweep': return { removed: o.sweep() }
      case 'reannounce': return this.ops.blocks.reannounce()
      case 'block': return this.ops.moderation.block(a?.kind, a?.target, `remote:${requester.slice(0, 12)}: ${String(a?.reason ?? '')}`.slice(0, 200))   // no key argument: key-assisted blocking stays local
      case 'unblock': return { removed: this.ops.moderation.unblock(a?.kind, a?.target) }
      default: throw new Error('unknown command')
    }
  }

  /** Send one signed command to a node that lists this node as an admin. Throws with the remote's reason when refused. */
  async call (peer: string, cmd: AdminCommand, args: Record<string, unknown> = {}, opts: { addr?: string, timeoutMs?: number } = {}): Promise<any> {
    if (!isPeerId(peer)) throw new Error('invalid peer ID')
    if (!(ADMIN_COMMANDS as readonly string[]).includes(cmd)) throw new Error(`unknown command "${cmd}" (use ${ADMIN_COMMANDS.join(', ')})`)
    const argText = JSON.stringify(args)
    if (Buffer.byteLength(argText) > MAX_ARGS_BYTES) throw new Error('arguments too large')
    const self = this.node.peerId.toString()
    const id = randomUUID()
    const ts = Date.now()
    const sig = await signBytes(this.key, canon(DOMAIN, [self, peer, id, String(ts), cmd], argText))
    const signal = AbortSignal.timeout(opts.timeoutMs ?? 15_000)
    if (opts.addr) await this.node.dial(multiaddr(opts.addr), { signal })
    const stream = await this.node.dialProtocol(peerIdFromString(peer), ADMIN_PROTOCOL, { signal, runOnLimitedConnection: true })
    const w: Wire = { v: 1, id, ts, to: peer, cmd, args: argText, sig }
    let reply: any
    try {
      stream.send(Buffer.from(JSON.stringify(w)))
      await stream.close()
      reply = await readJson(stream as any, MAX_RESPONSE_BYTES)
    } catch { throw new Error('no valid reply (this node is probably not an admin of that peer, the request was refused, or the peer has remote administration off)') }
    if (!reply?.ok) throw new Error(`remote refused: ${String(reply?.error ?? 'unknown error').slice(0, 300)}`)
    return reply.result
  }

  /** Count the drop and abort the stream, so a refused client fails fast instead of waiting for a reply that never comes. */
  private reject (stream: { abort: (e: Error) => void }, peer: string, reason: string): void {
    this.drop(peer, reason)
    try { stream.abort(new Error('refused')) } catch { /* already closed */ }
  }

  private drop (peer: string, reason: string): void { this.emit('dropped', { peer, reason }) }
}

function summary (cmd: string, args: string): string {
  try {
    const a = JSON.parse(args)
    return [cmd, a?.peer, a?.kind && `${a.kind}:${String(a.target ?? '').slice(0, 64)}`].filter(Boolean).join(' ').replace(/[\u0000-\u001f\u007f]/g, ' ').slice(0, 200)
  } catch { return cmd }
}

function parse (buf: Buffer): Wire | null {
  try {
    const o = JSON.parse(buf.toString('utf8'))
    if (o?.v !== 1 || typeof o.id !== 'string' || typeof o.ts !== 'number' || typeof o.to !== 'string' || typeof o.cmd !== 'string' || typeof o.args !== 'string' || typeof o.sig !== 'string') return null
    if (!ID_RE.test(o.id) || !Number.isFinite(o.ts) || Math.abs(Date.now() - o.ts) > MAX_SKEW_MS * 2) return null
    if (o.to.length > 128 || o.sig.length > 128 || o.args.length > MAX_ARGS_BYTES || !(ADMIN_COMMANDS as readonly string[]).includes(o.cmd)) return null
    const args = JSON.parse(o.args)
    if (!args || typeof args !== 'object' || Array.isArray(args)) return null
    return { v: 1, id: o.id, ts: o.ts, to: o.to, cmd: o.cmd, args: o.args, sig: o.sig }
  } catch { return null }
}
