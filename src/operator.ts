import { cpus, loadavg } from 'node:os'
import { peerIdFromString } from '@libp2p/peer-id'
import type { Libp2p } from '@libp2p/interface'
import { isPeerId } from './channel.js'
import type { Store } from './store.js'

const MAX_DROP_KEYS = 100

/**
 * Operator tools: a persistent peer ban list enforced by the libp2p connection gater (`banned` is the
 * live set the gater reads), manual disconnect, retention sweep, resource and abuse counters.
 */
export class Operator {
  private drops = new Map<string, number>()

  constructor (private node: Libp2p, private store: Store, readonly banned: Set<string>) {
    for (const b of store.listBans()) banned.add(b.peer)
  }

  noteDrop (proto: string, reason: string): void {
    const k = `${proto}: ${reason.startsWith('error') ? 'error' : reason}`
    if (!this.drops.has(k) && this.drops.size >= MAX_DROP_KEYS) return
    this.drops.set(k, (this.drops.get(k) ?? 0) + 1)
  }

  private peer (p: unknown): string {
    if (!isPeerId(p)) throw new Error('invalid peer ID')
    return p
  }

  async ban (peer: unknown, reason: unknown = ''): Promise<void> {
    const p = this.peer(peer)
    if (p === this.node.peerId.toString()) throw new Error('cannot ban this node')
    this.store.addBan(p, String(reason ?? '').replace(/[\u0000-\u001f\u007f]/g, ' ').slice(0, 200))
    this.banned.add(p)
    await this.node.hangUp(peerIdFromString(p)).catch(() => {})
  }

  unban (peer: unknown): boolean {
    const p = this.peer(peer)
    this.banned.delete(p)
    return this.store.removeBan(p)
  }

  async disconnect (peer: unknown): Promise<void> { await this.node.hangUp(peerIdFromString(this.peer(peer))) }

  sweep (): number { return this.store.sweep() }

  snapshot (): unknown {
    const conns = this.node.getConnections()
    const m = process.memoryUsage()
    const mb = (n: number): number => Math.round(n / 1048576)
    return {
      process: { node: process.version, rssMb: mb(m.rss), heapUsedMb: mb(m.heapUsed), uptimeS: Math.round(process.uptime()), loadAvg: loadavg().map((x) => Math.round(x * 100) / 100), cpus: cpus().length },
      connections: {
        total: conns.length,
        inbound: conns.filter((c) => c.direction === 'inbound').length,
        outbound: conns.filter((c) => c.direction === 'outbound').length,
        relayed: conns.filter((c) => c.remoteAddr.toString().includes('/p2p-circuit')).length
      },
      bans: this.store.listBans(),
      drops: Object.fromEntries(this.drops)
    }
  }
}
