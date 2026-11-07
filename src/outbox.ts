import type { Libp2p } from '@libp2p/interface'
import type { Store } from './store.js'

export const OUTBOX_TTL_MS = 7 * 24 * 3600 * 1000
export const OUTBOX_MAX_PER_PEER = 200
export const OUTBOX_MAX_TOTAL = 2000
const RETRY_BASE_MS = 5_000
const RETRY_MAX_MS = 5 * 60_000
const FLUSH_EVERY_MS = 15_000
const BATCH = 50

export type OutboxKind = 'msg' | 'group'
export interface OutboxRow { kind: OutboxKind, id: string, peer: string, ts: number, payload: string, tries: number, next: number }
/** Delivers one queued payload. Resolve when the peer has it (or when it no longer needs it); reject to retry later. */
export type OutboxHandler = (peer: string, payload: string) => Promise<void>

/**
 * Store-and-forward for the sender side only. A message that could not be delivered is kept in the local
 * database and retried when the peer connects and on a backoff timer, for at most OUTBOX_TTL_MS. Nothing is
 * handed to a third party: there is no relay that holds mail, so the *sender's* node has to be online when
 * the recipient comes back. Receivers dedupe by id, so a retry after a half-finished delivery is harmless.
 */
export class Outbox {
  private handlers = new Map<OutboxKind, OutboxHandler>()
  private timer: NodeJS.Timeout | null = null
  private running = new Set<string>()
  private onConnect = (evt: CustomEvent<{ toString(): string }>): void => { void this.flush(evt.detail.toString(), true).catch(() => {}) }

  constructor (private node: Libp2p, private store: Store, private clock: () => number = Date.now) {}

  register (kind: OutboxKind, fn: OutboxHandler): void { this.handlers.set(kind, fn) }

  start (): void {
    this.timer = setInterval(() => { void this.flush().catch(() => {}) }, FLUSH_EVERY_MS)
    this.timer.unref()
    this.node.addEventListener('peer:connect', this.onConnect as EventListener)
    void this.flush().catch(() => {})   // anything left from before a restart
  }

  stop (): void {
    if (this.timer) clearInterval(this.timer)
    this.timer = null
    this.node.removeEventListener('peer:connect', this.onConnect as EventListener)
  }

  /** Queue a payload for `peer`. Returns false if the outbox is full (the caller should report the failure). */
  enqueue (kind: OutboxKind, id: string, peer: string, ts: number, payload: string): boolean {
    if (this.store.outboxCount() >= OUTBOX_MAX_TOTAL || this.store.outboxCount(peer) >= OUTBOX_MAX_PER_PEER) return false
    this.store.outboxAdd({ kind, id, peer, ts, payload, tries: 0, next: this.clock() + RETRY_BASE_MS })
    return true
  }

  pending (peer?: string): number { return this.store.outboxCount(peer) }

  /** Try everything that is due (or, with `force`, everything for `peer`). Returns how many payloads were delivered. */
  async flush (peer?: string, force = false): Promise<number> {
    const now = this.clock()
    this.store.outboxExpire(now - OUTBOX_TTL_MS)
    let sent = 0
    for (const row of this.store.outboxDue(now, peer, force, BATCH)) {
      const key = `${row.kind}:${row.id}:${row.peer}`
      if (this.running.has(key)) continue
      this.running.add(key)
      try {
        const h = this.handlers.get(row.kind)
        if (!h) continue
        try {
          await h(row.peer, row.payload)
          this.store.outboxDone(row.kind, row.id, row.peer)
          sent++
        } catch {
          this.store.outboxRetry(row.kind, row.id, row.peer, this.clock() + Math.min(RETRY_MAX_MS, RETRY_BASE_MS * 2 ** Math.min(row.tries, 10)))
        }
      } finally { this.running.delete(key) }
    }
    return sent
  }
}
