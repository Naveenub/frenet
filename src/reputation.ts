import type { Store } from './store.js'

/**
 * Local node reputation and malicious-node detection.
 *
 * Every verified-bad act a peer commits against *this* node (bad signature, a block that does not hash to its
 * CID, a forged name record, malformed or oversize frames, floods) lowers that peer's score; verified-good acts
 * (a valid signed message, a block that verified) raise it a little. Scores decay toward zero with a half-life so
 * a peer is not punished forever for an old mistake. When a score falls to `banThreshold` the peer is blocked
 * for a period that doubles with every repeat (1 h .. 7 d) and the block is enforced by the connection gater.
 *
 * What this is not: a global or shared reputation. Nothing is gossiped, so a peer cannot lie about another
 * peer to this node, and a good name on another node is worth nothing here. A peer that rotates its peer ID
 * starts fresh; that is what the Sybil defences in `sybil.ts` make costly. Only misbehaviour this node can
 * itself prove is scored: a peer that merely stays silent or is slow is not.
 */

/** Score deltas. Negative events are things a correct implementation never does, positive ones are cheap to earn. */
export const EVENTS = {
  'valid-message': 0.5,
  'valid-block': 1,
  'valid-record': 0.5,
  'bad-signature': -25,
  'bad-block': -40,
  'bad-record': -25,
  'malformed': -8,
  'oversize': -10,
  'replay': -6,
  'wrong-recipient': -3,
  'stale': -2,
  'rate-limited': -4,
  'sybil-cluster': -15,
  'error': -2,
  'unauthorized': -10
} as const
export type ReputationEvent = keyof typeof EVENTS

export interface ReputationOptions {
  /** Score at or below which a peer is blocked. Default -50. */
  banThreshold: number
  /** Positive scores are capped here so good history cannot buy unlimited misbehaviour. */
  maxScore: number
  /** Half-life of both good and bad scores. Default 24 h. */
  halfLifeMs: number
  /** First block duration; doubled per strike up to `maxBlockMs`. */
  baseBlockMs: number
  maxBlockMs: number
  /** Max tracked peers (lowest-information rows are dropped first), bounding memory/disk against peer-ID floods. */
  maxPeers: number
}
export const DEFAULT_REPUTATION: ReputationOptions = {
  banThreshold: -50, maxScore: 50, halfLifeMs: 24 * 3_600_000, baseBlockMs: 3_600_000, maxBlockMs: 7 * 86_400_000, maxPeers: 10_000
}

export interface PeerReputation { peer: string, score: number, good: number, bad: number, strikes: number, blockedUntil: number | null, lastReason: string, updated: number }

export class Reputation {
  readonly opts: ReputationOptions
  private rows = new Map<string, PeerReputation>()
  /** Peers that are never auto-blocked (operator-configured bootstrap and relay peers). They are still scored. */
  readonly trusted = new Set<string>()

  constructor (private store: Store, opts: Partial<ReputationOptions> = {}, private now: () => number = Date.now) {
    this.opts = { ...DEFAULT_REPUTATION, ...opts }
    for (const r of store.listReputation()) this.rows.set(r.peer, r)
  }

  private decayed (r: PeerReputation, at: number): number {
    const dt = Math.max(0, at - r.updated)
    return r.score * Math.pow(0.5, dt / this.opts.halfLifeMs)
  }

  /** Record an event. Returns true if this event caused the peer to become blocked. */
  record (peer: string, event: ReputationEvent, detail = ''): boolean {
    const at = this.now()
    let r = this.rows.get(peer)
    if (!r) {
      if (EVENTS[event] >= 0 && this.rows.size >= this.opts.maxPeers) return false   // do not allocate rows for good news when full
      r = { peer, score: 0, good: 0, bad: 0, strikes: 0, blockedUntil: null, lastReason: '', updated: at }
      this.rows.set(peer, r)
    }
    const delta = EVENTS[event]
    r.score = Math.min(this.opts.maxScore, this.decayed(r, at) + delta)
    r.updated = at
    if (delta >= 0) r.good++
    else { r.bad++; r.lastReason = (detail ? `${event}: ${detail}` : event).replace(/[\u0000-\u001f\u007f]/g, ' ').slice(0, 120) }
    let blocked = false
    if (delta < 0 && r.score <= this.opts.banThreshold && !this.trusted.has(peer) && !this.isBlocked(peer)) {
      r.strikes++
      r.blockedUntil = at + Math.min(this.opts.maxBlockMs, this.opts.baseBlockMs * 2 ** (r.strikes - 1))
      r.score = this.opts.banThreshold / 2   // after a block ends the peer is on probation, not forgiven
      blocked = true
    }
    this.store.putReputation(r)
    this.evict(peer)
    return blocked
  }

  /** Map a protocol drop reason (see Messaging/Calls/Groups `dropped`) to an event. Unknown reasons are ignored. */
  noteDrop (peer: string, reason: string): boolean {
    const base = reason.startsWith('error') ? 'error' : reason
    const ev = DROP_EVENTS[base]
    return ev ? this.record(peer, ev, base) : false
  }

  isBlocked (peer: string): boolean {
    const r = this.rows.get(peer)
    if (!r || r.blockedUntil === null) return false
    if (r.blockedUntil > this.now()) return true
    r.blockedUntil = null
    this.store.putReputation(r)
    return false
  }

  score (peer: string): number {
    const r = this.rows.get(peer)
    return r ? Math.round(this.decayed(r, this.now()) * 100) / 100 : 0
  }

  /** Forget a peer (operator override). */
  reset (peer: string): boolean {
    this.store.deleteReputation(peer)
    return this.rows.delete(peer)
  }

  list (limit = 100): PeerReputation[] {
    const at = this.now()
    return [...this.rows.values()]
      .map((r) => ({ ...r, score: Math.round(this.decayed(r, at) * 100) / 100 }))
      .sort((a, b) => a.score - b.score)
      .slice(0, limit)
  }

  blockedCount (): number { let n = 0; for (const p of this.rows.keys()) if (this.isBlocked(p)) n++; return n }

  /** Keep memory and disk bounded: drop the rows that say the least (near-zero score, never blocked, oldest). */
  private evict (keep: string): void {
    if (this.rows.size <= this.opts.maxPeers) return
    const at = this.now()
    const candidates = [...this.rows.values()]
      .filter((r) => r.peer !== keep && (r.blockedUntil === null || r.blockedUntil <= at))
      .sort((a, b) => Math.abs(this.decayed(a, at)) - Math.abs(this.decayed(b, at)) || a.updated - b.updated)
    for (const r of candidates) {
      if (this.rows.size <= this.opts.maxPeers) break
      this.rows.delete(r.peer); this.store.deleteReputation(r.peer)
    }
  }
}

const DROP_EVENTS: Record<string, ReputationEvent> = {
  'rate-limited': 'rate-limited',
  'offer-rate-limited': 'rate-limited',
  'oversize': 'oversize',
  'malformed': 'malformed',
  'wrong-recipient': 'wrong-recipient',
  'bad-signature': 'bad-signature',
  'replay': 'replay',
  'stale': 'stale',
  'error': 'error',
  'not-owner': 'unauthorized'
}
