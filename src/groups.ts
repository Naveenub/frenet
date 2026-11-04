import { randomBytes, randomUUID } from 'node:crypto'
import { EventEmitter } from 'node:events'
import { peerIdFromString } from '@libp2p/peer-id'
import type { Libp2p, PrivateKey } from '@libp2p/interface'
import { canon, ID_RE, isPeerId, MAX_SKEW_MS, readFrame, signBytes, verifyBytes } from './channel.js'
import { RateLimiter, ReplayGuard } from './messaging.js'
import type { CommunityRow, Store } from './store.js'

export const GROUP_PROTOCOL = '/frenet/group/1.0.0'
export const GROUP_DOMAIN = 'frenet-group/v1'
export const MAX_MEMBERS = 100
export const MAX_TEXT_BYTES = 4096
const MAX_BODY_BYTES = 16 * 1024
const MAX_PENDING_INVITES = 50
export const MIN_VOTE_MS = 60_000
export const MAX_VOTE_MS = 30 * 86_400_000
const COMMUNITY_RE = /^[a-f0-9]{16}$/
const KINDS = ['roster', 'msg', 'proposal', 'vote'] as const
type Kind = typeof KINDS[number]
export const CHOICES = ['yes', 'no', 'abstain'] as const
export type Choice = typeof CHOICES[number]

export interface Wire { v: 1, community: string, kind: Kind, id: string, ts: number, body: string, sig: string }
export interface GroupEvent { community: string, id: string, kind: Kind, author: string, ts: number }
export interface Delivery { delivered: number, failed: string[] }

export interface Tally { yes: number, no: number, abstain: number, voted: number, electorate: number, quorum: boolean, outcome: 'passed' | 'rejected' | 'no-quorum' }

/**
 * One member, one vote; the latest ballot per member counts; only the electorate frozen into the
 * proposal can vote. Quorum is strictly more than half the electorate casting any ballot.
 * Pure function over signed events, so any node holding the same ballots computes the same result.
 */
export function tally (electorate: string[], votes: Array<{ author: string, ts: number, id: string, choice: string }>): Tally {
  const el = new Set(electorate)
  const latest = new Map<string, (typeof votes)[number]>()
  for (const v of votes) {
    if (!el.has(v.author) || !(CHOICES as readonly string[]).includes(v.choice)) continue
    const cur = latest.get(v.author)
    if (!cur || v.ts > cur.ts || (v.ts === cur.ts && v.id > cur.id)) latest.set(v.author, v)
  }
  const t = { yes: 0, no: 0, abstain: 0 }
  for (const v of latest.values()) t[v.choice as Choice]++
  const quorum = latest.size * 2 > el.size
  return { ...t, voted: latest.size, electorate: el.size, quorum, outcome: !quorum ? 'no-quorum' : t.yes > t.no ? 'passed' : 'rejected' }
}

export function cleanLine (s: unknown, max: number): string | null {
  if (typeof s !== 'string') return null
  const t = s.trim()
  return t.length >= 1 && t.length <= max && !/[\u0000-\u001f\u007f]/.test(t) ? t : null
}

const json = (s: string): any => { try { return JSON.parse(s) } catch { return null } }

/**
 * Communities and group chat over /frenet/group/1.0.0 (one signed event per stream, fan-out to members).
 * The community owner (creator) signs membership rosters; members sign messages, proposals and ballots.
 * The sender is the Noise-authenticated remotePeer and must equal the signing author: no relaying yet.
 */
export class Groups extends EventEmitter<{ event: [GroupEvent], community: [string], dropped: [{ peer: string, reason: string }] }> {
  private limiter = new RateLimiter(60, 10)
  private replay = new ReplayGuard()

  constructor (private node: Libp2p, private store: Store, private key: PrivateKey) { super() }

  private get self (): string { return this.node.peerId.toString() }

  async start (): Promise<void> {
    await this.node.handle(GROUP_PROTOCOL, async (stream, connection) => {
      const peer = connection.remotePeer.toString()
      try {
        if (!this.limiter.allow(peer)) { this.drop(peer, 'rate-limited'); stream.abort(new Error('rate limited')); return }
        const buf = await readFrame(stream)
        if (!buf) { this.drop(peer, 'oversize'); return }
        const w = parse(buf)
        if (!w) { this.drop(peer, 'malformed'); return }
        const reason = await this.accept(peer, w)
        if (reason) this.drop(peer, reason)
      } catch (err) {
        this.drop(peer, `error: ${(err as Error).message}`)
      }
    }, { maxInboundStreams: 64, maxOutboundStreams: 64, runOnLimitedConnection: true })
  }

  async stop (): Promise<void> { await this.node.unhandle(GROUP_PROTOCOL) }

  list (): CommunityRow[] { return this.store.listCommunities() }

  /** Verify and apply one inbound event from `author` (the connection's remote peer). Returns a drop reason, or null if accepted. */
  async accept (author: string, w: Wire): Promise<string | null> {
    const now = Date.now()
    if (!(await verifyBytes(author, canon(GROUP_DOMAIN, [author, w.community, w.kind, w.id, String(w.ts)], w.body), w.sig))) return 'bad-signature'
    const verdict = this.replay.check(author, `${w.community}:${w.id}`, w.ts, now)
    if (verdict !== 'ok') return verdict
    if (w.kind === 'roster') return this.applyRoster(author, w, now)
    const c = this.store.getCommunity(w.community)
    if (!c || c.state !== 'joined') return 'not-joined'
    if (!c.members.includes(author)) return 'not-a-member'
    return this.apply(c, author, w, now)
  }

  private applyRoster (author: string, w: Wire, now: number): string | null {
    const b = json(w.body)
    const name = cleanLine(b?.name, 60)
    const members = b?.members
    if (!name || !Number.isSafeInteger(b?.seq) || b.seq < 1 || !Array.isArray(members) || members.length > MAX_MEMBERS ||
        !members.every(isPeerId) || new Set(members).size !== members.length || !members.includes(author)) return 'malformed'
    const c = this.store.getCommunity(w.community)
    const mine = members.includes(this.self)
    if (c) {
      if (c.owner !== author) return 'not-owner'
      if (b.seq <= c.seq) return 'stale-roster'
    } else if (!mine) return 'not-a-member'
    else if (this.store.countCommunities('invited') >= MAX_PENDING_INVITES) return 'invite-limit'
    // An invitation needs the user's explicit join; leaving is sticky so an owner cannot re-invite-spam.
    const state = c?.state === 'left' ? 'left' : !mine ? 'removed' : c?.state === 'joined' ? 'joined' : 'invited'
    this.store.putCommunity({ id: w.community, owner: author, name, seq: b.seq, members, state, updated: now })
    this.emit('community', w.community)
    return null
  }

  private apply (c: CommunityRow, author: string, w: Wire, now: number): string | null {
    let meta: string | null = null
    if (w.kind === 'msg') {
      if (!w.body || Buffer.byteLength(w.body) > MAX_TEXT_BYTES) return 'malformed'
    } else if (w.kind === 'proposal') {
      const b = json(w.body)
      if (!cleanLine(b?.title, 80) || typeof b?.text !== 'string' || b.text.length > 2000 || !Number.isSafeInteger(b?.closes)) return 'malformed'
      if (b.closes - w.ts < MIN_VOTE_MS || b.closes - w.ts > MAX_VOTE_MS || b.closes <= now) return 'malformed'
      meta = JSON.stringify(c.members) // the electorate is frozen when the proposal is first seen
    } else if (w.kind === 'vote') {
      const b = json(w.body)
      if (typeof b?.proposal !== 'string' || !ID_RE.test(b.proposal) || !(CHOICES as readonly string[]).includes(b.choice)) return 'malformed'
      const p = this.store.getGroupEvent(c.id, b.proposal)
      if (!p || p.kind !== 'proposal') return 'unknown-proposal'
      if (w.ts > json(p.body).closes || now > json(p.body).closes + MAX_SKEW_MS) return 'voting-closed'
      if (!json(p.meta ?? '[]').includes(author)) return 'not-eligible'
    } else return 'malformed'
    if (!this.store.addGroupEvent({ community: c.id, id: w.id, kind: w.kind, author, ts: w.ts, body: w.body, sig: w.sig, meta })) return 'duplicate'
    this.emit('event', { community: c.id, id: w.id, kind: w.kind, author, ts: w.ts })
    return null
  }

  private async make (community: string, kind: Kind, body: string): Promise<Wire> {
    const id = randomUUID()
    const ts = Date.now()
    return { v: 1, community, kind, id, ts, body, sig: await signBytes(this.key, canon(GROUP_DOMAIN, [this.self, community, kind, id, String(ts)], body)) }
  }

  private async broadcast (members: string[], w: Wire): Promise<Delivery> {
    const targets = members.filter((m) => m !== this.self)
    const data = Buffer.from(JSON.stringify(w))
    const res = await Promise.allSettled(targets.map(async (m) => {
      const s = await this.node.dialProtocol(peerIdFromString(m), GROUP_PROTOCOL, { runOnLimitedConnection: true, signal: AbortSignal.timeout(8000) })
      s.send(data)
      await s.close()
    }))
    return { delivered: res.filter((r) => r.status === 'fulfilled').length, failed: targets.filter((_, i) => res[i].status === 'rejected') }
  }

  private joined (id: string): CommunityRow {
    const c = this.store.getCommunity(id)
    if (!c || c.state !== 'joined') throw new Error('not a member of this community')
    return c
  }

  private members (list: unknown): string[] {
    if (!Array.isArray(list) || !list.every(isPeerId)) throw new Error('members must be peer IDs')
    const all = [...new Set([this.self, ...list])]
    if (all.length > MAX_MEMBERS) throw new Error(`a community has at most ${MAX_MEMBERS} members`)
    return all
  }

  async create (name: unknown, members: unknown): Promise<{ community: CommunityRow } & Delivery> {
    const n = cleanLine(name, 60)
    if (!n) throw new Error('name must be 1-60 characters without control characters')
    const c: CommunityRow = { id: randomBytes(8).toString('hex'), owner: this.self, name: n, seq: 1, members: this.members(members), state: 'joined', updated: Date.now() }
    this.store.putCommunity(c)
    return { community: c, ...await this.broadcast(c.members, await this.make(c.id, 'roster', JSON.stringify({ name: c.name, seq: c.seq, members: c.members }))) }
  }

  /** Owner only. Removed members also get the new roster so they learn they were removed. */
  async setMembers (id: string, members: unknown): Promise<{ community: CommunityRow } & Delivery> {
    const old = this.joined(id)
    if (old.owner !== this.self) throw new Error('only the owner can change membership')
    const c: CommunityRow = { ...old, seq: old.seq + 1, members: this.members(members), updated: Date.now() }
    this.store.putCommunity(c)
    return { community: c, ...await this.broadcast([...new Set([...old.members, ...c.members])], await this.make(id, 'roster', JSON.stringify({ name: c.name, seq: c.seq, members: c.members }))) }
  }

  join (id: string): void {
    const c = this.store.getCommunity(id)
    if (!c || c.state !== 'invited') throw new Error('no pending invitation')
    this.store.putCommunity({ ...c, state: 'joined', updated: Date.now() })
  }

  leave (id: string): void {
    const c = this.store.getCommunity(id)
    if (!c) throw new Error('unknown community')
    this.store.putCommunity({ ...c, state: 'left', updated: Date.now() })
  }

  private async emitOwn (c: CommunityRow, kind: Kind, body: string): Promise<{ id: string } & Delivery> {
    const w = await this.make(c.id, kind, body)
    const bad = this.apply(c, this.self, w, Date.now())
    if (bad) throw new Error(bad === 'malformed' ? `invalid ${kind}` : bad)
    return { id: w.id, ...await this.broadcast(c.members, w) }
  }

  async post (id: string, text: unknown): Promise<{ id: string } & Delivery> {
    return this.emitOwn(this.joined(id), 'msg', typeof text === 'string' ? text : '')
  }

  async propose (id: string, title: unknown, text: unknown, durationMs: unknown): Promise<{ id: string } & Delivery> {
    const ms = Number(durationMs)
    if (!Number.isFinite(ms)) throw new Error('invalid voting period')
    return this.emitOwn(this.joined(id), 'proposal', JSON.stringify({ title, text: text ?? '', closes: Date.now() + Math.round(ms) }))
  }

  async vote (id: string, proposal: unknown, choice: unknown): Promise<{ id: string } & Delivery> {
    return this.emitOwn(this.joined(id), 'vote', JSON.stringify({ proposal, choice }))
  }

  messages (id: string, limit = 200): Array<{ id: string, author: string, ts: number, text: string, own: boolean }> {
    return this.store.listGroupEvents(id, 'msg', limit).map((e) => ({ id: e.id, author: e.author, ts: e.ts, text: e.body, own: e.author === this.self }))
  }

  proposals (id: string): Array<{ id: string, author: string, ts: number, title: string, text: string, closes: number, open: boolean, myVote: Choice | null, tally: Tally }> {
    const votes = this.store.listGroupEvents(id, 'vote', 10_000).map((v) => ({ author: v.author, ts: v.ts, id: v.id, ...json(v.body) as { proposal: string, choice: string } }))
    const now = Date.now()
    return this.store.listGroupEvents(id, 'proposal', 100).map((p) => {
      const b = json(p.body)
      const mine = votes.filter((v) => v.proposal === p.id)
      const t = tally(json(p.meta ?? '[]'), mine)
      const me = mine.filter((v) => v.author === this.self).sort((a, z) => z.ts - a.ts)[0]
      return { id: p.id, author: p.author, ts: p.ts, title: b.title, text: b.text, closes: b.closes, open: now <= b.closes, myVote: (me?.choice as Choice) ?? null, tally: t }
    }).reverse()
  }

  private drop (peer: string, reason: string): void { this.emit('dropped', { peer, reason }) }
}

function parse (buf: Buffer): Wire | null {
  try {
    const o = JSON.parse(buf.toString('utf8'))
    if (o?.v !== 1 || typeof o.community !== 'string' || typeof o.kind !== 'string' || typeof o.id !== 'string' || typeof o.ts !== 'number' ||
        typeof o.body !== 'string' || typeof o.sig !== 'string') return null
    if (!COMMUNITY_RE.test(o.community) || !(KINDS as readonly string[]).includes(o.kind) || !ID_RE.test(o.id)) return null
    if (!Number.isFinite(o.ts) || o.sig.length > 128 || Buffer.byteLength(o.body) > MAX_BODY_BYTES) return null
    return o as Wire
  } catch { return null }
}
