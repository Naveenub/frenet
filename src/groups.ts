import { randomBytes, randomUUID } from 'node:crypto'
import { EventEmitter } from 'node:events'
import { OUTBOX_TTL_MS, type Outbox } from './outbox.js'
import { peerIdFromString } from '@libp2p/peer-id'
import type { Libp2p, PrivateKey } from '@libp2p/interface'
import { canon, ID_RE, isPeerId, MAX_SKEW_MS, readFrame, signBytes, verifyBytes } from './channel.js'
import { MAX_ENVELOPE_BYTES, open as openEnvelope, parseEnvelope, seal, sealedTextBytes, tagOf } from './groupcrypto.js'
import { RateLimiter, ReplayGuard } from './messaging.js'
import type { CommunityRow, GroupEventRow, Store } from './store.js'

export const GROUP_PROTOCOL = '/frenet/group/1.0.0'
export const GROUP_DOMAIN = 'frenet-group/v1'
export const GROUP_SYNC_PROTOCOL = '/frenet/group-sync/1.0.0'
export const MAX_MEMBERS = 100
export const MAX_TEXT_BYTES = 4096
const MAX_BODY_BYTES = 16 * 1024
const MAX_ENACT_BYTES = 256 * 1024 // an enactment carries its evidence: up to one ballot and one delegation per member
const MAX_GROUP_FRAME = 320 * 1024
const SYNC_MAX_EVENTS = 200
const SYNC_MAX_REQUEST = 64 * 1024
const SYNC_MAX_FRAME = 4 * 1024 * 1024
const SYNC_MIN_GAP_MS = 5 * 60_000
export const MIN_DISCUSSION_MS = 60_000
export const MAX_DISCUSSION_MS = 14 * 86_400_000
const MAX_COMMENT_BYTES = 2048
const MAX_PENDING_INVITES = 50
export const MIN_VOTE_MS = 60_000
export const MAX_VOTE_MS = 30 * 86_400_000
const COMMUNITY_RE = /^[a-f0-9]{16}$/
const KINDS = ['roster', 'msg', 'proposal', 'vote', 'delegate', 'comment', 'withdraw', 'enact'] as const
type Kind = typeof KINDS[number]
export const CHOICES = ['yes', 'no', 'abstain'] as const
export type Choice = typeof CHOICES[number]

export interface Wire { v: 1, community: string, kind: Kind, id: string, ts: number, body: string, sig: string, q?: 1 }
export interface GroupEvent { community: string, id: string, kind: Kind, author: string, ts: number }
/** `failed` = members not reached right now; `queued` = how many of those were put in the outbox for retry (chat and roster events only). */
export interface Delivery { delivered: number, failed: string[], queued: number }

/** A binding action. It only ever takes effect through an `enact` event whose evidence every node re-verifies. */
export type Action = { type: 'rename', name: string } | { type: 'members', members: string[] }
export type Status = 'discussion' | 'voting' | 'closed' | 'withdrawn' | 'enacted'

export interface Tally { yes: number, no: number, abstain: number, voted: number, delegated: number, electorate: number, quorum: boolean, outcome: 'passed' | 'rejected' | 'no-quorum' }
export interface TallyVote { author: string, ts: number, id: string, choice: string }
export interface TallyDelegation { author: string, ts: number, id: string, to: string | null }
export interface TallyOptions { delegations?: TallyDelegation[], supermajority?: boolean }

/**
 * One member, one vote; the latest ballot per member counts; only the electorate frozen into the proposal can vote.
 * A member with no ballot of their own is counted through their latest delegation, followed transitively to the first
 * member who did vote directly; a broken chain (cycle, non-member, nobody voted) counts as no ballot. A direct ballot
 * always overrides a delegation. Quorum is strictly more than half the electorate casting any effective ballot.
 * Advisory proposals pass on yes > no; binding ones (`supermajority`) need yes of at least two thirds of yes+no.
 * Pure function over signed events, so any node holding the same events computes the same result.
 */
export function tally (electorate: string[], votes: TallyVote[], opts: TallyOptions = {}): Tally {
  const el = new Set(electorate)
  const newer = (a: { ts: number, id: string }, b: { ts: number, id: string }): boolean => a.ts > b.ts || (a.ts === b.ts && a.id > b.id)
  const latest = new Map<string, TallyVote>()
  for (const v of votes) {
    if (!el.has(v.author) || !(CHOICES as readonly string[]).includes(v.choice)) continue
    const cur = latest.get(v.author)
    if (!cur || newer(v, cur)) latest.set(v.author, v)
  }
  const dl = new Map<string, TallyDelegation>()
  for (const d of opts.delegations ?? []) {
    if (!el.has(d.author)) continue
    const cur = dl.get(d.author)
    if (!cur || newer(d, cur)) dl.set(d.author, d)
  }
  const effective = new Map<string, Choice>()
  let delegated = 0
  for (const m of el) {
    const own = latest.get(m)
    if (own) { effective.set(m, own.choice as Choice); continue }
    const seen = new Set([m])
    let cur = m
    for (;;) {
      const to = dl.get(cur)?.to
      if (!to || !el.has(to) || seen.has(to)) break
      const theirs = latest.get(to)
      if (theirs) { effective.set(m, theirs.choice as Choice); delegated++; break }
      seen.add(to); cur = to
    }
  }
  const t = { yes: 0, no: 0, abstain: 0 }
  for (const c of effective.values()) t[c]++
  const quorum = effective.size * 2 > el.size
  const wins = opts.supermajority ? t.yes > 0 && t.yes * 3 >= (t.yes + t.no) * 2 : t.yes > t.no
  return { ...t, voted: effective.size, delegated, electorate: el.size, quorum, outcome: !quorum ? 'no-quorum' : wins ? 'passed' : 'rejected' }
}

export function cleanLine (s: unknown, max: number): string | null {
  if (typeof s !== 'string') return null
  const t = s.trim()
  return t.length >= 1 && t.length <= max && !/[\u0000-\u001f\u007f]/.test(t) ? t : null
}

/** Validate a binding action against the community owner (who can never be voted out of the roster). */
export function cleanAction (a: unknown, owner: string): Action | null {
  const o = a as any
  if (o?.type === 'rename') { const name = cleanLine(o.name, 60); return name ? { type: 'rename', name } : null }
  if (o?.type === 'members') {
    const m = o.members
    return Array.isArray(m) && m.length <= MAX_MEMBERS && m.every(isPeerId) && new Set(m).size === m.length && m.includes(owner) ? { type: 'members', members: [...m] } : null
  }
  return null
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
  /** Injectable clock (tests move it; production uses wall time). */
  clock: () => number = Date.now
  private timer: NodeJS.Timeout | null = null
  private syncLimiter = new RateLimiter(10, 0.2)
  private lastSync = new Map<string, number>()
  private onConnect = (evt: CustomEvent<{ toString(): string }>): void => { void this.syncWith(evt.detail.toString()).catch(() => {}) }

  constructor (private node: Libp2p, private store: Store, private key: PrivateKey, private outbox?: Outbox) {
    super()
    outbox?.register('group', async (peer, payload) => {
      const w = JSON.parse(payload) as Wire
      // A chat message is never delivered to someone who has left or been removed since it was queued.
      if (w.kind === 'msg') {
        const c = this.store.getCommunity(w.community)
        if (!c || c.state !== 'joined' || !c.members.includes(peer)) return
      }
      await this.send(peer, { ...w, q: 1 })
    })
  }

  private get self (): string { return this.node.peerId.toString() }

  async start (): Promise<void> {
    await this.node.handle(GROUP_PROTOCOL, async (stream, connection) => {
      const peer = connection.remotePeer.toString()
      try {
        if (!this.limiter.allow(peer)) { this.drop(peer, 'rate-limited'); stream.abort(new Error('rate limited')); return }
        const buf = await readFrame(stream, MAX_GROUP_FRAME)
        if (!buf) { this.drop(peer, 'oversize'); return }
        const w = parse(buf)
        if (!w) { this.drop(peer, 'malformed'); return }
        const reason = await this.accept(peer, w)
        if (reason) this.drop(peer, reason)
      } catch (err) {
        this.drop(peer, `error: ${(err as Error).message}`)
      }
    }, { maxInboundStreams: 64, maxOutboundStreams: 64, runOnLimitedConnection: true })
    await this.node.handle(GROUP_SYNC_PROTOCOL, async (stream, connection) => {
      const peer = connection.remotePeer.toString()
      try {
        if (!this.syncLimiter.allow(peer)) { this.drop(peer, 'sync-rate-limited'); stream.abort(new Error('rate limited')); return }
        const buf = await readFrame(stream, SYNC_MAX_REQUEST)
        if (!buf) { this.drop(peer, 'oversize'); return }
        const req = json(buf.toString('utf8'))
        const c = typeof req?.community === 'string' && COMMUNITY_RE.test(req.community) ? this.store.getCommunity(req.community) : null
        if (!c || c.state !== 'joined' || !c.members.includes(peer)) { this.drop(peer, 'sync-not-a-member'); stream.abort(new Error('not a member')); return }
        const have = new Set<string>((Array.isArray(req.have) ? req.have : []).filter((x: unknown): x is string => typeof x === 'string' && ID_RE.test(x)).slice(0, 500))
        // Only chat addressed to the requester (it carries a key wrapped for them) and not older than the outbox lifetime.
        const tag = tagOf(peer)
        const cutoff = this.clock() - OUTBOX_TTL_MS
        const events = this.store.listGroupEvents(c.id, 'msg', SYNC_MAX_EVENTS * 5)
          .filter((e) => e.ts >= cutoff && !have.has(e.id) && !!parseEnvelope(e.body)?.k[tag])
          .slice(-SYNC_MAX_EVENTS)
          .map((e) => ({ author: e.author, id: e.id, ts: e.ts, body: e.body, sig: e.sig }))
        stream.send(Buffer.from(JSON.stringify({ v: 1, events })))
        await stream.close()
      } catch (err) {
        this.drop(peer, `error: ${(err as Error).message}`)
      }
    }, { maxInboundStreams: 8, maxOutboundStreams: 8, runOnLimitedConnection: true })
    this.node.addEventListener('peer:connect', this.onConnect as EventListener)
    // Enforcement is not optional goodwill: the proposer's node enacts its own passed binding proposals; anyone else can too.
    this.timer = setInterval(() => { void this.sweep().catch(() => {}) }, 30_000)
    this.timer.unref()
  }

  async stop (): Promise<void> {
    if (this.timer) clearInterval(this.timer)
    this.timer = null
    this.node.removeEventListener('peer:connect', this.onConnect as EventListener)
    await this.node.unhandle(GROUP_SYNC_PROTOCOL)
    await this.node.unhandle(GROUP_PROTOCOL)
  }

  list (): CommunityRow[] { return this.store.listCommunities() }

  /** Verify and apply one inbound event from `author` (the connection's remote peer). Returns a drop reason, or null if accepted. */
  async accept (author: string, w: Wire): Promise<string | null> {
    const now = this.clock()
    if (!(await verifyBytes(author, canon(GROUP_DOMAIN, [author, w.community, w.kind, w.id, String(w.ts)], w.body), w.sig))) return 'bad-signature'
    const queued = w.q === 1
    if (queued && w.kind !== 'msg' && w.kind !== 'roster') return 'malformed'   // governance events keep the strict clock window: their deadlines depend on it
    if (queued && w.kind === 'msg' && this.store.getGroupEvent(w.community, w.id)) return null   // a retry of a message we already have
    const verdict = this.replay.check(author, `${w.community}:${w.id}`, w.ts, now, queued ? OUTBOX_TTL_MS : undefined)
    if (verdict !== 'ok') return verdict
    if (w.kind === 'roster') return this.applyRoster(author, w, now)
    const c = this.store.getCommunity(w.community)
    if (!c || c.state !== 'joined') return 'not-joined'
    if (!c.members.includes(author)) return 'not-a-member'
    return await this.apply(c, author, w, now)
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

  /** Decode a stored proposal. `opens` is when ballots start counting (after the discussion period). */
  private proposalOf (p: GroupEventRow): { title: string, text: string, closes: number, opens: number, action: Action | null } {
    const b = json(p.body)
    return { title: b.title, text: b.text, closes: b.closes, opens: Number.isSafeInteger(b.opens) ? b.opens : p.ts, action: b.action ?? null }
  }

  private enacted (community: string, proposal: string): boolean {
    return this.store.listGroupEvents(community, 'enact', 10_000).some((e) => json(e.body)?.proposal === proposal)
  }

  private withdrawn (community: string, p: GroupEventRow, closes: number): boolean {
    return this.store.listGroupEvents(community, 'withdraw', 10_000).some((e) => e.author === p.author && e.ts <= closes && json(e.body)?.proposal === p.id)
  }

  /** Ballots that count for a proposal: right proposal, valid choice, cast inside the voting window. Duplicates by id are merged. */
  private ballotsFor (p: GroupEventRow, rows: GroupEventRow[]): TallyVote[] {
    const { opens, closes } = this.proposalOf(p)
    const out = new Map<string, TallyVote>()
    for (const r of rows) {
      const b = json(r.body)
      if (b?.proposal === p.id && (CHOICES as readonly string[]).includes(b?.choice) && r.ts >= opens && r.ts <= closes) out.set(r.id, { author: r.author, ts: r.ts, id: r.id, choice: b.choice })
    }
    return [...out.values()]
  }

  private delegationsFor (p: GroupEventRow, rows: GroupEventRow[]): TallyDelegation[] {
    const { closes } = this.proposalOf(p)
    const out = new Map<string, TallyDelegation>()
    for (const r of rows) {
      const to = json(r.body)?.to
      if (r.ts <= closes && (to === null || typeof to === 'string')) out.set(r.id, { author: r.author, ts: r.ts, id: r.id, to })
    }
    return [...out.values()]
  }

  private tallyOf (p: GroupEventRow, votes: GroupEventRow[], delegations: GroupEventRow[]): Tally {
    return tally(json(p.meta ?? '[]'), this.ballotsFor(p, votes), { delegations: this.delegationsFor(p, delegations), supermajority: !!this.proposalOf(p).action })
  }

  /** Re-verify signed evidence carried by an enactment (never trusted just because the enacter sent it). */
  private async evidence (c: CommunityRow, kind: 'vote' | 'delegate', items: unknown): Promise<GroupEventRow[] | null> {
    if (!Array.isArray(items) || items.length > MAX_MEMBERS) return null
    const rows: GroupEventRow[] = []
    for (const it of items) {
      if (!isPeerId(it?.author) || typeof it.id !== 'string' || !ID_RE.test(it.id) || !Number.isFinite(it.ts) || typeof it.body !== 'string' ||
          Buffer.byteLength(it.body) > MAX_BODY_BYTES || typeof it.sig !== 'string' || it.sig.length > 128) return null
      if (!(await verifyBytes(it.author, canon(GROUP_DOMAIN, [it.author, c.id, kind, it.id, String(it.ts)], it.body), it.sig))) return null
      rows.push({ community: c.id, id: it.id, kind, author: it.author, ts: it.ts, body: it.body, sig: it.sig, meta: null })
    }
    return rows
  }

  private async apply (c: CommunityRow, author: string, w: Wire, now: number): Promise<string | null> {
    let meta: string | null = null
    let enact: { p: GroupEventRow, action: Action } | null = null
    if (w.kind === 'msg') {
      const env = parseEnvelope(w.body)
      if (env) {
        // Encrypted chat: it must carry a key for us and really open (a sender cannot park junk under a valid signature).
        const n = sealedTextBytes(env)
        if (n < 1 || n > MAX_TEXT_BYTES) return 'malformed'
        if (!env.k[tagOf(this.self)]) return 'not-addressed'
        if (openEnvelope(env, c.id, author, this.self, this.key) === null) return 'undecryptable'
      } else if (!w.body || Buffer.byteLength(w.body) > MAX_TEXT_BYTES) return 'malformed' // plaintext from a node that predates encryption
    } else if (w.kind === 'proposal') {
      const b = json(w.body)
      if (!cleanLine(b?.title, 80) || typeof b?.text !== 'string' || b.text.length > 2000 || !Number.isSafeInteger(b?.closes)) return 'malformed'
      const opens = b.opens === undefined ? w.ts : b.opens
      if (!Number.isSafeInteger(opens) || opens < w.ts || opens - w.ts > MAX_DISCUSSION_MS) return 'malformed'
      if (b.closes - opens < MIN_VOTE_MS || b.closes - opens > MAX_VOTE_MS || b.closes <= now) return 'malformed'
      if (b.action !== undefined) {
        // A binding proposal must name a valid action and leave members time to discuss it before ballots count.
        if (!cleanAction(b.action, c.owner) || opens - w.ts < MIN_DISCUSSION_MS) return 'malformed'
      }
      meta = JSON.stringify(c.members) // the electorate is frozen when the proposal is first seen
    } else if (w.kind === 'vote') {
      const b = json(w.body)
      if (typeof b?.proposal !== 'string' || !ID_RE.test(b.proposal) || !(CHOICES as readonly string[]).includes(b.choice)) return 'malformed'
      const p = this.store.getGroupEvent(c.id, b.proposal)
      if (!p || p.kind !== 'proposal') return 'unknown-proposal'
      const { opens, closes } = this.proposalOf(p)
      if (w.ts < opens) return 'voting-not-open'
      if (w.ts > closes || now > closes + MAX_SKEW_MS) return 'voting-closed'
      if (!json(p.meta ?? '[]').includes(author)) return 'not-eligible'
    } else if (w.kind === 'delegate') {
      const b = json(w.body)
      if (b?.to !== null && (!isPeerId(b?.to) || b.to === author || !c.members.includes(b.to))) return 'malformed'
    } else if (w.kind === 'comment') {
      const b = json(w.body)
      if (typeof b?.proposal !== 'string' || !ID_RE.test(b.proposal) || typeof b.text !== 'string' || !b.text.trim() || Buffer.byteLength(b.text) > MAX_COMMENT_BYTES || /[\u0000-\u0008\u000b-\u001f\u007f]/.test(b.text)) return 'malformed'
      if (this.store.getGroupEvent(c.id, b.proposal)?.kind !== 'proposal') return 'unknown-proposal'
    } else if (w.kind === 'withdraw') {
      const b = json(w.body)
      if (typeof b?.proposal !== 'string' || !ID_RE.test(b.proposal)) return 'malformed'
      const p = this.store.getGroupEvent(c.id, b.proposal)
      if (!p || p.kind !== 'proposal') return 'unknown-proposal'
      if (p.author !== author) return 'not-proposer'
      if (w.ts > this.proposalOf(p).closes || this.enacted(c.id, p.id)) return 'voting-closed'
    } else if (w.kind === 'enact') {
      const r = await this.checkEnact(c, w)
      if (typeof r === 'string') return r
      enact = r
    } else return 'malformed'
    if (!this.store.addGroupEvent({ community: c.id, id: w.id, kind: w.kind, author, ts: w.ts, body: w.body, sig: w.sig, meta })) return 'duplicate'
    if (enact) this.applyAction(c, enact.action)
    this.emit('event', { community: c.id, id: w.id, kind: w.kind, author, ts: w.ts })
    return null
  }

  /**
   * The enforcement rule. An enactment applies a binding proposal's action only if, by this node's own count over the
   * evidence plus every ballot it already holds, the voting period (plus clock-skew allowance) is over, quorum was met,
   * at least two thirds of yes+no said yes, the proposal was not withdrawn and has not been enacted before.
   */
  private async checkEnact (c: CommunityRow, w: Wire): Promise<string | { p: GroupEventRow, action: Action }> {
    const b = json(w.body)
    if (typeof b?.proposal !== 'string' || !ID_RE.test(b.proposal)) return 'malformed'
    const p = this.store.getGroupEvent(c.id, b.proposal)
    if (!p || p.kind !== 'proposal') return 'unknown-proposal'
    const { closes, action } = this.proposalOf(p)
    if (!action) return 'not-binding'
    if (w.ts <= closes + MAX_SKEW_MS) return 'voting-open'
    if (this.withdrawn(c.id, p, closes)) return 'withdrawn'
    if (this.enacted(c.id, p.id)) return 'already-enacted'
    const votes = await this.evidence(c, 'vote', b.ballots)
    const dels = await this.evidence(c, 'delegate', b.delegations)
    if (!votes || !dels) return 'bad-evidence'
    const local = (kind: string): GroupEventRow[] => this.store.listGroupEvents(c.id, kind, 10_000)
    const t = this.tallyOf(p, [...votes, ...local('vote')], [...dels, ...local('delegate')])
    if (t.outcome !== 'passed') return 'not-passed'
    const a = cleanAction(action, c.owner)
    return a ? { p, action: a } : 'malformed'
  }

  private applyAction (c: CommunityRow, action: Action): void {
    const now = this.clock()
    const fresh = this.store.getCommunity(c.id) ?? c
    const next: CommunityRow = { ...fresh, seq: fresh.seq + 1, updated: now }
    if (action.type === 'rename') next.name = action.name
    else {
      next.members = action.members
      next.state = action.members.includes(this.self) ? fresh.state : 'removed'
    }
    this.store.putCommunity(next)
    this.emit('community', c.id)
    // New members hold no roster yet and an invitation must be signed by the owner: the owner's node sends it,
    // but only because a verified vote said so (the owner cannot refuse the roster change itself, only delay an invitation).
    if (action.type === 'members' && fresh.owner === this.self) {
      const targets = [...new Set([...fresh.members, ...action.members])]
      void this.make(c.id, 'roster', JSON.stringify({ name: next.name, seq: next.seq, members: next.members })).then((w) => this.broadcast(targets, w)).catch(() => {})
    }
  }

  private async make (community: string, kind: Kind, body: string, at?: number): Promise<Wire> {
    const id = randomUUID()
    const ts = at ?? this.clock()
    return { v: 1, community, kind, id, ts, body, sig: await signBytes(this.key, canon(GROUP_DOMAIN, [this.self, community, kind, id, String(ts)], body)) }
  }

  private async send (member: string, w: Wire): Promise<void> {
    const s = await this.node.dialProtocol(peerIdFromString(member), GROUP_PROTOCOL, { runOnLimitedConnection: true, signal: AbortSignal.timeout(8000) })
    s.send(Buffer.from(JSON.stringify(w)))
    await s.close()
  }

  private async broadcast (members: string[], w: Wire): Promise<Delivery> {
    const targets = members.filter((m) => m !== this.self)
    const res = await Promise.allSettled(targets.map((m) => this.send(m, w)))
    const failed = targets.filter((_, i) => res[i].status === 'rejected')
    let queued = 0
    if (w.kind === 'msg' || w.kind === 'roster') {
      for (const m of failed) if (this.outbox?.enqueue('group', w.id, m, w.ts, JSON.stringify(w))) queued++
    }
    return { delivered: res.filter((r) => r.status === 'fulfilled').length, failed, queued }
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
    const c: CommunityRow = { id: randomBytes(8).toString('hex'), owner: this.self, name: n, seq: 1, members: this.members(members), state: 'joined', updated: this.clock() }
    this.store.putCommunity(c)
    return { community: c, ...await this.broadcast(c.members, await this.make(c.id, 'roster', JSON.stringify({ name: c.name, seq: c.seq, members: c.members }))) }
  }

  /** Owner only. Removed members also get the new roster so they learn they were removed. */
  async setMembers (id: string, members: unknown): Promise<{ community: CommunityRow } & Delivery> {
    const old = this.joined(id)
    if (old.owner !== this.self) throw new Error('only the owner can change membership')
    const c: CommunityRow = { ...old, seq: old.seq + 1, members: this.members(members), updated: this.clock() }
    this.store.putCommunity(c)
    return { community: c, ...await this.broadcast([...new Set([...old.members, ...c.members])], await this.make(id, 'roster', JSON.stringify({ name: c.name, seq: c.seq, members: c.members }))) }
  }

  join (id: string): void {
    const c = this.store.getCommunity(id)
    if (!c || c.state !== 'invited') throw new Error('no pending invitation')
    this.store.putCommunity({ ...c, state: 'joined', updated: this.clock() })
  }

  leave (id: string): void {
    const c = this.store.getCommunity(id)
    if (!c) throw new Error('unknown community')
    this.store.putCommunity({ ...c, state: 'left', updated: this.clock() })
  }

  private async emitOwn (c: CommunityRow, kind: Kind, body: string, at?: number): Promise<{ id: string } & Delivery> {
    const w = await this.make(c.id, kind, body, at)
    const bad = await this.apply(c, this.self, w, this.clock())
    if (bad) throw new Error(bad === 'malformed' ? `invalid ${kind}` : bad)
    return { id: w.id, ...await this.broadcast(c.members, w) }
  }

  async post (id: string, text: unknown): Promise<{ id: string } & Delivery> {
    const c = this.joined(id)
    const t = typeof text === 'string' ? text : ''
    if (!t || Buffer.byteLength(t) > MAX_TEXT_BYTES) throw new Error('invalid msg')
    // Sealed for the members named in this node's current roster; each of them can open it, nobody else can.
    return this.emitOwn(c, 'msg', seal(t, c.id, this.self, c.members))
  }

  /**
   * `discussionMs` delays when ballots start counting. A proposal with an `action` is binding: it needs at least
   * MIN_DISCUSSION_MS of discussion, quorum and a two-thirds majority, and is applied by an `enact` event.
   */
  async propose (id: string, title: unknown, text: unknown, durationMs: unknown, opts: { discussionMs?: unknown, action?: unknown } = {}): Promise<{ id: string } & Delivery> {
    const ms = Number(durationMs)
    const disc = Number(opts.discussionMs ?? 0)
    if (!Number.isFinite(ms)) throw new Error('invalid voting period')
    if (!Number.isFinite(disc) || disc < 0 || disc > MAX_DISCUSSION_MS) throw new Error('invalid discussion period')
    const c = this.joined(id)
    const ts = this.clock()
    const opens = ts + Math.round(disc)
    const body: Record<string, unknown> = { title, text: text ?? '', closes: opens + Math.round(ms) }
    if (disc > 0) body.opens = opens
    if (opts.action !== undefined) {
      const a = cleanAction(opts.action, c.owner)
      if (!a) throw new Error('invalid action: rename needs a name; members must be unique peer IDs and include the owner')
      if (disc < MIN_DISCUSSION_MS) throw new Error(`a binding proposal needs at least ${MIN_DISCUSSION_MS / 60_000} minute(s) of discussion`)
      body.action = a
    }
    return this.emitOwn(c, 'proposal', JSON.stringify(body), ts)
  }

  async vote (id: string, proposal: unknown, choice: unknown): Promise<{ id: string } & Delivery> {
    return this.emitOwn(this.joined(id), 'vote', JSON.stringify({ proposal, choice }))
  }

  /** Delegate your ballot to another member for every proposal you do not vote on yourself; `null` revokes. Latest wins. */
  async delegate (id: string, to: unknown): Promise<{ id: string } & Delivery> {
    return this.emitOwn(this.joined(id), 'delegate', JSON.stringify({ to: to ?? null }))
  }

  async comment (id: string, proposal: unknown, text: unknown): Promise<{ id: string } & Delivery> {
    return this.emitOwn(this.joined(id), 'comment', JSON.stringify({ proposal, text }))
  }

  /** Proposer only, before voting closes and before enactment. */
  async withdraw (id: string, proposal: unknown): Promise<{ id: string } & Delivery> {
    return this.emitOwn(this.joined(id), 'withdraw', JSON.stringify({ proposal }))
  }

  /** Publish the signed ballots and delegations as evidence; every member's node recounts them before applying the action. */
  async enact (id: string, proposal: unknown): Promise<{ id: string } & Delivery> {
    const c = this.joined(id)
    const p = typeof proposal === 'string' ? this.store.getGroupEvent(id, proposal) : null
    if (!p || p.kind !== 'proposal') throw new Error('unknown proposal')
    const latest = (kind: string, keep: (r: GroupEventRow) => boolean): GroupEventRow[] => {
      const m = new Map<string, GroupEventRow>()
      for (const r of this.store.listGroupEvents(id, kind, 10_000)) {
        const cur = m.get(r.author)
        if (keep(r) && (!cur || r.ts > cur.ts || (r.ts === cur.ts && r.id > cur.id))) m.set(r.author, r)
      }
      return [...m.values()]
    }
    const { closes } = this.proposalOf(p)
    const ballots = this.ballotsFor(p, this.store.listGroupEvents(id, 'vote', 10_000))
    const ids = new Set(ballots.map((v) => v.id))
    const pick = (r: GroupEventRow): { author: string, id: string, ts: number, body: string, sig: string } => ({ author: r.author, id: r.id, ts: r.ts, body: r.body, sig: r.sig })
    const body = JSON.stringify({
      proposal: p.id,
      ballots: latest('vote', (r) => ids.has(r.id)).map(pick),
      delegations: latest('delegate', (r) => r.ts <= closes).map(pick)
    })
    return this.emitOwn(c, 'enact', body)
  }

  /** Enact every passed, settled binding proposal this node authored and has not seen enacted. Returns the proposal ids it enacted. */
  async sweep (): Promise<string[]> {
    const done: string[] = []
    for (const c of this.store.listCommunities()) {
      if (c.state !== 'joined') continue
      for (const p of this.proposals(c.id)) {
        if (p.canEnact && p.author === this.self) {
          try { await this.enact(c.id, p.id); done.push(p.id) } catch { /* another member may have enacted it first */ }
        }
      }
    }
    return done
  }

  /** Chat, decrypted for this node. `encrypted: false` marks plaintext from a node that predates encryption. */
  messages (id: string, limit = 200): Array<{ id: string, author: string, ts: number, text: string, own: boolean, encrypted: boolean }> {
    type Msg = { id: string, author: string, ts: number, text: string, own: boolean, encrypted: boolean }
    return this.store.listGroupEvents(id, 'msg', limit).flatMap((e): Msg[] => {
      const env = parseEnvelope(e.body)
      if (!env) return [{ id: e.id, author: e.author, ts: e.ts, text: e.body, own: e.author === this.self, encrypted: false }]
      const text = openEnvelope(env, id, e.author, this.self, this.key)
      return text === null ? [] : [{ id: e.id, author: e.author, ts: e.ts, text, own: e.author === this.self, encrypted: true }]
    })
  }

  /**
   * History sync. Asks other members for chat that was addressed to us and that we do not hold (we were offline, and
   * so was its sender). Events are relayed with the author's original signature, which is checked as for a direct
   * delivery; only chat sealed to us is ever served, so a member added later gets nothing from before they joined.
   * Chat only: governance events stay on their strict clock window. Returns how many new messages arrived.
   */
  async sync (id: string, peers?: string[]): Promise<{ received: number, asked: number }> {
    const c = this.joined(id)
    const targets = (peers ?? c.members).filter((m) => m !== this.self && c.members.includes(m))
    const have = this.store.listGroupEvents(id, 'msg', 500).map((e) => e.id)
    const fresh = new Set<string>()   // several members may serve the same message; count it once
    const results = await Promise.allSettled(targets.map(async (m) => {
      const s = await this.node.dialProtocol(peerIdFromString(m), GROUP_SYNC_PROTOCOL, { runOnLimitedConnection: true, signal: AbortSignal.timeout(8000) })
      s.send(Buffer.from(JSON.stringify({ v: 1, community: id, have })))
      await s.close()
      const buf = await readFrame(s, SYNC_MAX_FRAME)
      const events = json(buf?.toString('utf8') ?? '')?.events
      if (!Array.isArray(events)) return
      for (const ev of events.slice(0, SYNC_MAX_EVENTS)) {
        if (!isPeerId(ev?.author) || ev.author === this.self || typeof ev.id !== 'string' || !ID_RE.test(ev.id) || !Number.isFinite(ev.ts) ||
            typeof ev.body !== 'string' || Buffer.byteLength(ev.body) > MAX_ENVELOPE_BYTES || typeof ev.sig !== 'string' || ev.sig.length > 128) continue
        const had = !!this.store.getGroupEvent(id, ev.id)
        if (await this.accept(ev.author, { v: 1, community: id, kind: 'msg', id: ev.id, ts: ev.ts, body: ev.body, sig: ev.sig, q: 1 }) === null && !had) fresh.add(ev.id)
      }
    }))
    void results
    return { received: fresh.size, asked: targets.length }
  }

  /** On a new connection, catch up with that peer for every community we both belong to (at most every few minutes per peer and community). */
  private async syncWith (peer: string): Promise<void> {
    const now = this.clock()
    for (const c of this.store.listCommunities()) {
      if (c.state !== 'joined' || !c.members.includes(peer) || peer === this.self) continue
      const k = `${c.id}:${peer}`
      if (now - (this.lastSync.get(k) ?? 0) < SYNC_MIN_GAP_MS) continue
      this.lastSync.set(k, now)
      await this.sync(c.id, [peer]).catch(() => {})
    }
  }

  comments (id: string, proposal: string): Array<{ id: string, author: string, ts: number, text: string, own: boolean }> {
    return this.store.listGroupEvents(id, 'comment', 10_000).flatMap((e) => {
      const b = json(e.body)
      return b?.proposal === proposal ? [{ id: e.id, author: e.author, ts: e.ts, text: String(b.text), own: e.author === this.self }] : []
    })
  }

  /** Current delegation of every member who has one, newest event per member (a revocation shows as `to: null` and is omitted). */
  delegations (id: string): { mine: string | null, current: Array<{ from: string, to: string, ts: number }> } {
    const latest = new Map<string, GroupEventRow>()
    for (const r of this.store.listGroupEvents(id, 'delegate', 10_000)) {
      const cur = latest.get(r.author)
      if (!cur || r.ts > cur.ts || (r.ts === cur.ts && r.id > cur.id)) latest.set(r.author, r)
    }
    const current = [...latest.values()].flatMap((r) => { const to = json(r.body)?.to; return typeof to === 'string' ? [{ from: r.author, to, ts: r.ts }] : [] })
    return { mine: current.find((d) => d.from === this.self)?.to ?? null, current }
  }

  proposals (id: string): Array<{
    id: string, author: string, ts: number, title: string, text: string, opens: number, closes: number, open: boolean, status: Status,
    action: Action | null, binding: boolean, canEnact: boolean, enactAfter: number, comments: number, myVote: Choice | null, tally: Tally
  }> {
    const c = this.store.getCommunity(id)
    const votes = this.store.listGroupEvents(id, 'vote', 10_000)
    const dels = this.store.listGroupEvents(id, 'delegate', 10_000)
    const commentCount = new Map<string, number>()
    for (const e of this.store.listGroupEvents(id, 'comment', 10_000)) { const k = json(e.body)?.proposal; commentCount.set(k, (commentCount.get(k) ?? 0) + 1) }
    const now = this.clock()
    return this.store.listGroupEvents(id, 'proposal', 100).map((p) => {
      const b = this.proposalOf(p)
      const action = c ? cleanAction(b.action, c.owner) : null
      const t = this.tallyOf(p, votes, dels)
      const me = this.ballotsFor(p, votes).filter((v) => v.author === this.self).sort((a, z) => z.ts - a.ts)[0]
      const enacted = this.enacted(id, p.id)
      const withdrawn = this.withdrawn(id, p, b.closes)
      const status: Status = enacted ? 'enacted' : withdrawn ? 'withdrawn' : now < b.opens ? 'discussion' : now <= b.closes ? 'voting' : 'closed'
      const enactAfter = b.closes + MAX_SKEW_MS
      return {
        id: p.id, author: p.author, ts: p.ts, title: b.title, text: b.text, opens: b.opens, closes: b.closes, open: now <= b.closes, status,
        action, binding: !!action, canEnact: !!action && status === 'closed' && now > enactAfter && t.outcome === 'passed', enactAfter,
        comments: commentCount.get(p.id) ?? 0, myVote: (me?.choice as Choice) ?? null, tally: t
      }
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
    if (!Number.isFinite(o.ts) || o.sig.length > 128 || Buffer.byteLength(o.body) > (o.kind === 'enact' ? MAX_ENACT_BYTES : o.kind === 'msg' ? MAX_ENVELOPE_BYTES : MAX_BODY_BYTES)) return null
    return o as Wire
  } catch { return null }
}
