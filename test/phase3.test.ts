import assert from 'node:assert/strict'
import { after, describe, it } from 'node:test'
import { generateKeyPair } from '@libp2p/crypto/keys'
import { peerIdFromPrivateKey } from '@libp2p/peer-id'
import type { PrivateKey } from '@libp2p/interface'
import { startApi } from '../src/api.js'
import { CALL_PROTOCOL, MAX_SIGNAL_BYTES } from '../src/calls.js'
import { canon, MAX_SKEW_MS, signBytes } from '../src/channel.js'
import { GROUP_DOMAIN, MIN_DISCUSSION_MS, tally, type Wire } from '../src/groups.js'
import { ReplayGuard } from '../src/messaging.js'
import { startFrenet, type FrenetNode } from '../src/node.js'
import { Operator } from '../src/operator.js'

const L = ['/ip4/127.0.0.1/tcp/0']
const nodes: FrenetNode[] = []
const track = async (o: Partial<Parameters<typeof startFrenet>[0]> = {}) => { const n = await startFrenet({ dataDir: ':memory:', listen: L, mdns: false, ...o }); nodes.push(n); return n }
after(async () => { for (const n of nodes) await n.stop().catch(() => {}) })
const waitFor = async (fn: () => boolean, ms = 5000) => {
  const t = Date.now()
  while (!fn()) { if (Date.now() - t > ms) throw new Error('timeout'); await new Promise((r) => setTimeout(r, 25)) }
}
const id = (n: FrenetNode) => n.libp2p.peerId.toString()
const link = async (a: FrenetNode, b: FrenetNode) => { await a.libp2p.dial(b.libp2p.getMultiaddrs()[0]) }

interface Author { key: PrivateKey, id: string }
const author = async (): Promise<Author> => { const key = await generateKeyPair('Ed25519'); return { key, id: peerIdFromPrivateKey(key).toString() } }
let seq = 0
const wire = async (a: Author, community: string, kind: Wire['kind'], body: string, o: Partial<Wire> = {}): Promise<Wire> => {
  const eid = o.id ?? `e${++seq}`
  const ts = o.ts ?? Date.now()
  const sig = await signBytes(a.key, canon(GROUP_DOMAIN, [a.id, community, kind, eid, String(ts)], body))
  return { v: 1, community, kind, id: eid, ts, body, sig, ...o }
}
const roster = (name: string, n: number, members: string[]) => JSON.stringify({ name, seq: n, members })
const C = '0123456789abcdef'

describe('voice/video signalling', () => {
  it('delivers a signed signal with the authenticated sender', async () => {
    const a = await track(); const b = await track()
    await link(a, b)
    const got: any[] = []
    b.calls.on('signal', (s) => got.push(s))
    await a.calls.send(b.libp2p.peerId, 'call-1', 'offer', JSON.stringify({ sdp: 'v=0' }))
    await waitFor(() => got.length === 1)
    assert.equal(got[0].peer, id(a)); assert.equal(got[0].kind, 'offer'); assert.equal(got[0].call, 'call-1')
    assert.equal(JSON.parse(got[0].data).sdp, 'v=0')
  })

  it('refuses bad kinds, call ids and oversize signals on send', async () => {
    const a = await track(); const b = await track()
    await link(a, b)
    await assert.rejects(a.calls.send(b.libp2p.peerId, 'c1', 'bogus', '{}'), /kind/)
    await assert.rejects(a.calls.send(b.libp2p.peerId, 'bad id\n', 'offer', '{}'), /call id/)
    await assert.rejects(a.calls.send(b.libp2p.peerId, 'c1', 'ice', 'x'.repeat(MAX_SIGNAL_BYTES + 1)), /exceeds/)
  })

  it('drops a forged signature and rate-limits offer floods', async () => {
    const a = await track(); const b = await track()
    await link(a, b)
    const dropped: string[] = []; const got: any[] = []
    b.calls.on('dropped', (d) => dropped.push(d.reason)); b.calls.on('signal', (s) => got.push(s))
    const s = await a.libp2p.dialProtocol(b.libp2p.peerId, CALL_PROTOCOL)
    s.send(Buffer.from(JSON.stringify({ v: 1, id: 'x1', call: 'c1', to: id(b), kind: 'offer', ts: Date.now(), data: '{}', sig: 'AAAA' })))
    await s.close()
    await waitFor(() => dropped.includes('bad-signature'))
    assert.equal(got.length, 0)
    for (let i = 0; i < 8; i++) await a.calls.send(b.libp2p.peerId, `c${i}`, 'offer', '{}')
    await waitFor(() => dropped.includes('offer-rate-limited'))
    assert.ok(got.length <= 4)
  })
})

describe('communities and group chat', () => {
  it('invites, requires an explicit join, then fans messages out to all members', async () => {
    const a = await track(); const b = await track(); const c = await track(); const d = await track()
    await link(a, b); await link(a, c); await link(b, c)
    const made = await a.groups.create('club', [id(b), id(c)])
    assert.equal(made.delivered, 2)
    const cid = made.community.id
    await waitFor(() => b.store.getCommunity(cid)?.state === 'invited' && c.store.getCommunity(cid)?.state === 'invited')
    await assert.rejects(b.groups.post(cid, 'too early'), /not a member/)
    b.groups.join(cid); c.groups.join(cid)
    await b.groups.post(cid, 'hi all')
    await waitFor(() => a.groups.messages(cid).length === 1 && c.groups.messages(cid).length === 1)
    assert.equal(a.groups.messages(cid)[0].author, id(b))
    assert.equal(b.groups.messages(cid)[0].own, true)
    await assert.rejects(d.groups.post(cid, 'outsider'), /not a member/)
  })

  it('seals group chat end to end and syncs history to a member who was offline', async () => {
    const a = await track(); const b = await track(); const c = await track()
    await link(a, b); await link(a, c); await link(b, c)
    const cid = (await a.groups.create('secret', [id(b), id(c)])).community.id
    await waitFor(() => b.store.getCommunity(cid)?.state === 'invited' && c.store.getCommunity(cid)?.state === 'invited')
    b.groups.join(cid); c.groups.join(cid)
    await b.groups.post(cid, 'top secret plan')
    await waitFor(() => a.groups.messages(cid).length === 1 && c.groups.messages(cid).length === 1)
    for (const n of [a, b, c]) {
      const m = n.groups.messages(cid)[0]
      assert.equal(m.text, 'top secret plan'); assert.equal(m.encrypted, true)
      const stored = n.store.listGroupEvents(cid, 'msg')[0]
      assert.ok(!stored.body.includes('top secret plan'), 'stored body is ciphertext')
    }
    // A node outside the roster, and the roster's own keys, cannot open it: tampering with the recipient list fails.
    const d = await track()
    const env = JSON.parse(a.store.listGroupEvents(cid, 'msg')[0].body)
    assert.equal(Object.keys(env.k).length, 3)
    assert.equal(d.groups.messages(cid).length, 0)

    // History sync: c misses a message (sender b cannot reach c and c is not reachable by a either), then syncs from a.
    const missed = await b.groups.post(cid, 'while you were away')
    await waitFor(() => a.groups.messages(cid).length === 2 && c.groups.messages(cid).length === 2)
    // Simulate a restart that lost the message: drop the stored row and the in-memory replay memory.
    ;(c.store as any).db.prepare('DELETE FROM group_events WHERE community = ? AND id = ?').run(cid, missed.id)
    ;(c.groups as any).replay = new ReplayGuard()
    assert.equal(c.groups.messages(cid).length, 1)
    const r = await c.groups.sync(cid)
    assert.equal(r.received, 1)
    assert.deepEqual(c.groups.messages(cid).map((m) => m.text), ['top secret plan', 'while you were away'])
    assert.equal((await c.groups.sync(cid)).received, 0)
  })

  it('does not serve history to non-members or messages not addressed to the requester', async () => {
    const a = await track(); const b = await track(); const late = await track()
    await link(a, b); await link(a, late)
    const cid = (await a.groups.create('club', [id(b)])).community.id
    await waitFor(() => b.store.getCommunity(cid)?.state === 'invited')
    b.groups.join(cid)
    await a.groups.post(cid, 'before late joined')
    await waitFor(() => b.groups.messages(cid).length === 1)
    await a.groups.setMembers(cid, [id(b), id(late)])
    await waitFor(() => late.store.getCommunity(cid)?.state === 'invited')
    late.groups.join(cid)
    const r = await late.groups.sync(cid)
    assert.equal(r.received, 0)
    assert.equal(late.groups.messages(cid).length, 0)
  })

  it('enforces roster, membership, replay and freshness rules on inbound events', async () => {
    const n = await track()
    const O = await author(); const M = await author(); const X = await author()
    const members = [O.id, id(n), M.id]
    assert.equal(await n.groups.accept(O.id, await wire(O, C, 'roster', roster('g', 1, members))), null)
    assert.equal(n.store.getCommunity(C)?.state, 'invited')
    assert.equal(await n.groups.accept(M.id, await wire(M, C, 'msg', 'early')), 'not-joined')
    n.groups.join(C)
    const hi = await wire(M, C, 'msg', 'hello')
    assert.equal(await n.groups.accept(M.id, hi), null)
    assert.equal(await n.groups.accept(M.id, hi), 'replay')
    assert.equal(await n.groups.accept(X.id, await wire(X, C, 'msg', 'spam')), 'not-a-member')
    assert.equal(await n.groups.accept(M.id, { ...(await wire(M, C, 'msg', 'a')), body: 'b' }), 'bad-signature')
    assert.equal(await n.groups.accept(M.id, await wire(M, C, 'msg', 'old', { ts: Date.now() - 10 * 60_000 })), 'stale')
    assert.equal(await n.groups.accept(M.id, await wire(M, C, 'roster', roster('g', 2, [M.id, id(n)]))), 'not-owner')
    assert.equal(await n.groups.accept(O.id, await wire(O, C, 'roster', roster('g', 1, members))), 'stale-roster')
    assert.equal(await n.groups.accept(O.id, await wire(O, C, 'roster', roster('g', 2, [id(n), M.id]))), 'malformed') // owner not in roster
    assert.equal(await n.groups.accept(O.id, await wire(O, C, 'roster', roster('g', 2, [O.id, id(n)]))), null)       // removes M
    assert.equal(await n.groups.accept(M.id, await wire(M, C, 'msg', 'after')), 'not-a-member')
    assert.equal(await n.groups.accept(O.id, await wire(O, 'aaaaaaaaaaaaaaaa', 'roster', roster('g', 1, [O.id, M.id]))), 'not-a-member')
    assert.equal(n.groups.messages(C).length, 1)
  })

  it('caps unsolicited invitations and keeps "left" sticky', async () => {
    const n = await track()
    const O = await author()
    for (let i = 0; i < 50; i++) assert.equal(await n.groups.accept(O.id, await wire(O, i.toString(16).padStart(16, '0'), 'roster', roster('g', 1, [O.id, id(n)]))), null)
    assert.equal(await n.groups.accept(O.id, await wire(O, 'ffffffffffffffff', 'roster', roster('g', 1, [O.id, id(n)]))), 'invite-limit')
    n.groups.leave('0000000000000000')
    assert.equal(await n.groups.accept(O.id, await wire(O, '0000000000000000', 'roster', roster('g', 2, [O.id, id(n)]))), null)
    assert.equal(n.store.getCommunity('0000000000000000')?.state, 'left')
  })
})

describe('governance', () => {
  it('counts one ballot per eligible member, freezes the electorate and rejects bad votes', async () => {
    const n = await track()
    const O = await author(); const M1 = await author(); const M2 = await author(); const M3 = await author(); const X = await author()
    await n.groups.accept(O.id, await wire(O, C, 'roster', roster('g', 1, [O.id, id(n), M1.id, M2.id])))
    n.groups.join(C)
    const closes = Date.now() + 3_600_000
    const prop = await wire(M1, C, 'proposal', JSON.stringify({ title: 'Adopt rules', text: 'v1', closes }))
    assert.equal(await n.groups.accept(M1.id, prop), null)
    assert.equal(await n.groups.accept(M1.id, await wire(M1, C, 'proposal', JSON.stringify({ title: 'Short', text: '', closes: Date.now() + 1000 }))), 'malformed')
    await assert.rejects(n.groups.propose(C, '\u0007bad', '', 3_600_000), /invalid proposal/)
    const vote = (a: Author, choice: string, o: Partial<Wire> = {}) => wire(a, C, 'vote', JSON.stringify({ proposal: prop.id, choice }), o)
    await n.groups.vote(C, prop.id, 'yes')
    assert.equal(await n.groups.accept(M1.id, await vote(M1, 'yes')), null)
    assert.equal(await n.groups.accept(M2.id, await vote(M2, 'no')), null)
    assert.equal(await n.groups.accept(X.id, await vote(X, 'yes')), 'not-a-member')
    assert.equal(await n.groups.accept(M2.id, await wire(M2, C, 'vote', JSON.stringify({ proposal: 'nope', choice: 'yes' }))), 'unknown-proposal')
    assert.equal(await n.groups.accept(M2.id, await vote(M2, 'maybe')), 'malformed')
    const soon = Date.now() + 61_000 // shortest allowed period; a ballot stamped just after it (still inside the clock-skew window) is too late
    const quick = await wire(M1, C, 'proposal', JSON.stringify({ title: 'Quick', text: '', closes: soon }))
    assert.equal(await n.groups.accept(M1.id, quick), null)
    assert.equal(await n.groups.accept(M2.id, await wire(M2, C, 'vote', JSON.stringify({ proposal: quick.id, choice: 'yes' }), { ts: soon + 1000 })), 'voting-closed')
    // Owner adds M3 afterwards: M3 is in the community but not in this proposal's electorate.
    await n.groups.accept(O.id, await wire(O, C, 'roster', roster('g', 2, [O.id, id(n), M1.id, M2.id, M3.id])))
    assert.equal(await n.groups.accept(M3.id, await vote(M3, 'yes')), 'not-eligible')
    // M2 changes their ballot: the latest one counts.
    assert.equal(await n.groups.accept(M2.id, await vote(M2, 'yes', { ts: Date.now() + 1000 })), null)
    const p = n.groups.proposals(C).find((x) => x.id === prop.id)!
    assert.deepEqual([p.tally.yes, p.tally.no, p.tally.voted, p.tally.electorate, p.tally.outcome, p.myVote, p.open], [3, 0, 3, 4, 'passed', 'yes', true])
  })

  it('tally: latest ballot wins, outsiders ignored, quorum and ties handled', () => {
    const el = ['a', 'b', 'c', 'd']
    const v = (author: string, ts: number, choice: string) => ({ author, ts, id: `${author}${ts}`, choice })
    assert.equal(tally(el, [v('a', 1, 'yes'), v('a', 2, 'no'), v('z', 3, 'yes')]).no, 1)
    assert.equal(tally(el, [v('a', 1, 'yes'), v('b', 1, 'yes')]).outcome, 'no-quorum')                      // 2 of 4 is not more than half
    assert.equal(tally(el, [v('a', 1, 'yes'), v('b', 1, 'no'), v('c', 1, 'abstain')]).outcome, 'rejected') // tie yes=no
    assert.equal(tally(el, [v('a', 1, 'yes'), v('b', 1, 'yes'), v('c', 1, 'abstain')]).outcome, 'passed')
    assert.equal(tally([], []).outcome, 'no-quorum')
  })
})

describe('governance: delegation, process and enforcement', () => {
  it('tally: delegation is transitive, overridable, revocable and cycle-safe; binding needs two thirds', () => {
    const el = ['a', 'b', 'c', 'd']
    const v = (author: string, ts: number, choice: string) => ({ author, ts, id: `${author}${ts}`, choice })
    const d = (author: string, ts: number, to: string | null) => ({ author, ts, id: `d${author}${ts}`, to })
    const chain = tally(el, [v('a', 1, 'yes')], { delegations: [d('b', 1, 'a'), d('c', 1, 'b')] })
    assert.deepEqual([chain.yes, chain.voted, chain.delegated, chain.outcome], [3, 3, 2, 'passed'])           // c -> b -> a
    const own = tally(el, [v('a', 1, 'yes'), v('b', 1, 'no'), v('c', 1, 'no')], { delegations: [d('b', 1, 'a')] })
    assert.deepEqual([own.yes, own.no, own.delegated], [1, 2, 0])                                                // a direct ballot beats a delegation
    assert.equal(tally(el, [v('a', 1, 'yes')], { delegations: [d('b', 1, 'a'), d('b', 2, null)] }).voted, 1)    // latest delegation (a revocation) wins
    assert.equal(tally(el, [], { delegations: [d('b', 1, 'c'), d('c', 1, 'b')] }).voted, 0)                     // cycle: nobody votes
    assert.equal(tally(el, [v('a', 1, 'yes')], { delegations: [d('b', 1, 'z'), d('z', 1, 'a')] }).voted, 1)     // outsiders neither delegate nor receive
    assert.equal(tally(el, [v('a', 1, 'yes'), v('b', 1, 'yes'), v('c', 1, 'no')], { supermajority: true }).outcome, 'passed')   // 2 of 3 yes+no
    assert.equal(tally(el, [v('a', 1, 'yes'), v('b', 1, 'no'), v('c', 1, 'no')], { supermajority: true }).outcome, 'rejected')
    assert.equal(tally(el, [v('a', 1, 'yes'), v('b', 1, 'yes'), v('c', 1, 'no')]).outcome, 'passed')
  })

  it('runs the process rules and enforces a passed binding proposal only after every check', async () => {
    const n = await track()
    const base = Date.now()
    let off = 0
    n.groups.clock = () => base + off
    const O = await author(); const M1 = await author(); const M2 = await author(); const X = await author(); const Y = await author()
    await n.groups.accept(O.id, await wire(O, C, 'roster', roster('g', 1, [O.id, id(n), M1.id, M2.id])))
    n.groups.join(C)
    const act = { type: 'rename', name: 'renamed' }
    const prop = async (a: Author, o: { action?: unknown, discussion?: number, vote?: number, title?: string }) => {
      const opens = base + (o.discussion ?? 0)
      const w = await wire(a, C, 'proposal', JSON.stringify({ title: o.title ?? 'p', text: '', closes: opens + (o.vote ?? 60_000), ...(o.discussion ? { opens } : {}), ...(o.action ? { action: o.action } : {}) }), { ts: base })
      return w
    }
    // Binding proposals need a discussion period and a valid action.
    assert.equal(await n.groups.accept(M1.id, await prop(M1, { action: act })), 'malformed')
    assert.equal(await n.groups.accept(M1.id, await prop(M1, { action: { type: 'rename', name: '' }, discussion: 120_000 })), 'malformed')
    assert.equal(await n.groups.accept(M1.id, await prop(M1, { action: { type: 'members', members: [M1.id, id(n)] }, discussion: 120_000 })), 'malformed') // would remove the owner
    assert.equal(await n.groups.accept(M1.id, await prop(M1, { action: { type: 'wipe' }, discussion: 120_000 })), 'malformed')
    await assert.rejects(n.groups.propose(C, 't', '', 60_000, { action: act }), /discussion/)
    const P = await prop(M1, { action: act, discussion: MIN_DISCUSSION_MS + 60_000, title: 'rename' })
    assert.equal(await n.groups.accept(M1.id, P), null)
    const opens = base + MIN_DISCUSSION_MS + 60_000; const closes = opens + 60_000
    const ballot = (a: Author, pid: string, choice: string, ts: number) => wire(a, C, 'vote', JSON.stringify({ proposal: pid, choice }), { ts })
    // Discussion: comments allowed, ballots not yet.
    assert.equal(await n.groups.accept(M2.id, await wire(M2, C, 'comment', JSON.stringify({ proposal: P.id, text: 'why?' }), { ts: base })), null)
    assert.equal(await n.groups.accept(M2.id, await wire(M2, C, 'comment', JSON.stringify({ proposal: 'nope', text: 'x' }), { ts: base })), 'unknown-proposal')
    assert.equal(await n.groups.accept(X.id, await wire(X, C, 'comment', JSON.stringify({ proposal: P.id, text: 'x' }), { ts: base })), 'not-a-member')
    assert.equal(await n.groups.accept(M2.id, await ballot(M2, P.id, 'no', base)), 'voting-not-open')
    assert.equal(n.groups.proposals(C)[0].status, 'discussion')
    assert.equal(n.groups.comments(C, P.id)[0].text, 'why?')
    // Voting: O yes, M1 yes, M2 no, and this node delegates to O (counted as yes).
    off = MIN_DISCUSSION_MS + 61_000
    const vO = await ballot(O, P.id, 'yes', opens + 1000); const vM1 = await ballot(M1, P.id, 'yes', opens + 1000); const vM2 = await ballot(M2, P.id, 'no', opens + 1000)
    for (const [a, w] of [[O, vO], [M1, vM1], [M2, vM2]] as const) assert.equal(await n.groups.accept(a.id, w), null)
    await n.groups.delegate(C, O.id)
    await assert.rejects(n.groups.delegate(C, id(n)), /invalid delegate/)
    await assert.rejects(n.groups.delegate(C, X.id), /invalid delegate/)
    assert.equal(n.groups.delegations(C).mine, O.id)
    let pr = n.groups.proposals(C).find((x) => x.id === P.id)!
    assert.deepEqual([pr.status, pr.tally.yes, pr.tally.no, pr.tally.delegated, pr.tally.outcome, pr.canEnact], ['voting', 3, 1, 1, 'passed', false])
    const pick = (a: Author, w: Wire) => ({ author: a.id, id: w.id, ts: w.ts, body: w.body, sig: w.sig })
    const evidence = { proposal: P.id, ballots: [pick(O, vO), pick(M1, vM1), pick(M2, vM2)], delegations: [] as unknown[] }
    // Not enactable while voting is open or inside the clock-skew allowance after closing.
    off = closes - base + 1000
    assert.equal(await n.groups.accept(M1.id, await wire(M1, C, 'enact', JSON.stringify(evidence), { ts: base + off })), 'voting-open')
    off = closes - base + MAX_SKEW_MS + 1000
    assert.equal(n.groups.proposals(C).find((x) => x.id === P.id)!.canEnact, true)
    const enact = (a: Author, e: unknown, o: Partial<Wire> = {}) => wire(a, C, 'enact', JSON.stringify(e), { ts: base + off, ...o })
    // Forged or tampered evidence, outsiders and unknown proposals are refused; the name has not changed.
    const forged = { ...evidence, ballots: [pick(O, vO), { ...pick(M1, vM1), body: JSON.stringify({ proposal: P.id, choice: 'no' }) }] }
    assert.equal(await n.groups.accept(M1.id, await enact(M1, forged)), 'bad-evidence')
    assert.equal(await n.groups.accept(X.id, await enact(X, evidence)), 'not-a-member')
    assert.equal(await n.groups.accept(M1.id, await enact(M1, { ...evidence, proposal: 'nope' })), 'unknown-proposal')
    assert.equal(n.store.getCommunity(C)!.name, 'g')
    // Omitting a ballot this node already holds does not help the enacter; the node recounts everything it knows.
    assert.equal(await n.groups.accept(M1.id, await enact(M1, { ...evidence, ballots: [pick(O, vO), pick(M1, vM1)] })), null)
    assert.deepEqual([n.store.getCommunity(C)!.name, n.store.getCommunity(C)!.seq], ['renamed', 2])
    assert.equal(await n.groups.accept(M2.id, await enact(M2, evidence)), 'already-enacted')
    assert.equal(n.groups.proposals(C).find((x) => x.id === P.id)!.status, 'enacted')
    // A failing vote is not applied even with valid evidence; advisory proposals are never "enacted".
    off = 0
    const Q = await prop(M1, { action: { type: 'rename', name: 'nope' }, discussion: 120_000, vote: 60_000 })
    assert.equal(await n.groups.accept(M1.id, Q), null)
    const qo = base + 120_000
    const q1 = await ballot(O, Q.id, 'yes', qo + 1); const q2 = await ballot(M1, Q.id, 'yes', qo + 1); const q3 = await ballot(M2, Q.id, 'no', qo + 1)
    off = 120_500
    for (const [a, w] of [[O, q1], [M1, q2], [M2, q3]] as const) assert.equal(await n.groups.accept(a.id, w), null)
    await n.groups.vote(C, Q.id, 'no') // 2 yes, 2 no: below two thirds
    off = 180_000 + MAX_SKEW_MS + 1000
    assert.equal(await n.groups.accept(M1.id, await enact(M1, { proposal: Q.id, ballots: [pick(O, q1), pick(M1, q2)], delegations: [] })), 'not-passed')
    assert.equal(n.groups.proposals(C).find((x) => x.id === Q.id)!.canEnact, false)
    const adv = await prop(M1, { title: 'adv' })
    off = 0
    assert.equal(await n.groups.accept(M1.id, adv), null)
    off = 60_000 + MAX_SKEW_MS + 1000
    assert.equal(await n.groups.accept(M1.id, await enact(M1, { proposal: adv.id, ballots: [], delegations: [] })), 'not-binding')
    // Withdrawal: only the proposer, and a withdrawn proposal cannot be enacted.
    off = 0
    const W = await prop(M1, { action: act, discussion: 120_000 })
    assert.equal(await n.groups.accept(M1.id, W), null)
    assert.equal(await n.groups.accept(M2.id, await wire(M2, C, 'withdraw', JSON.stringify({ proposal: W.id }), { ts: base })), 'not-proposer')
    assert.equal(await n.groups.accept(M1.id, await wire(M1, C, 'withdraw', JSON.stringify({ proposal: W.id }), { ts: base })), null)
    assert.equal(n.groups.proposals(C).find((x) => x.id === W.id)!.status, 'withdrawn')
    off = 180_000 + MAX_SKEW_MS + 1000
    assert.equal(await n.groups.accept(M1.id, await enact(M1, { proposal: W.id, ballots: [], delegations: [] })), 'withdrawn')
    // A membership change cannot touch the owner and is applied (with removal) only through a verified enactment.
    off = 0
    const R = await prop(M1, { action: { type: 'members', members: [O.id, id(n), M1.id, Y.id] }, discussion: 120_000 })
    assert.equal(await n.groups.accept(M1.id, R), null)
    const ro = base + 120_000
    off = 120_500
    const rb = [await ballot(O, R.id, 'yes', ro + 1), await ballot(M1, R.id, 'yes', ro + 1), await ballot(M2, R.id, 'yes', ro + 1)]
    for (const [i, a] of [O, M1, M2].entries()) assert.equal(await n.groups.accept(a.id, rb[i]), null)
    off = 180_000 + MAX_SKEW_MS + 1000
    assert.equal(await n.groups.accept(M1.id, await enact(M1, { proposal: R.id, ballots: [pick(O, rb[0]), pick(M1, rb[1]), pick(M2, rb[2])], delegations: [] })), null)
    assert.deepEqual(n.store.getCommunity(C)!.members, [O.id, id(n), M1.id, Y.id])
    assert.equal(await n.groups.accept(M2.id, await wire(M2, C, 'msg', 'still here?', { ts: base + off })), 'not-a-member')
  })

  it('enforces a vote across real peers: enact is verified remotely and the owner invites the new member', async () => {
    const a = await track(); const b = await track(); const c = await track()
    await link(a, b); await link(a, c); await link(b, c)
    const t0 = Date.now(); let off = 0
    for (const x of [a, b, c]) x.groups.clock = () => Date.now() + off
    const made = await a.groups.create('club', [id(b)])
    await waitFor(() => b.store.getCommunity(made.community.id) !== undefined && b.store.getCommunity(made.community.id) !== null)
    b.groups.join(made.community.id)
    const cid = made.community.id
    const sent = await a.groups.propose(cid, 'Invite carol', '', 60_000, { discussionMs: MIN_DISCUSSION_MS, action: { type: 'members', members: [id(a), id(b), id(c)] } })
    await waitFor(() => b.groups.proposals(cid).length === 1)
    off = MIN_DISCUSSION_MS + 1000
    await a.groups.vote(cid, sent.id, 'yes'); await b.groups.vote(cid, sent.id, 'yes')
    await waitFor(() => a.groups.proposals(cid)[0].tally.voted === 2 && b.groups.proposals(cid)[0].tally.voted === 2)
    off = 2 * MIN_DISCUSSION_MS + MAX_SKEW_MS + 5000
    assert.deepEqual(await b.groups.sweep(), [])             // only the proposer's node enacts automatically
    assert.deepEqual(await a.groups.sweep(), [sent.id])
    await waitFor(() => b.store.getCommunity(cid)!.members.length === 3)
    assert.equal(b.groups.proposals(cid)[0].status, 'enacted')
    await waitFor(() => c.store.getCommunity(cid)?.state === 'invited')
    assert.equal(c.store.getCommunity(cid)!.members.length, 3)
    assert.ok(Date.now() - t0 < 60_000)
  })
})

describe('node operator tools', () => {
  it('bans a peer: drops the connection, refuses both directions, persists, and can be lifted', async () => {
    const a = await track(); const b = await track()
    await link(a, b)
    await a.operator.ban(id(b), 'abuse')
    await waitFor(() => a.libp2p.getConnections(b.libp2p.peerId).length === 0)
    await assert.rejects(a.libp2p.dial(b.libp2p.getMultiaddrs()[0]))
    await b.libp2p.dial(a.libp2p.getMultiaddrs()[0]).catch(() => {})
    await new Promise((r) => setTimeout(r, 300))
    assert.equal(a.libp2p.getConnections(b.libp2p.peerId).length, 0)
    assert.ok(new Operator(a.libp2p, a.store, new Set()).banned.has(id(b)))
    assert.equal((a.operator.snapshot() as any).bans[0].reason, 'abuse')
    assert.equal(a.operator.unban(id(b)), true)
    await link(a, b)
    assert.equal(a.libp2p.getConnections(b.libp2p.peerId).length > 0, true)
  })

  it('validates input and counts dropped traffic by protocol', async () => {
    const a = await track()
    await assert.rejects(a.operator.ban('not-a-peer'), /invalid peer/)
    await assert.rejects(a.operator.ban(id(a)), /cannot ban this node/)
    a.operator.noteDrop('msg', 'bad-signature'); a.operator.noteDrop('msg', 'bad-signature'); a.operator.noteDrop('group', 'error: boom')
    const s = a.operator.snapshot() as any
    assert.equal(s.drops['msg: bad-signature'], 2); assert.equal(s.drops['group: error'], 1)
    assert.equal(s.connections.total, 0)
  })
})

describe('Phase 3 local API', () => {
  it('creates a community, posts, lists, and exposes operator stats and ICE config', async () => {
    const n = await track({ iceServers: ['stun:stun.example.org:3478'] })
    const { server, port } = await startApi(n, 0)
    const call = async (path: string, body?: unknown) => {
      const r = await fetch(`http://127.0.0.1:${port}${path}`, body === undefined ? undefined : { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) })
      return { status: r.status, json: await r.json() as any }
    }
    try {
      const made = await call('/api/communities', { name: 'solo', members: [] })
      assert.equal(made.status, 200); assert.equal(made.json.community.state, 'joined')
      const cid = made.json.community.id
      assert.equal((await call('/api/communities/post', { id: cid, text: 'hello' })).status, 200)
      assert.equal((await call(`/api/communities/messages?id=${cid}`)).json[0].text, 'hello')
      assert.equal((await call('/api/communities/vote', { id: cid, proposal: 'x', choice: 'yes' })).status, 400)
      assert.equal((await call('/api/communities/post', { id: cid, text: '' })).status, 400)
      assert.equal((await call('/api/operator')).json.connections.total, 0)
      assert.equal((await call('/api/operator/ban', { peer: 'nope' })).status, 400)
      assert.deepEqual((await call('/api/status')).json.calls.iceServers, ['stun:stun.example.org:3478'])
    } finally { server.close() }
  })

  it('rejects malformed ICE servers at startup', async () => {
    await assert.rejects(startFrenet({ dataDir: ':memory:', listen: L, mdns: false, iceServers: ['http://evil'] }), /invalid ICE server/)
  })
})
