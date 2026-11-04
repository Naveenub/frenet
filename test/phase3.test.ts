import assert from 'node:assert/strict'
import { after, describe, it } from 'node:test'
import { generateKeyPair } from '@libp2p/crypto/keys'
import { peerIdFromPrivateKey } from '@libp2p/peer-id'
import type { PrivateKey } from '@libp2p/interface'
import { startApi } from '../src/api.js'
import { CALL_PROTOCOL, MAX_SIGNAL_BYTES } from '../src/calls.js'
import { canon, signBytes } from '../src/channel.js'
import { GROUP_DOMAIN, tally, type Wire } from '../src/groups.js'
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
