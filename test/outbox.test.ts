import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { after, describe, it } from 'node:test'
import { MSG_PROTOCOL, ReplayGuard, signMessage } from '../src/messaging.js'
import { OUTBOX_TTL_MS } from '../src/outbox.js'
import { startFrenet, type FrenetNode } from '../src/node.js'

const L = ['/ip4/127.0.0.1/tcp/0']
const nodes: FrenetNode[] = []
const dirs: string[] = []
const track = async (o: Parameters<typeof startFrenet>[0] = { dataDir: ':memory:' }) => { const n = await startFrenet({ listen: L, mdns: false, ...o }); nodes.push(n); return n }
const tmp = (): string => { const d = mkdtempSync(join(tmpdir(), 'frenet-outbox-')); dirs.push(d); return d }
after(async () => { for (const n of nodes) await n.stop().catch(() => {}); for (const d of dirs) rmSync(d, { recursive: true, force: true }) })
const waitFor = async (fn: () => boolean, ms = 8000) => {
  const t = Date.now()
  while (!fn()) { if (Date.now() - t > ms) throw new Error('timeout'); await new Promise((r) => setTimeout(r, 25)) }
}
const id = (n: FrenetNode): string => n.libp2p.peerId.toString()

describe('store-and-forward (sender-side outbox)', () => {
  it('queues a direct message for an offline peer and delivers it when the peer reconnects', async () => {
    const dir = tmp()
    const a = await track()
    let b = await track({ dataDir: dir })
    const bid = b.libp2p.peerId
    await a.libp2p.dial(b.libp2p.getMultiaddrs()[0])
    await b.stop()
    await waitFor(() => a.libp2p.getConnections().length === 0)

    const r = await a.messaging.send(bid, 'while you were out')
    assert.equal(r.queued, true)
    assert.equal(a.outbox.pending(), 1)
    assert.equal(a.store.count().out, 1, 'the sender keeps its own copy right away')

    b = await track({ dataDir: dir })
    assert.equal(b.libp2p.peerId.toString(), bid.toString(), 'same identity after restart')
    const got: string[] = []
    b.messaging.on('message', (m) => got.push(`${m.peer}:${m.body}`))
    await a.libp2p.dial(b.libp2p.getMultiaddrs()[0])
    await waitFor(() => got.length === 1)
    assert.equal(got[0], `${id(a)}:while you were out`)
    await waitFor(() => a.outbox.pending() === 0)
    assert.equal(b.store.count().in, 1)
  })

  it('does not deliver the same queued message twice', async () => {
    const a = await track(); const b = await track()
    await a.libp2p.dial(b.libp2p.getMultiaddrs()[0])
    const got: string[] = []
    b.messaging.on('message', (m) => got.push(m.id))
    const r = await a.messaging.send(b.libp2p.peerId, 'once')
    await waitFor(() => got.length === 1)
    // a retry of an id the receiver already holds is accepted silently and changes nothing
    a.store.outboxAdd({ kind: 'msg', id: r.id, peer: id(b), ts: r.ts, payload: JSON.stringify({ v: 2, id: r.id, ts: r.ts, to: id(b), body: 'once', sig: a.store.list(id(b))[0].sig }), tries: 0, next: 0 })
    await a.outbox.flush(id(b), true)
    await new Promise((x) => setTimeout(x, 200))
    assert.equal(got.length, 1)
    assert.equal(b.store.count().in, 1)
    assert.equal(a.outbox.pending(), 0)
  })

  it('accepts an old signed message only when it is marked as a queued retry', async () => {
    const a = await track(); const b = await track()
    await a.libp2p.dial(b.libp2p.getMultiaddrs()[0])
    const old = Date.now() - 3 * 3600_000
    const send = async (mid: string, extra: object) => {
      const sig = await signMessage((a as any).privateKey ?? (a.messaging as any).key, id(a), id(b), mid, old, 'old news')
      const s = await a.libp2p.dialProtocol(b.libp2p.peerId, MSG_PROTOCOL)
      s.send(Buffer.from(JSON.stringify({ v: 2, id: mid, ts: old, to: id(b), body: 'old news', sig, ...extra })))
      await s.close()
    }
    const dropped: string[] = []
    b.messaging.on('dropped', (d) => dropped.push(d.reason))
    await send('live-old', {})
    await waitFor(() => dropped.includes('stale'))
    assert.equal(b.store.count().in, 0)
    await send('queued-old', { q: 1 })
    await waitFor(() => b.store.count().in === 1)
  })

  it('ReplayGuard: a longer age limit never allows future-dated messages', () => {
    const g = new ReplayGuard()
    assert.equal(g.check('p', 'a', Date.now() - 3600_000, Date.now(), OUTBOX_TTL_MS), 'ok')
    assert.equal(g.check('p', 'b', Date.now() + 3600_000, Date.now(), OUTBOX_TTL_MS), 'stale')
    assert.equal(g.check('p', 'c', Date.now() - OUTBOX_TTL_MS - 60_000, Date.now(), OUTBOX_TTL_MS), 'stale')
  })

  it('queues group chat for a member who is offline, and skips it if they were removed meanwhile', async () => {
    const dir = tmp()
    const a = await track(); const b = await track()
    let c = await track({ dataDir: dir })
    const cid = id(c)
    await a.libp2p.dial(b.libp2p.getMultiaddrs()[0]); await a.libp2p.dial(c.libp2p.getMultiaddrs()[0])
    const made = await a.groups.create('club', [id(b), cid])
    await waitFor(() => b.store.getCommunity(made.community.id) !== null && c.store.getCommunity(made.community.id) !== null)
    b.groups.join(made.community.id); c.groups.join(made.community.id)
    await c.stop()
    await waitFor(() => a.libp2p.getConnections().every((x) => x.remotePeer.toString() !== cid))

    const r = await a.groups.post(made.community.id, 'see you later')
    assert.deepEqual(r.failed, [cid])
    assert.equal(r.queued, 1)
    assert.equal(a.outbox.pending(cid), 1)

    c = await track({ dataDir: dir })
    await a.libp2p.dial(c.libp2p.getMultiaddrs()[0])
    await waitFor(() => c.store.listGroupEvents(made.community.id, 'msg').length === 1)
    assert.equal(c.groups.messages(made.community.id)[0].text, 'see you later')   // stored sealed, opened on read
    await waitFor(() => a.outbox.pending(cid) === 0)
  })

  it('a queued chat message is dropped, not delivered, once the member is no longer in the community', async () => {
    const a = await track(); const b = await track()
    await a.libp2p.dial(b.libp2p.getMultiaddrs()[0])
    const made = await a.groups.create('club', [id(b)])
    await waitFor(() => b.store.getCommunity(made.community.id) !== null)
    b.groups.join(made.community.id)
    // park a message for b as if b had been unreachable, then remove b from the roster
    const w = { v: 1, community: made.community.id, kind: 'msg', id: 'm-parked', ts: Date.now(), body: 'secret', sig: 'x' }
    a.store.outboxAdd({ kind: 'group', id: w.id, peer: id(b), ts: w.ts, payload: JSON.stringify(w), tries: 0, next: 0 })
    await a.groups.setMembers(made.community.id, [])
    await waitFor(() => b.store.getCommunity(made.community.id)?.state === 'removed')
    await a.outbox.flush(id(b), true)
    assert.equal(a.outbox.pending(id(b)), 0, 'entry cleared')
    assert.equal(b.store.listGroupEvents(made.community.id, 'msg').length, 0, 'never delivered')
  })

  it('expires entries older than the TTL', async () => {
    const a = await track()
    const stranger = (await track()).libp2p.peerId.toString()
    a.store.outboxAdd({ kind: 'msg', id: 'ancient', peer: stranger, ts: Date.now() - OUTBOX_TTL_MS - 1000, payload: '{}', tries: 0, next: 0 })
    await a.outbox.flush()
    assert.equal(a.outbox.pending(), 0)
  })
})

describe('TURN configuration for calls', () => {
  it('accepts turn: servers with credentials and reports them to the dashboard', async () => {
    const n = await track({ dataDir: ':memory:', iceServers: ['stun:s.example:3478', 'turn:t.example:3478'], turnUsername: 'u', turnCredential: 'c' })
    assert.deepEqual(n.iceServers, ['stun:s.example:3478', 'turn:t.example:3478'])
    assert.deepEqual(n.turn, { username: 'u', credential: 'c' })
  })
  it('refuses a turn: server without credentials, and credentials without a turn: server', async () => {
    await assert.rejects(startFrenet({ dataDir: ':memory:', listen: L, mdns: false, iceServers: ['turn:t.example:3478'] }), /turnUsername and turnCredential/)
    await assert.rejects(startFrenet({ dataDir: ':memory:', listen: L, mdns: false, iceServers: ['stun:s.example'], turnUsername: 'u', turnCredential: 'c' }), /no turn: ICE server/)
    await assert.rejects(startFrenet({ dataDir: ':memory:', listen: L, mdns: false, iceServers: ['turn:t.example', 'http://evil'], turnUsername: 'u', turnCredential: 'c' }), /invalid ICE server/)
  })
})
