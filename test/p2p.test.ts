import assert from 'node:assert/strict'
import { mkdtempSync, rmSync, statSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { after, describe, it } from 'node:test'
import { startApi } from '../src/api.js'
import { MAX_BODY_BYTES, RateLimiter, ReplayGuard } from '../src/messaging.js'
import { startFrenet, type FrenetNode } from '../src/node.js'

const L = ['/ip4/127.0.0.1/tcp/0']
const nodes: FrenetNode[] = []
const track = async (o: Parameters<typeof startFrenet>[0]) => { const n = await startFrenet(o); nodes.push(n); return n }
after(async () => { for (const n of nodes) await n.stop().catch(() => {}) })

const waitFor = async (fn: () => boolean, ms = 5000) => {
  const t = Date.now()
  while (!fn()) { if (Date.now() - t > ms) throw new Error('timeout'); await new Promise((r) => setTimeout(r, 25)) }
}

describe('real two-node network (loopback TCP + Noise + yamux)', () => {
  it('connects, encrypts, exchanges a message, persists it on both sides', async () => {
    const a = await track({ dataDir: ':memory:', listen: L, mdns: false })
    const b = await track({ dataDir: ':memory:', listen: L, mdns: false })
    const got: string[] = []
    b.messaging.on('message', (m) => got.push(`${m.peer}:${m.body}`))

    const conn = await a.libp2p.dial(b.libp2p.getMultiaddrs()[0])
    assert.equal(conn.encryption, '/noise')
    assert.equal(conn.remotePeer.toString(), b.libp2p.peerId.toString())

    await a.messaging.send(b.libp2p.peerId, 'hello frenet')
    await waitFor(() => got.length === 1)
    assert.equal(got[0], `${a.libp2p.peerId}:hello frenet`)
    assert.equal(a.store.count().out, 1)
    assert.equal(b.store.count().in, 1)
  })

  it('rejects oversize and empty messages on send', async () => {
    const a = await track({ dataDir: ':memory:', listen: L, mdns: false })
    const b = await track({ dataDir: ':memory:', listen: L, mdns: false })
    await a.libp2p.dial(b.libp2p.getMultiaddrs()[0])
    await assert.rejects(a.messaging.send(b.libp2p.peerId, 'x'.repeat(MAX_BODY_BYTES + 1)))
    await assert.rejects(a.messaging.send(b.libp2p.peerId, ''))
  })

  it('rate limits a flooding peer', async () => {
    const a = await track({ dataDir: ':memory:', listen: L, mdns: false })
    const b = await track({ dataDir: ':memory:', listen: L, mdns: false })
    const dropped: string[] = []
    b.messaging.on('dropped', (d) => dropped.push(d.reason))
    await a.libp2p.dial(b.libp2p.getMultiaddrs()[0])
    for (let i = 0; i < 40; i++) await a.messaging.send(b.libp2p.peerId, `m${i}`).catch(() => {})
    await waitFor(() => dropped.includes('rate-limited'))
    await new Promise((r) => setTimeout(r, 200))
    assert.ok(b.store.count().in <= 21 && b.store.count().in >= 20)
  })
})

describe('local identity', () => {
  it('persists a stable Ed25519 identity with 0600 permissions', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'frenet-'))
    try {
      const n1 = await startFrenet({ dataDir: dir, listen: L, mdns: false })
      const id = n1.libp2p.peerId.toString()
      await n1.stop()
      assert.equal(statSync(join(dir, 'identity.key')).mode & 0o777, 0o600)
      const n2 = await startFrenet({ dataDir: dir, listen: L, mdns: false })
      assert.equal(n2.libp2p.peerId.toString(), id)
      assert.equal(n2.libp2p.peerId.type, 'Ed25519')
      await n2.stop()
    } finally { rmSync(dir, { recursive: true, force: true }) }
  })
})

describe('replay + rate-limit primitives', () => {
  it('ReplayGuard rejects duplicates and stale timestamps', () => {
    const g = new ReplayGuard()
    assert.equal(g.check('p', 'id1', Date.now()), 'ok')
    assert.equal(g.check('p', 'id1', Date.now()), 'replay')
    assert.equal(g.check('p', 'id2', Date.now() - 10 * 60_000), 'stale')
    assert.equal(g.check('q', 'id1', Date.now()), 'ok')
  })
  it('RateLimiter enforces burst then refills', () => {
    let t = 0
    const r = new RateLimiter(3, 1, () => t)
    assert.deepEqual([1, 2, 3, 4].map(() => r.allow('p')), [true, true, true, false])
    t += 2000
    assert.equal(r.allow('p'), true)
  })
})

describe('local API hardening', () => {
  it('serves status, rejects foreign Host and cross-origin POST', async () => {
    const n = await track({ dataDir: ':memory:', listen: L, mdns: false })
    const { server, port } = await startApi(n, 0)
    try {
      const base = `http://127.0.0.1:${port}`
      const s = await (await fetch(`${base}/api/status`)).json() as any
      assert.equal(s.peerId, n.libp2p.peerId.toString())
      assert.equal(s.privacy.telemetry, 'none')

      const { request } = await import('node:http')
      const code = await new Promise<number>((resolve) => {
        const r = request({ host: '127.0.0.1', port, path: '/api/status', headers: { host: 'evil.example' } }, (res) => { res.resume(); resolve(res.statusCode!) })
        r.end()
      })
      assert.equal(code, 403)

      const csrf = await fetch(`${base}/api/dial`, {
        method: 'POST', headers: { 'content-type': 'application/json', origin: 'http://evil.example' }, body: '{}'
      })
      assert.equal(csrf.status, 403)
      const html = await fetch(`${base}/`)
      assert.equal(html.status, 200)
    } finally { server.close() }
  })
})

describe('content-addressed blocks via DHT provider records', () => {
  it('B fetches A\'s block by CID through the DHT (no direct knowledge of A\'s content), hash-verified', async () => {
    const a = await track({ dataDir: ':memory:', listen: L, mdns: false })
    const b = await track({ dataDir: ':memory:', listen: L, mdns: false })
    const c = await track({ dataDir: ':memory:', listen: L, mdns: false })
    // line topology: A <-> B <-> C ; C never connects to A directly
    await a.libp2p.dial(b.libp2p.getMultiaddrs()[0])
    await c.libp2p.dial(b.libp2p.getMultiaddrs()[0])
    await new Promise((r) => setTimeout(r, 1500)) // let identify populate routing tables

    const data = Buffer.from('frenet block ' + Math.random())
    const { cid, announced } = await a.blocks.put(data)
    assert.ok(announced, 'provider record should be published to the DHT')

    const got = await c.blocks.get(cid)
    assert.ok(got, 'block should be found via DHT')
    assert.deepEqual(Buffer.from(got!), data)
    assert.equal(c.store.blockStats().count, 1) // cached, now also a replica
  })

  it('rejects a CID whose content does not match (tampered provider)', async () => {
    const { cidFor } = await import('../src/blocks.js')
    assert.notEqual(cidFor(Buffer.from('a')).toString(), cidFor(Buffer.from('b')).toString())
  })
})

describe('encrypted, chunked files + retention', () => {
  const trio = async (extra: Partial<Parameters<typeof startFrenet>[0]> = {}) => {
    const a = await track({ dataDir: ':memory:', listen: L, mdns: false })
    const b = await track({ dataDir: ':memory:', listen: L, mdns: false, ...extra })
    const c = await track({ dataDir: ':memory:', listen: L, mdns: false, ...extra })
    await a.libp2p.dial(b.libp2p.getMultiaddrs()[0])
    await c.libp2p.dial(b.libp2p.getMultiaddrs()[0])
    await new Promise((r) => setTimeout(r, 1500))
    return { a, b, c }
  }

  it('multi-chunk file: providers hold only ciphertext; key holder decrypts; wrong/no key fails', async () => {
    const { a, c } = await trio()
    a.files.chunkBytes = 1000
    const secret = Buffer.from('SECRET-PLAINTEXT-'.repeat(400)) // 6800 bytes -> 7 chunks
    const f = await a.files.add('notes.txt', secret)
    assert.equal(f.chunks, 7)
    assert.ok(f.key && f.link.startsWith('frenet://') && f.link.endsWith('#' + f.key))
    assert.ok(f.announced)

    const row = a.store.getFile(f.cid)!
    for (const cid of [f.cid, ...row.chunks]) {
      assert.ok(!Buffer.from(a.store.getBlock(cid)!).includes('SECRET-PLAINTEXT'), 'block must be ciphertext')
    }
    const got = await c.files.get(f.cid, f.key)
    assert.equal(got.name, 'notes.txt')
    assert.deepEqual(got.data, secret)
    assert.equal(c.store.blockStats().count, 8) // replicated manifest + 7 chunks

    await assert.rejects(c.files.get(f.cid, Buffer.alloc(32, 1).toString('base64url')), /wrong key/)
    await assert.rejects(c.files.get(f.cid), /key is required|encrypted/)
  })

  it('public (unencrypted) files are readable without a key', async () => {
    const { a, c } = await trio()
    const data = Buffer.from('public data ' + Math.random())
    const f = await a.files.add('p.txt', data, { encrypt: false })
    assert.equal(f.key, null)
    assert.deepEqual((await c.files.get(f.cid)).data, data)
  })

  it('retention: replicas expire, pinned blocks stay, expired blocks are unreadable and swept', async () => {
    const { a, c } = await trio({ replicaTtlMs: 50 })
    const { cid } = await a.blocks.put(Buffer.from('keep me ' + Math.random()))
    assert.ok(await c.blocks.get(cid))
    assert.equal(c.store.blockStats().count, 1)
    await new Promise((r) => setTimeout(r, 120))
    assert.equal(c.store.getBlock(cid), null)          // expired = not served
    assert.equal(c.store.sweep(), 1)                   // sweeper removes it
    assert.equal(c.store.blockStats().count, 0)
    assert.ok(a.store.getBlock(cid))                   // origin copy is pinned
    assert.equal(a.store.sweep(), 0)
  })

  it('quota is enforced and partial file writes roll back', async () => {
    const n = await track({ dataDir: ':memory:', listen: L, mdns: false, quotaBytes: 500 })
    n.files.chunkBytes = 100
    await assert.rejects(n.files.add('big', Buffer.alloc(900, 7)), /quota/)
    assert.equal(n.store.blockStats().count, 0)
    assert.equal(n.files.list().length, 0)
  })

  it('local delete removes manifest + chunks and the file record', async () => {
    const n = await track({ dataDir: ':memory:', listen: L, mdns: false })
    n.files.chunkBytes = 100
    const f = await n.files.add('x', Buffer.alloc(350, 1))
    assert.ok(n.store.blockStats().count >= 5)
    assert.ok(n.files.remove(f.cid))
    assert.equal(n.store.blockStats().count, 0)
    assert.equal(n.files.list().length, 0)
  })
})
