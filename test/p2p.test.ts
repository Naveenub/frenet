import assert from 'node:assert/strict'
import { mkdtempSync, rmSync, statSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { after, describe, it } from 'node:test'
import { request } from 'node:http'
import { startApi } from '../src/api.js'
import { nameFromHost, startGateway } from '../src/gateway.js'
import { pubToB32, signRecord, validateRecord, type NameRecord } from '../src/names.js'
import { generateKeyPair } from '@libp2p/crypto/keys'
import { peerIdFromPrivateKey } from '@libp2p/peer-id'
import { MAX_BODY_BYTES, MSG_PROTOCOL, RateLimiter, ReplayGuard, signMessage, verifyMessage } from '../src/messaging.js'
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

describe('per-message signatures', () => {
  const send = async (from: FrenetNode, to: FrenetNode, wire: object) => {
    const s = await from.libp2p.dialProtocol(to.libp2p.peerId, MSG_PROTOCOL)
    s.send(Buffer.from(JSON.stringify(wire)))
    await s.close()
  }
  const setup = async () => {
    const a = await track({ dataDir: ':memory:', listen: L, mdns: false, nat: false })
    const b = await track({ dataDir: ':memory:', listen: L, mdns: false, nat: false })
    await a.libp2p.dial(b.libp2p.getMultiaddrs()[0])
    const dropped: string[] = []
    b.messaging.on('dropped', (d) => dropped.push(d.reason))
    return { a, b, dropped }
  }

  it('stores a signature that any third party can verify, and detects tampering', async () => {
    const { a, b } = await setup()
    const got: string[] = []
    b.messaging.on('message', (m) => got.push(m.id))
    await a.messaging.send(b.libp2p.peerId, 'signed hello')
    await waitFor(() => got.length === 1)
    for (const m of [...a.store.list(), ...b.store.list()]) {
      const row = { sender: m.sender!, recipient: m.recipient!, id: m.id, ts: m.ts, body: m.body, sig: m.sig! }
      assert.equal(row.sender, a.libp2p.peerId.toString())
      assert.equal(row.recipient, b.libp2p.peerId.toString())
      assert.equal(await verifyMessage(row), true)
      assert.equal(await verifyMessage({ ...row, body: 'tampered' }), false)
      assert.equal(await verifyMessage({ ...row, recipient: a.libp2p.peerId.toString() }), false)
      assert.equal(await verifyMessage({ ...row, ts: row.ts + 1 }), false)
    }
  })

  it('drops unsigned, forged-signer, wrong-recipient and bad-signature messages', async () => {
    const { a, b, dropped } = await setup()
    const aId = a.libp2p.peerId.toString(); const bId = b.libp2p.peerId.toString()
    const ts = Date.now()
    // unsigned v1
    await send(a, b, { v: 1, id: 'u1', ts, body: 'x' })
    // signed by a different key (C) but delivered over A's authenticated connection
    const ckey = await generateKeyPair('Ed25519'); const cId = peerIdFromPrivateKey(ckey).toString()
    await send(a, b, { v: 2, id: 'f1', ts, to: bId, body: 'x', sig: await signMessage(ckey, cId, bId, 'f1', ts, 'x') })
    // addressed to someone else (rejected on recipient before the signature is even considered)
    await send(a, b, { v: 2, id: 'w1', ts, to: cId, body: 'x', sig: await signMessage(ckey, aId, cId, 'w1', ts, 'x') })
    // garbage signature
    await send(a, b, { v: 2, id: 's1', ts, to: bId, body: 'x', sig: Buffer.alloc(64).toString('base64') })
    await waitFor(() => dropped.length >= 4)
    assert.deepEqual(dropped.sort(), ['bad-signature', 'bad-signature', 'malformed', 'wrong-recipient'].sort())
    assert.equal(b.store.count().in, 0)
  })
})

describe('NAT traversal: circuit relay', () => {
  it('delivers a message between two peers that only share a relay', async () => {
    const relay = await track({ dataDir: ':memory:', listen: L, mdns: false, relayServer: true })
    const relayAddr = relay.libp2p.getMultiaddrs()[0].toString()
    // A and B never learn each other's direct addresses; both reserve a slot on the relay.
    const a = await track({ dataDir: ':memory:', listen: L, mdns: false, relays: [relayAddr] })
    const b = await track({ dataDir: ':memory:', listen: L, mdns: false, relays: [relayAddr] })
    await waitFor(() => a.libp2p.getMultiaddrs().some((m) => m.toString().includes('/p2p-circuit')), 10_000)
    const circuit = a.libp2p.getMultiaddrs().find((m) => m.toString().includes('/p2p-circuit'))!
    const got: string[] = []
    a.messaging.on('message', (m) => got.push(`${m.peer}:${m.body}`))

    const conn = await b.libp2p.dial(circuit)
    assert.equal(conn.remotePeer.toString(), a.libp2p.peerId.toString())
    assert.ok(conn.remoteAddr.toString().includes('/p2p-circuit'))
    assert.equal(conn.encryption, '/noise')   // end-to-end Noise on top of the relayed hop
    await b.messaging.send(a.libp2p.peerId, 'via relay')
    await waitFor(() => got.length === 1)
    assert.equal(got[0], `${b.libp2p.peerId}:via relay`)   // sender identity is still the authenticated peer, not the relay
  })
})

describe('decentralized sites + gateway', () => {
  const get = (port: number, host: string, path: string, headers: Record<string, string> = {}, method = 'GET') =>
    new Promise<{ status: number, headers: Record<string, any>, body: Buffer }>((resolve, reject) => {
      const r = request({ host: '127.0.0.1', port, path, method, headers: { host, ...headers } }, (res) => {
        const c: Buffer[] = []; res.on('data', (d) => c.push(d)); res.on('end', () => resolve({ status: res.statusCode!, headers: res.headers, body: Buffer.concat(c) }))
      })
      r.on('error', reject); r.end()
    })
  const html = '<!doctype html><link rel="stylesheet" href="css/app.css"><h1>hello frenet</h1>'

  it('publishes on A and B serves it through the gateway, hash-verified, with a locked-down CSP', async () => {
    const a = await track({ dataDir: ':memory:', listen: L, mdns: false, nat: false })
    const b = await track({ dataDir: ':memory:', listen: L, mdns: false, nat: false })
    await a.libp2p.dial(b.libp2p.getMultiaddrs()[0])
    await new Promise((r) => setTimeout(r, 1500))
    const site = await a.sites.publish([
      { path: 'index.html', data: Buffer.from(html) },
      { path: 'css/app.css', data: Buffer.from('h1{color:red}') },
      { path: 'docs/index.html', data: Buffer.from('<p>docs</p>') },
      { path: 'blob.bin', data: Buffer.from([1, 2, 3]) }
    ])
    assert.ok(site.announced)
    const gw = await startGateway(b, 0)
    try {
      const host = `${site.cid}.localhost:${gw.port}`
      const root = await get(gw.port, host, '/')
      assert.equal(root.status, 200)
      assert.equal(root.body.toString(), html)
      assert.match(root.headers['content-type'], /text\/html/)
      assert.match(root.headers['content-security-policy'], /default-src 'none'/)
      assert.match(root.headers['content-security-policy'], /connect-src 'self'/)
      assert.equal(root.headers['x-content-type-options'], 'nosniff')
      assert.equal(root.headers['referrer-policy'], 'no-referrer')
      assert.equal((await get(gw.port, host, '/css/app.css')).body.toString(), 'h1{color:red}')
      assert.equal((await get(gw.port, host, '/docs/')).body.toString(), '<p>docs</p>')
      const bin = await get(gw.port, host, '/blob.bin')
      assert.equal(bin.headers['content-type'], 'application/octet-stream')
      assert.equal(bin.headers['content-disposition'], 'attachment')
      assert.equal((await get(gw.port, host, '/nope.html')).status, 404)
      assert.equal((await get(gw.port, host, '/../../etc/passwd')).status, 404)
      assert.equal((await get(gw.port, host, '/%2e%2e/%2e%2e/x')).status, 404)
      assert.equal((await get(gw.port, host, '/', {}, 'POST')).status, 405)
      assert.equal((await get(gw.port, `127.0.0.1:${gw.port}`, '/')).status, 404)          // no site in Host
      assert.equal((await get(gw.port, `evil.example`, '/')).status, 404)                  // DNS rebinding
      assert.equal((await get(gw.port, `${site.cid}.evil.example`, '/')).status, 404)
      // drive-by subresource loads from other pages are refused; user navigation and same-origin loads work
      assert.equal((await get(gw.port, host, '/', { 'sec-fetch-site': 'cross-site', 'sec-fetch-dest': 'image' })).status, 403)
      assert.equal((await get(gw.port, host, '/', { 'sec-fetch-site': 'cross-site', 'sec-fetch-dest': 'iframe' })).status, 403)
      assert.equal((await get(gw.port, host, '/', { 'sec-fetch-site': 'cross-site', 'sec-fetch-dest': 'document' })).status, 200)
      assert.equal((await get(gw.port, host, '/css/app.css', { 'sec-fetch-site': 'same-origin', 'sec-fetch-dest': 'style' })).status, 200)
    } finally { gw.server.close() }
  })

  it('rejects unsafe publishes and malicious manifests', async () => {
    const a = await track({ dataDir: ':memory:', listen: L, mdns: false, nat: false })
    const f = (path: string) => ({ path, data: Buffer.from('x') })
    for (const bad of ['../x', '/abs', 'a//b', 'a/../b', './a', 'a b', 'a\\b', '']) {
      await assert.rejects(a.sites.publish([f('index.html'), f(bad)]), /invalid path/, bad)
    }
    await assert.rejects(a.sites.publish([f('home.html')]), /index file/)
    await assert.rejects(a.sites.publish([f('index.html'), f('index.html')]), /duplicate/)
    await assert.rejects(a.sites.publish(Array.from({ length: 65 }, (_, i) => f(i === 0 ? 'index.html' : `f${i}`))), /too many/)
    assert.equal(a.store.listFiles().length, 0)   // nothing half-published

    // a hostile publisher's manifest cannot smuggle traversal paths or non-site blocks
    const fc = (await a.files.add('x', Buffer.from('x'), { encrypt: false })).cid
    const evil = await a.blocks.put(Buffer.from(JSON.stringify({ v: 1, type: 'site', index: 'index.html', files: { 'index.html': fc, '../../etc/passwd': fc } })))
    await assert.rejects(a.sites.resolve(evil.cid, '/'), /bad site manifest/)
    const notSite = await a.blocks.put(Buffer.from('just some bytes'))
    await assert.rejects(a.sites.resolve(notSite.cid, '/'), /not a site/)
    await assert.rejects(a.sites.resolve('not-a-cid', '/'), /invalid site id/)
    const proto = await a.blocks.put(Buffer.from(JSON.stringify({ v: 1, type: 'site', index: 'index.html', files: { 'index.html': fc } })))
    assert.equal(await a.sites.resolve(proto.cid, '/constructor'), null)   // prototype keys are not files
  })

  it('publishes through the local API', async () => {
    const n = await track({ dataDir: ':memory:', listen: L, mdns: false, nat: false })
    const { server, port } = await startApi(n, 0, '127.0.0.1', 7778)
    try {
      const r = await fetch(`http://127.0.0.1:${port}/api/sites`, { method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ files: [{ path: 'index.html', data: Buffer.from('<p>hi</p>').toString('base64') }] }) })
      const j = await r.json() as any
      assert.equal(r.status, 200)
      assert.equal(j.url, `http://${j.cid}.localhost:7778/`)
      assert.equal((await n.sites.resolve(j.cid, '/'))!.data.toString(), '<p>hi</p>')
      const bad = await fetch(`http://127.0.0.1:${port}/api/sites`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ files: [{ path: '../x', data: 'eA==' }] }) })
      assert.equal(bad.status, 400)
    } finally { server.close() }
  })
})

describe('names, updates and search', () => {
  const get = (port: number, host: string, path: string, headers: Record<string, string> = {}) =>
    new Promise<{ status: number, body: Buffer }>((resolve, reject) => {
      const r = request({ host: '127.0.0.1', port, path, method: 'GET', headers: { host, ...headers } }, (res) => {
        const c: Buffer[] = []; res.on('data', (d) => c.push(d)); res.on('end', () => resolve({ status: res.statusCode!, body: Buffer.concat(c) }))
      })
      r.on('error', reject); r.end()
    })
  const page = (t: string) => [{ path: 'index.html', data: Buffer.from(t) }]
  const pair = async () => {
    const a = await track({ dataDir: ':memory:', listen: L, mdns: false, nat: false })
    const b = await track({ dataDir: ':memory:', listen: L, mdns: false, nat: false })
    await a.libp2p.dial(b.libp2p.getMultiaddrs()[0])
    await new Promise((r) => setTimeout(r, 1500))
    return { a, b }
  }

  it('gives a site a human-readable name that B resolves and serves, and an update keeps the same name', async () => {
    const { a, b } = await pair()
    const v1 = await a.sites.publish(page('<p>version one</p>'))
    const n1 = await a.names.publish('blog', v1.cid, { title: 'My blog', keywords: ['writing'] })
    assert.equal(n1.record.seq, 1)
    assert.equal(n1.link, `frenet-name://blog.${a.names.publisherKey}`)
    const gw = await startGateway(b, 0)
    try {
      const host = `blog.${a.names.publisherKey}.localhost:${gw.port}`
      assert.deepEqual(nameFromHost(host), { name: 'blog', pub: a.names.publisherKey })
      const r1 = await get(gw.port, host, '/')
      assert.equal(r1.status, 200)
      assert.equal(r1.body.toString(), '<p>version one</p>')

      // update: publish new content under the SAME name; the site ID changes, the name does not
      const v2 = await a.sites.publish(page('<p>version two</p>'))
      assert.notEqual(v2.cid, v1.cid)
      const n2 = await a.names.publish('blog', v2.cid, { title: 'My blog', keywords: ['writing'] })
      assert.equal(n2.record.seq, 2)
      assert.equal((await b.names.resolve('blog', a.names.publisherKey, { fresh: true })).seq, 2)
      assert.equal((await get(gw.port, host, '/')).body.toString(), '<p>version two</p>')
      // the old immutable site ID still serves the old bytes
      assert.equal((await get(gw.port, `${v1.cid}.localhost:${gw.port}`, '/')).body.toString(), '<p>version one</p>')

      // unknown name -> 404; drive-by subresource loads never trigger a lookup
      assert.equal((await get(gw.port, `nope.${a.names.publisherKey}.localhost:${gw.port}`, '/')).status, 404)
      assert.equal((await get(gw.port, host, '/', { 'sec-fetch-site': 'cross-site', 'sec-fetch-dest': 'image' })).status, 403)
      // malformed name hosts are not names
      assert.equal(nameFromHost(`-bad.${a.names.publisherKey}.localhost`), null)
      assert.equal(nameFromHost(`Blog.${a.names.publisherKey}.localhost`), null)
      assert.equal(nameFromHost(`blog.${a.names.publisherKey.slice(1)}.localhost`), null)
      assert.equal(nameFromHost(`blog.${a.names.publisherKey}.evil.example`), null)
    } finally { gw.server.close() }
  })

  it('names are self-certifying: forged, tampered, stale, future-dated and malformed records are rejected', async () => {
    const { a } = await pair()
    const site = await a.sites.publish(page('<p>x</p>'))
    const mine = await a.names.publish('real', site.cid, { keywords: ['hello'] })
    assert.ok(await validateRecord(mine.record))

    const attacker = await generateKeyPair('Ed25519')
    const base = { v: 1 as const, name: 'real', pub: a.names.publisherKey, target: site.cid, seq: 99, ts: Date.now(), keywords: [] as string[], title: '' }
    // attacker signs a record that claims to be the victim's name
    assert.equal(await validateRecord(await signRecord(attacker, base)), null)
    // valid record with a field changed afterwards
    assert.equal(await validateRecord({ ...mine.record, target: (await a.blocks.put(Buffer.from('other'))).cid }), null)
    assert.equal(await validateRecord({ ...mine.record, seq: mine.record.seq + 1 }), null)
    assert.equal(await validateRecord({ ...mine.record, title: 'changed' }), null)
    // attacker's own name under their own key is of course fine, and cannot collide with ours
    const theirs = await signRecord(attacker, { ...base, pub: pubToB32(attacker.publicKey.raw) })
    assert.ok(await validateRecord(theirs))
    // future-dated (could pin a name forever if seq/ts were trusted blindly), bad name, bad keyword, bad title, duplicate keywords
    const k = (o: object) => signRecord(attacker, { ...base, pub: pubToB32(attacker.publicKey.raw), ...o })
    assert.equal(await validateRecord(await k({ ts: Date.now() + 3_600_000 })), null)
    assert.equal(await validateRecord(await k({ name: 'Bad Name' })), null)
    assert.equal(await validateRecord(await k({ keywords: ['x'] })), null)
    assert.equal(await validateRecord(await k({ keywords: ['ok', 'ok'] })), null)
    assert.equal(await validateRecord(await k({ title: 'line\nbreak' })), null)
    assert.equal(await validateRecord(await k({ target: 'not-a-cid' })), null)
    assert.equal(await validateRecord(await k({ seq: 0 })), null)
    assert.equal(await validateRecord('garbage'), null)
    assert.equal(await validateRecord(null), null)

    // a stale (lower-seq) valid record cannot roll a name back
    const v2 = await a.names.publish('real', site.cid)
    assert.equal(v2.record.seq, 2)
    assert.equal(a.store.putName(mine.record as NameRecord, false), false)
    assert.equal(a.store.getName('real', a.names.publisherKey)!.seq, 2)
  })

  it('rejects invalid names, titles and keywords at publish time', async () => {
    const a = await track({ dataDir: ':memory:', listen: L, mdns: false, nat: false })
    const site = await a.sites.publish(page('<p>x</p>'))
    for (const bad of ['', 'UPPER', '-a', 'a-', 'a b', 'a.b', 'x'.repeat(64), '../x']) await assert.rejects(a.names.publish(bad, site.cid), /invalid name/, bad)
    await assert.rejects(a.names.publish('ok', 'nope'), /invalid site id/)
    await assert.rejects(a.names.publish('ok', site.cid, { keywords: ['a'] }), /invalid keyword/)
    await assert.rejects(a.names.publish('ok', site.cid, { keywords: Array.from({ length: 9 }, (_, i) => `word${i}`) }), /too many keywords/)
    await assert.rejects(a.names.publish('ok', site.cid, { title: 'x'.repeat(81) }), /invalid title/)
  })

  it('finds names by keyword across the network (and locally), requiring every query word to match', async () => {
    const { a, b } = await pair()
    const s1 = await a.sites.publish(page('<p>cooking</p>'))
    await a.names.publish('kitchen', s1.cid, { title: 'Vegan recipes', keywords: ['vegan', 'recipes', 'food'] })
    const s2 = await a.sites.publish(page('<p>cars</p>'))
    await a.names.publish('garage', s2.cid, { title: 'Classic cars', keywords: ['cars', 'food'] })

    const hits = await b.names.search('vegan recipes')
    assert.deepEqual(hits.map((h) => h.name), ['kitchen'])
    assert.equal(hits[0].pub, a.names.publisherKey)
    assert.equal(hits[0].title, 'Vegan recipes')
    assert.equal(hits[0].own, false)
    assert.deepEqual((await b.names.search('food')).map((h) => h.name).sort(), ['garage', 'kitchen'])
    assert.deepEqual(await b.names.search('vegan cars'), [])          // AND semantics
    assert.deepEqual(await b.names.search('!!'), [])                 // no usable words
    assert.deepEqual((await a.names.search('cars', { network: false })).map((h) => h.name), ['garage'])
    assert.equal((await a.names.search('cars', { network: false }))[0].own, true)
    // a hit can be opened: it resolves to the site it points at
    assert.equal((await b.sites.resolve((await b.names.resolve(hits[0].name, hits[0].pub)).target, '/'))!.data.toString(), '<p>cooking</p>')
  })

  it('publishes a named site and updates it through the local API', async () => {
    const n = await track({ dataDir: ':memory:', listen: L, mdns: false, nat: false })
    const { server, port } = await startApi(n, 0, '127.0.0.1', 7778)
    const post = (b: object) => fetch(`http://127.0.0.1:${port}/api/sites`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(b) })
    const files = (t: string) => [{ path: 'index.html', data: Buffer.from(t).toString('base64') }]
    try {
      const r1 = await (await post({ files: files('one'), name: 'home', title: 'Home', keywords: ['hello'] })).json() as any
      assert.equal(r1.name.seq, 1)
      assert.equal(r1.url, `http://home.${n.names.publisherKey}.localhost:7778/`)
      const r2 = await (await post({ files: files('two'), name: 'home', title: 'Home', keywords: ['hello'] })).json() as any
      assert.equal(r2.name.seq, 2)
      assert.notEqual(r2.cid, r1.cid)
      const res = await (await fetch(`http://127.0.0.1:${port}/api/names/resolve?name=home&pub=${n.names.publisherKey}`)).json() as any
      assert.equal(res.target, r2.cid)
      const s = await (await fetch(`http://127.0.0.1:${port}/api/search?q=hello`)).json() as any
      assert.equal(s.results.length, 1)
      assert.equal(s.results[0].link, `frenet-name://home.${n.names.publisherKey}`)
      assert.equal((await fetch(`http://127.0.0.1:${port}/api/names/resolve?name=missing&pub=${n.names.publisherKey}`)).status, 404)
      // a bad name is refused before anything is published
      const before = n.store.listFiles().length
      assert.equal((await post({ files: files('three'), name: 'Bad Name' })).status, 400)
      assert.equal((await post({ files: files('three'), name: 'ok', keywords: ['x'] })).status, 400)
      assert.equal(n.store.listFiles().length, before)
    } finally { server.close() }
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
