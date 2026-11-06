import assert from 'node:assert/strict'
import { mkdtempSync, readdirSync, readFileSync, rmSync } from 'node:fs'
import { request } from 'node:http'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { after, describe, it } from 'node:test'
import { generateKeyPair } from '@libp2p/crypto/keys'
import { CID } from 'multiformats/cid'
import { startApi } from '../src/api.js'
import { cidFor, ContentBlocked } from '../src/blocks.js'
import { startGateway } from '../src/gateway.js'
import { keyFromLink, MAX_NOTE, MAX_REPORTS, normalizeTarget, verifyReport } from '../src/moderation.js'
import { startFrenet, type FrenetNode } from '../src/node.js'

const L = ['/ip4/127.0.0.1/tcp/0']
const nodes: FrenetNode[] = []
const dirs: string[] = []
const track = async (o: Partial<Parameters<typeof startFrenet>[0]> = {}) => { const n = await startFrenet({ dataDir: ':memory:', listen: L, mdns: false, nat: false, ...o }); nodes.push(n); return n }
after(async () => { for (const n of nodes) await n.stop().catch(() => {}); for (const d of dirs) rmSync(d, { recursive: true, force: true }) })
const waitFor = async (fn: () => boolean, ms = 5000) => {
  const t = Date.now()
  while (!fn()) { if (Date.now() - t > ms) throw new Error('timeout'); await new Promise((r) => setTimeout(r, 25)) }
}
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))
const id = (n: FrenetNode) => n.libp2p.peerId.toString()
/** Two connected nodes, given a moment for the DHT routing tables to fill. */
const pair = async (oa: Parameters<typeof track>[0] = {}, ob: Parameters<typeof track>[0] = {}) => {
  const a = await track(oa); const b = await track(ob)
  await a.libp2p.dial(b.libp2p.getMultiaddrs()[0])
  await sleep(1500)
  return { a, b }
}
const bytes = (s: string) => Buffer.from(s)
const cid = (s: string) => cidFor(bytes(s)).toString()
const page = (t: string) => [{ path: 'index.html', data: bytes(t) }, { path: 'css/app.css', data: bytes(`/* ${t} */`) }]
const get = (port: number, host: string, path = '/') =>
  new Promise<{ status: number, headers: Record<string, any>, body: Buffer }>((resolve, reject) => {
    const r = request({ host: '127.0.0.1', port, path, method: 'GET', headers: { host } }, (res) => {
      const c: Buffer[] = []; res.on('data', (d) => c.push(d)); res.on('end', () => resolve({ status: res.statusCode!, headers: res.headers, body: Buffer.concat(c) }))
    })
    r.on('error', reject); r.end()
  })

describe('re-announcing stored blocks', () => {
  it('makes content findable again from the local store, which provider records alone do not guarantee', async () => {
    const { a, b } = await pair()
    const data = bytes('stored but never announced')
    const c = a.blocks.putLocal(data)                       // in SQLite, but no provider record anywhere
    assert.equal(await b.blocks.get(c.toString()), null)    // so a peer cannot find it
    assert.deepEqual(await a.blocks.reannounce(), { total: 1, ok: 1 })
    assert.deepEqual(Buffer.from((await b.blocks.get(c.toString()))!), data)
    assert.equal(a.blocks.lastReannounce?.ok, 1)
  })

  it('does this by itself at start-up after a restart and then on a schedule', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'frenet-reann-')); dirs.push(dir)
    const data = bytes('survives a restart')
    // First life: publish while a peer is connected, then shut everything down (the DHT's own provider memory is lost with the process).
    const first = await track({ dataDir: dir }); const peer0 = await track()
    await first.libp2p.dial(peer0.libp2p.getMultiaddrs()[0]); await sleep(1500)
    const { cid: c } = await first.blocks.put(data)
    await first.stop(); await peer0.stop()
    // Second life: same data directory and identity, brand-new network state, and a peer that never saw the first announcement.
    const second = await track({ dataDir: dir, reannounceMs: 500, reannounceDelayMs: 4000 }); const peer = await track()
    await peer.libp2p.dial(second.libp2p.getMultiaddrs()[0]); await sleep(1500)
    assert.equal(await peer.blocks.get(c), null)            // before the start-up run nobody can find it
    await waitFor(() => second.blocks.lastReannounce !== null, 12_000)
    assert.deepEqual({ total: second.blocks.lastReannounce!.total, ok: second.blocks.lastReannounce!.ok }, { total: 1, ok: 1 })
    assert.deepEqual(Buffer.from((await peer.blocks.get(c))!), data)
    const firstRun = second.blocks.lastReannounce!.at
    await waitFor(() => second.blocks.lastReannounce!.at > firstRun, 8000)   // and again after reannounceMs
  })

  it('announces what is still held and nothing else: not blocked, not expired', async () => {
    const { a } = await pair()
    const kept = a.blocks.putLocal(bytes('keep'))
    a.blocks.putLocal(bytes('short lived'), 1)
    const doomed = a.blocks.putLocal(bytes('to be blocked'))
    await sleep(20)
    await a.moderation.block('cid', doomed.toString())
    assert.deepEqual(a.store.listBlockCids(), [kept.toString()])
    assert.deepEqual(await a.blocks.reannounce(), { total: 1, ok: 1 })
    assert.equal(await a.blocks.announce(doomed), false)
  })

  it('can be turned off, and rejects nonsense settings', async () => {
    await assert.rejects(startFrenet({ dataDir: ':memory:', listen: L, mdns: false, nat: false, reannounceMs: -1 }), /reannounceMs/)
    await assert.rejects(startFrenet({ dataDir: ':memory:', listen: L, mdns: false, nat: false, reannounceMs: Number.NaN }), /reannounceMs/)
    const a = await track({ reannounceMs: 0, reannounceDelayMs: 10 })
    a.blocks.putLocal(bytes('x'))
    await sleep(300)
    assert.equal(a.blocks.lastReannounce, null)
  })
})

describe('blocking content', () => {
  it('purges the local copy, refuses to store, fetch, announce or serve it, and keeps serving everything else', async () => {
    const { a, b } = await pair()
    const ok = await a.blocks.put(bytes('fine'))
    const bad = await a.blocks.put(bytes('abusive'))
    assert.ok(ok.announced && bad.announced)
    const { entry, purged } = await a.moderation.block('cid', bad.cid, 'abuse')
    assert.equal(purged, 1)
    assert.equal(entry.reason, 'abuse')
    assert.equal(a.store.hasBlock(bad.cid), false)
    assert.throws(() => a.blocks.putLocal(bytes('abusive')), ContentBlocked)
    await assert.rejects(a.blocks.put(bytes('abusive')), ContentBlocked)
    await assert.rejects(a.blocks.get(bad.cid), ContentBlocked)
    assert.equal(await a.blocks.announce(CID.parse(bad.cid)), false)
    // A peer that still has a provider record for it is told nothing, while unblocked content is served as before.
    assert.equal(await b.blocks.get(bad.cid), null)
    assert.deepEqual(Buffer.from((await b.blocks.get(ok.cid))!), bytes('fine'))
  })

  it('blocking a site removes its manifest, files and chunks, refuses re-publishing, and the gateway answers 451', async () => {
    const { a } = await pair()
    const keep = await a.files.add('keep.txt', bytes('unrelated'), { encrypt: false })
    const other = await a.sites.publish(page('other site'))
    const site = await a.sites.publish(page('bad site'))
    const name = await a.names.publish('blog', site.cid, { keywords: ['hello'] })
    const before = a.store.blockStats().count
    const gw = await startGateway(a, 0)
    try {
      assert.equal((await get(gw.port, `${site.cid}.localhost:${gw.port}`)).status, 200)

      const r = await a.moderation.block('cid', site.link, 'phishing')   // a frenet-site:// link is accepted as is
      assert.equal(r.purged, 5)                                     // manifest + 2 file manifests + 2 chunks
      assert.equal(r.entry.derived, 4)
      assert.equal(a.store.blockStats().count, before - 5)
      assert.deepEqual(a.store.listFiles().map((f) => f.cid).sort(), [keep.cid, ...Object.values((await a.sites.manifest(other.cid)).files)].sort())
      assert.deepEqual(a.names.list(), [])                          // the name that pointed at it is gone too
      await assert.rejects(a.names.publish('again', site.cid), ContentBlocked)
      await assert.rejects(a.sites.publish(page('bad site')), ContentBlocked)   // same bytes, same blocked chunks
      await assert.rejects(a.sites.resolve(site.cid, '/'), ContentBlocked)

      for (const host of [`${site.cid}.localhost:${gw.port}`, `blog.${name.record.pub}.localhost:${gw.port}`]) {
        const res = await get(gw.port, host)
        assert.equal(res.status, 451, host)
        assert.equal(res.headers['cache-control'], 'no-store')
        assert.match(res.body.toString(), /blocked by the operator/)
      }
      assert.equal((await get(gw.port, `${other.cid}.localhost:${gw.port}`)).status, 200)   // other sites are unaffected

      // Unblocking lifts the entry and everything it pulled in; the same site can be published again.
      assert.equal(a.moderation.unblock('cid', site.cid), true)
      assert.equal((await a.sites.publish(page('bad site'))).cid, site.cid)
      assert.equal((await get(gw.port, `${site.cid}.localhost:${gw.port}`)).status, 200)
      assert.deepEqual(a.moderation.list(), [])
    } finally { gw.server.close() }
  })

  it('a file block covers its chunks, and a single blocked file inside a site gives 451 for that file only', async () => {
    const { a } = await pair()
    const f = await a.files.add('pic.png', bytes('PIC'), { encrypt: false })
    await a.moderation.block('cid', `frenet://${f.cid}`)
    await assert.rejects(a.files.get(f.cid, null), ContentBlocked)
    await assert.rejects(a.files.add('pic.png', bytes('PIC'), { encrypt: false }), ContentBlocked)
    assert.equal(a.store.listFiles().length, 0)

    const site = await a.sites.publish([{ path: 'index.html', data: bytes('<p>ok</p>') }, { path: 'bad.png', data: bytes('BADPIC') }])
    const badFile = (await a.sites.manifest(site.cid)).files['bad.png']!
    const gw = await startGateway(a, 0)
    try {
      await a.moderation.block('cid', badFile)
      const host = `${site.cid}.localhost:${gw.port}`
      assert.equal((await get(gw.port, host, '/')).status, 200)
      assert.equal((await get(gw.port, host, '/bad.png')).status, 451)
    } finally { gw.server.close() }
  })

  it('blocking a publisher: its names stop resolving without any lookup, drop out of search, and its sites are purged', async () => {
    const { a, b } = await pair()
    const site = await a.sites.publish(page('their site'))
    const pub = a.names.publisherKey
    await a.names.publish('shop', site.cid, { title: 'Vegan shop', keywords: ['vegan'] })
    assert.equal((await b.names.resolve('shop', pub, { fresh: true })).target, site.cid)
    assert.equal((await b.sites.resolve(site.cid, '/'))!.path, 'index.html')    // b now holds replicas
    assert.equal((await b.names.search('vegan')).length, 1)
    const gw = await startGateway(b, 0)
    try {
      const r = await b.moderation.block('publisher', `frenet-name://shop.${pub}`, 'repeat abuse')   // a name link names the publisher
      assert.equal(r.entry.target, pub)
      // b only ever fetched index.html, so it holds 3 replicas (site manifest, that file's manifest, its chunk) and all 3 are purged.
      // The denylist is wider than what was held: the site manifest also names css/app.css, so that file is refused too.
      assert.equal(r.purged, 3)
      assert.equal(r.entry.derived, 4)
      assert.equal(b.store.blockStats().count, 0)
      assert.equal(b.moderation.isBlocked('cid', (await a.sites.manifest(site.cid)).files['css/app.css']!), true)
      await assert.rejects(b.names.resolve('shop', pub, { fresh: true }), ContentBlocked)
      await assert.rejects(b.names.resolve('anything', pub), ContentBlocked)
      await assert.rejects(b.blocks.get(site.cid), ContentBlocked)
      assert.deepEqual(await b.names.search('vegan'), [])       // the network is asked again, and the record is not kept
      assert.deepEqual(b.names.list(), [])
      assert.equal(b.reputation.score(id(a)) >= 0, true)        // a valid record that is merely blocked is not held against the peer
      const res = await get(gw.port, `shop.${pub}.localhost:${gw.port}`)
      assert.equal(res.status, 451)
      const t0 = Date.now()
      assert.equal((await get(gw.port, `never-published.${pub}.localhost:${gw.port}`)).status, 451)   // refused before any DHT lookup
      assert.ok(Date.now() - t0 < 1000)
    } finally { gw.server.close() }
  })

  it('blocking a name also blocks the site it currently points to', async () => {
    const { a, b } = await pair()
    const site = await a.sites.publish(page('named'))
    await a.names.publish('promo', site.cid)
    await b.names.resolve('promo', a.names.publisherKey)
    await b.moderation.block('name', `promo.${a.names.publisherKey}`)
    assert.equal(b.moderation.isBlocked('cid', site.cid), true)
    await assert.rejects(b.names.resolve('promo', a.names.publisherKey), ContentBlocked)
    // other names by the same publisher are not blocked
    await a.names.publish('fine', (await a.sites.publish(page('fine'))).cid)
    assert.equal((await b.names.resolve('fine', a.names.publisherKey)).name, 'fine')
  })

  it('validates what it is given, drops file keys, and will not block its own publisher key', async () => {
    const a = await track()
    const c = cid('x')
    assert.equal(normalizeTarget('cid', `frenet://${c}#SECRETKEY`), c)
    assert.equal(normalizeTarget('cid', `  frenet-site://${c}/index.html `), c)
    assert.equal(normalizeTarget('publisher', a.names.publisherKey), a.names.publisherKey)
    for (const [kind, bad] of [['cid', 'nope'], ['cid', ''], ['cid', 42], ['name', 'Bad.Name'], ['name', `x.${a.names.publisherKey.slice(1)}`], ['publisher', 'short'], ['publisher', `${c}`]] as const) {
      assert.throws(() => normalizeTarget(kind, bad), /invalid|target/, `${kind} ${String(bad)}`)
    }
    await assert.rejects(a.moderation.block('weird', c), /kind must be/)
    await assert.rejects(a.moderation.block('publisher', a.names.publisherKey), /own publisher/)
    assert.equal(a.moderation.unblock('cid', c), false)   // nothing to lift is not an error
  })
})

describe('content reports', () => {
  it('files a signed report that anyone can verify, and any alteration is detected', async () => {
    const a = await track(); const other = await track()
    const c = cid('evil')
    const r = await a.moderation.report({ kind: 'cid', target: `frenet://${c}#SECRETKEY`, category: 'malware', note: 'drops\na payload\u0000' })
    assert.equal(r.status, 'open')
    assert.equal(r.target, c)
    assert.equal(JSON.stringify(r).includes('SECRETKEY'), false)
    assert.equal(r.note, 'drops a payload')                 // control characters never reach storage or the signed bytes
    assert.equal(r.reporter, id(a))
    assert.equal(await verifyReport(r), true)
    assert.equal(await verifyReport({ ...r, status: 'dismissed' }), true)   // status is local workflow, not signed
    assert.equal(await verifyReport(JSON.parse(JSON.stringify(r))), true)    // survives export and import as JSON
    for (const tamper of [{ note: 'harmless' }, { target: cid('other') }, { category: 'spam' }, { kind: 'name' }, { ts: r.ts + 1 }, { id: 'other-id' }, { reporter: id(other) }, { sig: r.sig.slice(1) + 'A' }]) {
      assert.equal(await verifyReport({ ...r, ...tamper }), false, JSON.stringify(tamper))
    }
    assert.equal(await verifyReport({ ...r, note: 'x'.repeat(MAX_NOTE + 1) }), false)
    for (const junk of [null, undefined, 'x', 1, {}, { ...r, ts: 'now' }, { ...r, id: 'bad id\n' }]) assert.equal(await verifyReport(junk), false)
    const foreign = await generateKeyPair('Ed25519')   // a report signed by someone else's key cannot claim to be from this node
    assert.equal(await verifyReport({ ...r, sig: Buffer.from(await foreign.sign(Buffer.from('anything'))).toString('base64') }), false)
  })

  it('rejects bad input and bounds the note', async () => {
    const a = await track()
    const c = cid('y')
    await assert.rejects(a.moderation.report({ kind: 'cid', target: c, category: 'nonsense' }), /category/)
    await assert.rejects(a.moderation.report({ kind: 'file', target: c, category: 'spam' }), /kind/)
    await assert.rejects(a.moderation.report({ kind: 'cid', target: 'nope', category: 'spam' }), /invalid content ID/)
    const r = await a.moderation.report({ kind: 'cid', target: c, category: 'spam', note: 'n'.repeat(MAX_NOTE + 200) })
    assert.equal(r.note.length, MAX_NOTE)
    assert.equal(await verifyReport(r), true)
  })

  it('blocking from a report closes every open report about that target; dismissing only closes one', async () => {
    const a = await track()
    const bad = await a.blocks.put(bytes('bad bytes'))
    const r1 = await a.moderation.report({ kind: 'cid', target: bad.cid, category: 'illegal' })
    const r2 = await a.moderation.report({ kind: 'cid', target: bad.cid, category: 'child-safety', note: 'second report' })
    const r3 = await a.moderation.report({ kind: 'cid', target: cid('unrelated'), category: 'spam' })
    assert.equal(a.moderation.counts().openReports, 3)
    const out = await a.moderation.resolve(r1.id, 'block')
    assert.equal(out.purged, 1)
    const status = () => Object.fromEntries(a.moderation.listReports().map((r) => [r.id, r.status]))
    assert.deepEqual(status(), { [r1.id]: 'blocked', [r2.id]: 'blocked', [r3.id]: 'open' })
    assert.equal(a.store.hasBlock(bad.cid), false)
    assert.equal(a.moderation.list()[0].reason, 'report: illegal')
    await a.moderation.resolve(r3.id, 'dismiss')
    assert.equal(a.moderation.isBlocked('cid', cid('unrelated')), false)
    assert.deepEqual(a.moderation.counts(), { blocklist: 1, openReports: 0 })
    await assert.rejects(a.moderation.resolve('missing', 'block'), /no such report/)
    await assert.rejects(a.moderation.resolve(r3.id, 'ban'), /action must be/)
  })

  it('keeps the report log bounded: full of open reports it refuses, and it makes room by dropping the oldest resolved ones', async () => {
    const a = await track()
    const c = cid('flood')
    for (let i = 0; i < MAX_REPORTS; i++) await a.moderation.report({ kind: 'cid', target: c, category: 'spam' })
    await assert.rejects(a.moderation.report({ kind: 'cid', target: c, category: 'spam' }), /report log is full/)
    const oldest = a.moderation.listReports().at(-1)!
    await a.moderation.resolve(oldest.id, 'dismiss')
    await a.moderation.report({ kind: 'cid', target: c, category: 'spam' })
    assert.ok(a.store.countReports() <= MAX_REPORTS)
    assert.equal(a.store.getReport(oldest.id), null)
  })
})

describe('persistence', () => {
  it('the blocklist and reports survive a restart and are enforced straight away', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'frenet-mod-')); dirs.push(dir)
    const first = await track({ dataDir: dir })
    const site = await first.sites.publish(page('persisted'))
    const rep = await first.moderation.report({ kind: 'cid', target: site.cid, category: 'phishing', note: 'looks like a bank' })
    await first.moderation.resolve(rep.id, 'block')
    await first.stop()
    const second = await track({ dataDir: dir })
    assert.equal(second.moderation.isBlocked('cid', site.cid), true)
    assert.equal(second.moderation.list().length, 1)
    assert.equal(second.moderation.list()[0].derived, 4)
    assert.deepEqual(second.moderation.listReports().map((r) => [r.id, r.status]), [[rep.id, 'blocked']])
    assert.equal(await verifyReport(second.moderation.listReports()[0]), true)
    await assert.rejects(second.sites.publish(page('persisted')), ContentBlocked)
    assert.equal(second.store.blockStats().count, 0)
  })
})

describe('moderation API', () => {
  it('reports, blocks, unblocks and answers 451 for blocked content', async () => {
    const n = await track()
    const { server, port } = await startApi(n, 0)
    const call = async (path: string, body?: unknown) => {
      const r = await fetch(`http://127.0.0.1:${port}${path}`, body === undefined ? undefined : { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) })
      return { status: r.status, json: await r.json() as any }
    }
    try {
      const f = await n.blocks.put(bytes('from the api'))
      assert.equal((await call(`/api/blocks/${f.cid}`)).status, 200)

      const filed = await call('/api/moderation/report', { kind: 'cid', target: `frenet://${f.cid}#k`, category: 'malware', note: 'n' })
      assert.equal(filed.status, 200)
      assert.equal(filed.json.purged, null)
      assert.equal(filed.json.report.status, 'open')
      assert.equal(await verifyReport(filed.json.report), true)

      const both = await call('/api/moderation/report', { kind: 'cid', target: f.cid, category: 'illegal', block: true })
      assert.equal(both.json.purged, 1)
      assert.equal(both.json.report.status, 'blocked')
      const blockedGet = await call(`/api/blocks/${f.cid}`)
      assert.equal(blockedGet.status, 451)
      assert.match(blockedGet.json.error, /blocked by the operator/)
      assert.equal((await call('/api/files/get', { cid: f.cid })).status, 451)

      const view = await call('/api/moderation')
      assert.deepEqual(view.json.categories.slice(0, 2), ['illegal', 'child-safety'])
      assert.equal(view.json.blocklist.length, 1)
      assert.deepEqual(view.json.reports.map((r: any) => r.status).sort(), ['blocked', 'blocked'])   // blocking closed the earlier open one too
      assert.equal((await call('/api/status')).json.moderation.blocklist, 1)

      assert.equal((await call('/api/moderation/report', { kind: 'cid', target: 'nope', category: 'spam' })).status, 400)
      assert.equal((await call('/api/moderation/block', { kind: 'name', target: 'nope' })).status, 400)
      assert.equal((await call('/api/moderation/resolve', { id: 'missing', action: 'block' })).status, 400)
      assert.equal((await call('/api/moderation/unblock', { kind: 'cid', target: f.cid })).json.removed, true)
      assert.equal((await call('/api/moderation/unblock', { kind: 'cid', target: f.cid })).json.removed, false)
      assert.equal((await call('/api/moderation')).json.blocklist.length, 0)

      // state-changing calls keep the loopback API's protections
      const cross = await fetch(`http://127.0.0.1:${port}/api/moderation/block`, { method: 'POST', headers: { 'content-type': 'application/json', origin: 'http://evil.example' }, body: JSON.stringify({ kind: 'cid', target: f.cid }) })
      assert.equal(cross.status, 403)
      const form = await fetch(`http://127.0.0.1:${port}/api/moderation/block`, { method: 'POST', headers: { 'content-type': 'text/plain' }, body: '{}' })
      assert.equal(form.status, 415)

      // manual re-announce and its status (unblocking does not bring purged data back, so the store is empty until we add a block)
      assert.equal((await call('/api/operator/reannounce', {})).json.total, 0)
      n.blocks.putLocal(bytes('held locally'))
      const re = await call('/api/operator/reannounce', {})
      assert.equal(re.status, 200)
      assert.equal(re.json.total, 1)   // this node has no peers, so nothing can be announced (ok is 0), but the block is counted
      const st = (await call('/api/status')).json
      assert.equal(st.blocks.lastReannounce.total, 1)
      assert.equal(st.blocks.reannounceHours, 12)
    } finally { server.close() }
  })
})

describe('blocking encrypted files', () => {
  /** 600 KB = 3 chunks of 256 KB, each sealed with a fresh nonce, so every copy has its own chunk CIDs. */
  const big = (fill: number) => Buffer.alloc(600 * 1024, fill)
  /** `a` adds an encrypted file; `b` downloads it, so b holds the manifest and 3 chunks as replicas and cannot read the manifest. */
  const replicate = async (a: FrenetNode, b: FrenetNode, fill: number) => {
    const f = await a.files.add(`f${fill}.bin`, big(fill))
    assert.ok(f.key)
    await b.files.get(f.cid, f.key)
    return { ...f, key: f.key!, chunks: a.store.getFile(f.cid)!.chunks }
  }

  it('without the key only the manifest is blocked; with the file link every chunk is', async () => {
    const { a, b } = await pair()
    const f1 = await replicate(a, b, 1)
    const f2 = await replicate(a, b, 2)
    assert.equal(b.store.blockStats().count, 8)

    const noKey = await b.moderation.block('cid', f1.cid)
    assert.deepEqual([noKey.purged, noKey.entry.derived, noKey.keyStatus], [1, 0, 'key-needed'])   // it says the chunks are still there
    assert.equal(b.store.blockStats().count, 7)                      // f1's 3 chunks are orphans that only the replica TTL will remove
    for (const c of f1.chunks) assert.equal(b.moderation.isBlocked('cid', c), false)

    const keyed = await b.moderation.block('cid', f2.link)                  // the #key in the link is used once, in memory
    assert.deepEqual([keyed.purged, keyed.entry.derived, keyed.keyStatus], [4, 3, 'used'])
    assert.equal(b.store.blockStats().count, 3)                      // only f1's orphans are left
    for (const c of f2.chunks) assert.equal(b.moderation.isBlocked('cid', c), true)
    await assert.rejects(b.blocks.get(f2.chunks[0]), ContentBlocked)

    // The key can still be added afterwards, although the manifest is gone: it is fetched from a peer that has it (that block
    // only), read once, and not kept. f1's orphaned chunks, which this node still holds, are blocked and purged now.
    const late = await b.moderation.block('cid', f1.link)
    assert.deepEqual([late.purged, late.entry.derived, late.keyStatus], [3, 3, 'used'])
    assert.equal(b.store.blockStats().count, 0)
    assert.equal(b.store.hasBlock(f1.cid), false)                    // reading the manifest did not store it
    assert.equal(b.moderation.list().filter((e) => e.target === f1.cid).length, 1)   // the same entry, not a second one
    for (const c of f1.chunks) assert.equal(b.moderation.isBlocked('cid', c), true)

    // Unblocking lifts the chunks that the key revealed, together with the manifest.
    assert.equal(b.moderation.unblock('cid', f2.cid), true)
    for (const c of f2.chunks) assert.equal(b.moderation.isBlocked('cid', c), false)
    assert.equal(b.moderation.isBlocked('cid', f1.cid), true)         // f1's own entry is untouched
    assert.equal(b.moderation.isBlocked('cid', f1.chunks[0]!), true)
  })

  it('says "key-needed" only for a small block that cannot be read, and nothing for what it can read', async () => {
    const { a, b } = await pair()
    const sealed = await replicate(a, b, 20)
    const plain = Buffer.concat([Buffer.alloc(256 * 1024, 1), Buffer.alloc(256 * 1024, 2), Buffer.alloc(88 * 1024, 3)])
    const pub = await a.files.add('open.bin', plain, { encrypt: false })
    await b.files.get(pub.cid, null)
    const own = await a.files.add('mine.bin', big(21))
    const site = await a.sites.publish([{ path: 'index.html', data: bytes('<p>hi</p>') }])
    await b.sites.resolve(site.cid, '/')

    assert.equal((await b.moderation.block('cid', sealed.cid)).keyStatus, 'key-needed')
    assert.equal((await b.moderation.block('cid', pub.cid)).keyStatus, null)           // a public manifest is readable
    assert.equal((await a.moderation.block('cid', own.cid)).keyStatus, null)           // the owner knows the chunks
    assert.equal((await b.moderation.block('cid', site.cid)).keyStatus, null)
    assert.equal((await b.moderation.block('cid', sealed.chunks[0]!)).keyStatus, null) // a 256 KB chunk is not a manifest
    assert.equal((await b.moderation.block('cid', cid('not held here at all'))).keyStatus, null)
    assert.equal((await b.moderation.block('cid', b.blocks.putLocal(Buffer.alloc(100, 7)).toString())).keyStatus, 'key-needed')   // any small unreadable block, hence "if it is an encrypted file" in the dashboard
    assert.equal((await b.moderation.block('publisher', a.names.publisherKey)).keyStatus, null)
  })

  it('fetches only the manifest from a peer when none is held, keeps nothing, and fails safely', async () => {
    const { a, b } = await pair()
    const f = await a.files.add('far.bin', big(30))                  // b has never seen this file
    assert.equal(b.store.blockStats().count, 0)
    const before = b.reputation.score(id(a))
    const done = await b.moderation.block('cid', f.link, 'abuse')
    assert.deepEqual([done.keyStatus, done.purged, done.entry.derived], ['used', 0, 3])
    assert.equal(b.store.blockStats().count, 0)                      // neither the manifest nor any chunk was stored
    for (const c of a.store.getFile(f.cid)!.chunks) assert.equal(b.moderation.isBlocked('cid', c), true)
    assert.equal(b.reputation.score(id(a)) >= before, true)          // reading it from a peer is not held against the peer

    // a wrong key against the fetched manifest changes nothing
    const g = await a.files.add('far2.bin', big(31))
    const wrong = Buffer.alloc(32, 9).toString('base64url')
    await assert.rejects(b.moderation.block('cid', g.cid, '', wrong), /does not open/)
    assert.equal(b.moderation.list().length, 1)
    assert.equal(b.moderation.isBlocked('cid', g.cid), false)

    // a key given for a chunk-sized block never downloads it: the fetch stops at the manifest size limit
    const chunk0 = a.store.getFile(g.cid)!.chunks[0]!
    const mid = b.reputation.score(id(a))
    assert.equal((await b.moderation.block('cid', chunk0, '', g.key!)).keyStatus, 'manifest-not-held')
    assert.equal(b.store.blockStats().count, 0)
    assert.equal(b.reputation.score(id(a)), mid)

    // and with nobody reachable that holds the manifest, it still blocks the ID and says what was missing
    const lone = await track()
    const nobody = await lone.moderation.block('cid', f.link)
    assert.deepEqual([nobody.keyStatus, nobody.purged, nobody.entry.derived], ['manifest-not-held', 0, 0])
    assert.equal(lone.moderation.isBlocked('cid', f.cid), true)
    await a.stop()                                                   // the publisher goes away: a node that holds nothing can no longer be helped
    const orphan = await track()
    await orphan.libp2p.dial(b.libp2p.getMultiaddrs()[0]); await sleep(1000)
    assert.equal((await orphan.moderation.block('cid', g.cid, '', g.key!)).keyStatus, 'manifest-not-held')
  })

  it('takes the key separately too, and says whether it was needed', async () => {
    const { a, b } = await pair()
    const sealed = await replicate(a, b, 3)
    assert.equal((await b.moderation.block('cid', sealed.cid, 'x', sealed.key)).keyStatus, 'used')       // key as its own argument
    assert.equal(b.store.blockStats().count, 0)

    // A public file's chunks are the plain bytes, so give each chunk different content (identical chunks would share one CID).
    const plain = Buffer.concat([Buffer.alloc(256 * 1024, 4), Buffer.alloc(256 * 1024, 5), Buffer.alloc(88 * 1024, 6)])
    const pub = await a.files.add('open.bin', plain, { encrypt: false })
    await b.files.get(pub.cid, null)                                                              // a public file: manifest is readable by anyone
    const anyKey = Buffer.alloc(32, 5).toString('base64url')
    const r = await b.moderation.block('cid', pub.cid, 'x', anyKey)
    assert.deepEqual([r.keyStatus, r.purged, r.entry.derived], ['not-needed', 4, 3])

    const own = await a.files.add('mine.bin', big(6))                                             // the owner already knows the chunks
    assert.deepEqual([(await a.moderation.block('cid', own.link)).keyStatus, a.moderation.list()[0].derived], ['not-needed', 3])
  })

  it('rejects a wrong or malformed key before anything has changed, and leaves no half-finished report', async () => {
    const { a, b } = await pair()
    const f = await replicate(a, b, 7)
    const wrong = Buffer.alloc(32, 9).toString('base64url')
    await assert.rejects(b.moderation.block('cid', f.cid, '', wrong), /does not open/)
    await assert.rejects(b.moderation.block('cid', f.cid, '', 'short'), /invalid file key/)
    await assert.rejects(b.moderation.block('cid', `${f.cid}#nonsense-but-not-a-key`, '', 'short'), /invalid file key/)
    await assert.rejects(b.moderation.block('name', `x.${a.names.publisherKey}`, '', f.key), /only applies to a content ID/)
    await assert.rejects(b.moderation.reportAndBlock({ kind: 'cid', target: f.cid, category: 'illegal' }, wrong), /does not open/)
    assert.deepEqual([b.moderation.list().length, b.moderation.listReports().length, b.store.blockStats().count], [0, 0, 4])
    assert.equal((await b.moderation.block('cid', f.cid, '', f.key)).keyStatus, 'used')                    // the right key then works
    // a fragment that is not a key is simply dropped, as before
    assert.equal(keyFromLink(`frenet://x#${f.key}`), f.key)
    assert.equal(keyFromLink(`frenet://x#${f.key}  `), f.key)
    assert.equal(keyFromLink('frenet://x#short'), undefined)
    assert.equal(keyFromLink('frenet://x'), undefined)
    assert.equal(keyFromLink(42), undefined)
  })

  it('never writes the key to disk', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'frenet-key-')); dirs.push(dir)
    const a = await track()
    const b = await track({ dataDir: dir })
    await a.libp2p.dial(b.libp2p.getMultiaddrs()[0]); await sleep(1500)
    const f = await replicate(a, b, 8)
    const out = await b.moderation.reportAndBlock({ kind: 'cid', target: f.link, category: 'malware', note: 'n' })
    assert.equal(out.keyStatus, 'used')
    assert.equal(JSON.stringify([out, b.moderation.list(), b.moderation.listReports()]).includes(f.key), false)
    await b.stop()
    const files = readdirSync(dir).filter((n) => n.startsWith('frenet.db'))
    assert.ok(files.length >= 1)
    const disk = Buffer.concat(files.map((n) => readFileSync(join(dir, n))))
    assert.ok(disk.includes(Buffer.from(f.cid)), 'the scan can see the database content')     // so a miss below means something
    assert.equal(disk.includes(Buffer.from(f.key)), false)
  })

  it('works through the API for blocking, report-and-block and resolving a report, and never echoes a key', async () => {
    const { a, b } = await pair()
    const [f1, f2, f3] = [await replicate(a, b, 11), await replicate(a, b, 12), await replicate(a, b, 13)]
    const { server, port } = await startApi(b, 0)
    const call = async (path: string, body?: unknown) => {
      const r = await fetch(`http://127.0.0.1:${port}${path}`, body === undefined ? undefined : { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) })
      return { status: r.status, json: await r.json() as any }
    }
    try {
      const r1 = await call('/api/moderation/block', { kind: 'cid', target: f1.link, reason: 'abuse' })
      assert.deepEqual([r1.status, r1.json.keyStatus, r1.json.purged, r1.json.entry.derived], [200, 'used', 4, 3])

      const r2 = await call('/api/moderation/report', { kind: 'cid', target: f2.link, category: 'illegal', block: true })
      assert.deepEqual([r2.status, r2.json.keyStatus, r2.json.purged, r2.json.report.status, r2.json.report.target], [200, 'used', 4, 'blocked', f2.cid])

      const filed = await call('/api/moderation/report', { kind: 'cid', target: f3.link, category: 'malware' })   // a plain report keeps no key
      assert.deepEqual([filed.json.report.target, filed.json.report.status, filed.json.purged, filed.json.keyStatus], [f3.cid, 'open', null, null])
      assert.equal(b.store.blockStats().count, 4)                                                                // nothing blocked yet
      const wrong = await call('/api/moderation/resolve', { id: filed.json.report.id, action: 'block', key: Buffer.alloc(32, 1).toString('base64url') })
      assert.equal(wrong.status, 400)
      assert.equal(b.store.blockStats().count, 4)                                                                // a wrong key changed nothing
      const r3 = await call('/api/moderation/resolve', { id: filed.json.report.id, action: 'block', key: f3.key })
      assert.deepEqual([r3.status, r3.json.keyStatus, r3.json.purged, r3.json.report.status], [200, 'used', 4, 'blocked'])
      assert.equal(b.store.blockStats().count, 0)

      const everything = JSON.stringify([r1.json, r2.json, filed.json, wrong.json, r3.json, (await call('/api/moderation')).json])
      for (const f of [f1, f2, f3]) assert.equal(everything.includes(f.key), false)

      // blocked without a key it says so, and the key can be added afterwards
      const f4 = await replicate(a, b, 14)
      const r4 = await call('/api/moderation/block', { kind: 'cid', target: f4.cid })
      assert.deepEqual([r4.status, r4.json.keyStatus, r4.json.purged, r4.json.entry.derived], [200, 'key-needed', 1, 0])
      assert.equal(b.store.blockStats().count, 3)
      const r5 = await call('/api/moderation/block', { kind: 'cid', target: f4.cid, key: f4.key })
      assert.deepEqual([r5.status, r5.json.keyStatus, r5.json.purged, r5.json.entry.derived], [200, 'used', 3, 3])
      assert.equal(b.store.blockStats().count, 0)
      assert.equal(JSON.stringify([r4.json, r5.json]).includes(f4.key), false)

      const bad = await call('/api/moderation/report', { kind: 'cid', target: f1.cid, category: 'spam', block: true, key: 'nope' })
      assert.equal(bad.status, 400)
      assert.equal((await call('/api/moderation')).json.reports.length, 2)                                       // r2 and the resolved one; r1 was a plain block, and the failed attempt filed nothing
    } finally { server.close() }
  })
})
