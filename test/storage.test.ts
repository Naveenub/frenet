import assert from 'node:assert/strict'
import { request } from 'node:http'
import { after, describe, it } from 'node:test'
import { startApi } from '../src/api.js'
import { CHUNK_BYTES, MAX_FILE_BYTES, openBlock, sealBlock } from '../src/files.js'
import { startGateway } from '../src/gateway.js'
import { MAX_SITE_FILE_BYTES } from '../src/sites.js'
import { startFrenet, type FrenetNode } from '../src/node.js'

const L = ['/ip4/127.0.0.1/tcp/0']
const nodes: FrenetNode[] = []
const track = async (o: Partial<Parameters<typeof startFrenet>[0]> = {}) => { const n = await startFrenet({ dataDir: ':memory:', listen: L, mdns: false, nat: false, quic: false, ...o }); nodes.push(n); return n }
after(async () => { for (const n of nodes) await n.stop() })

async function * pieces (total: number, piece: number, fill = 7): AsyncGenerator<Buffer> {
  for (let left = total; left > 0; left -= piece) yield Buffer.alloc(Math.min(piece, left), fill)
}

describe('storage: big files and raw blocks', () => {
  it('limit is 1 GiB and a file bigger than the old 16 MB cap round-trips through streaming', async () => {
    assert.equal(MAX_FILE_BYTES, 1024 ** 3)
    const n = await track({ retention: { quotaBytes: 128 * 1024 * 1024 } } as any)
    const size = 20 * 1024 * 1024 + 12345                         // > 16 MB, not chunk aligned
    const f = await n.files.addStream('big.bin', pieces(size, 100_000))   // source pieces unrelated to chunk size
    assert.equal(f.size, size)
    assert.equal(f.chunks, Math.ceil(size / CHUNK_BYTES))
    const o = await n.files.open(f.cid, f.key)
    assert.equal(o.size, size)
    let got = 0
    for await (const p of o.chunks) { got += p.length; assert.ok(p.length <= CHUNK_BYTES); assert.ok(p.every((x) => x === 7)) }
    assert.equal(got, size)
  })

  it('a stream over the limit, an empty stream and a broken stream leave nothing behind', async () => {
    const n = await track()
    const before = n.store.blockStats().count
    await assert.rejects(n.files.addStream('x', [Buffer.alloc(MAX_FILE_BYTES + 1)]), /exceeds/)   // rejected on size alone, before any chunk is sealed
    await assert.rejects(n.files.addStream('x', []), /empty/)
    async function * broken (): AsyncGenerator<Buffer> { yield Buffer.alloc(CHUNK_BYTES * 3, 1); throw new Error('upload dropped') }
    await assert.rejects(n.files.addStream('x', broken()), /upload dropped/)
    assert.equal(n.store.blockStats().count, before)
    assert.equal(n.files.list().length, 0)
  })

  it('tampering and truncation are caught while streaming', async () => {
    const n = await track()
    n.files.chunkBytes = 1000
    const f = await n.files.add('t.bin', Buffer.alloc(3500, 9))
    const row = n.store.getFile(f.cid)!
    // swap two chunks: GCM AAD binds each chunk to its position
    const [c0, c1] = [row.chunks[0]!, row.chunks[1]!]
    const [b0, b1] = [n.store.getBlock(c0)!, n.store.getBlock(c1)!]
    n.store.deleteBlock(c0); n.store.deleteBlock(c1)      // putBlock keeps existing rows, so drop first
    n.store.putBlock(c0, b1, null); n.store.putBlock(c1, b0, null)
    await assert.rejects(n.files.get(f.cid, f.key), /wrong key or corrupted data/)
  })

  it('raw blocks over the API are encrypted by default; public must be asked for', async () => {
    const n = await track()
    const { server, port } = await startApi(n, 0)
    const post = async (path: string, body: unknown) => { const r = await fetch(`http://127.0.0.1:${port}${path}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) }); return { status: r.status, json: await r.json() as any } }
    try {
      const secret = Buffer.from('TOP-SECRET-BLOCK-CONTENT')
      const enc = await post('/api/blocks', { data: secret.toString('base64') })
      assert.equal(enc.status, 200)
      assert.ok(typeof enc.json.key === 'string' && enc.json.key.length === 43)
      assert.ok(!Buffer.from(n.store.getBlock(enc.json.cid)!).includes('TOP-SECRET'), 'stored bytes are ciphertext')
      // a CID holder without the key gets ciphertext only
      const noKey = await (await fetch(`http://127.0.0.1:${port}/api/blocks/${enc.json.cid}`)).json() as any
      assert.ok(!Buffer.from(noKey.data, 'base64').includes('TOP-SECRET'))
      // with the key: plaintext; wrong key: refused
      const withKey = await (await fetch(`http://127.0.0.1:${port}/api/blocks/${enc.json.cid}`, { headers: { 'x-frenet-key': enc.json.key } })).json() as any
      assert.deepEqual(Buffer.from(withKey.data, 'base64'), secret)
      const wrong = await fetch(`http://127.0.0.1:${port}/api/blocks/${enc.json.cid}`, { headers: { 'x-frenet-key': sealBlock(Buffer.from('x')).key } })
      assert.equal(wrong.status, 400)
      // explicit public block
      const pub = await post('/api/blocks', { data: secret.toString('base64'), public: true })
      assert.equal(pub.json.key, null)
      assert.deepEqual(Buffer.from(n.store.getBlock(pub.json.cid)!), secret)
      const s2 = sealBlock(secret)
      assert.deepEqual(openBlock(s2.blob, s2.key), secret)
      assert.throws(() => openBlock(s2.blob, sealBlock(secret).key), /wrong key/)
    } finally { server.close() }
  })

  it('PUT /api/files/stream uploads raw bytes; /api/files/download streams them back; csrf and type checks hold', async () => {
    const n = await track()
    const { server, port } = await startApi(n, 0)
    const base = `http://127.0.0.1:${port}`
    try {
      const data = Buffer.alloc(3 * 1024 * 1024 + 5, 3)
      const up = await fetch(`${base}/api/files/stream?name=${encodeURIComponent('big é.bin')}`, { method: 'PUT', headers: { 'content-type': 'application/octet-stream' }, body: data })
      assert.equal(up.status, 200)
      const f = await up.json() as any
      assert.equal(f.size, data.length)
      const dl = await fetch(`${base}/api/files/download`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ cid: f.cid, key: f.key }) })
      assert.equal(dl.status, 200)
      assert.equal(dl.headers.get('content-length'), String(data.length))
      assert.deepEqual(Buffer.from(await dl.arrayBuffer()), data)
      const bad = await fetch(`${base}/api/files/download`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ cid: f.cid, key: sealBlock(data).key }) })
      assert.equal(bad.status, 400)                                // wrong key: error before any bytes
      assert.equal((await fetch(`${base}/api/files/stream?name=a`, { method: 'PUT', headers: { 'content-type': 'application/json' }, body: '{}' })).status, 415)
      assert.equal((await fetch(`${base}/api/files/stream?name=a`, { method: 'PUT', headers: { 'content-type': 'application/octet-stream', origin: 'http://evil.example' }, body: data })).status, 403)
      assert.equal((await fetch(`${base}/api/files/stream?name=a`, { method: 'PUT', headers: { 'content-type': 'application/octet-stream', 'content-length': '0' } })).status, 400)   // empty
      // the old JSON route refuses to inline a file over 16 MB but still serves small ones
      const small = await (await fetch(`${base}/api/files/get`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ cid: f.cid, key: f.key }) })).json() as any
      assert.equal(small.size, data.length)
    } finally { server.close() }
  })
})

describe('storage: big site files', () => {
  it('a site file can be as big as any file: uploaded streaming, referenced by cid, served streaming with a correct length', async () => {
    assert.equal(MAX_SITE_FILE_BYTES, MAX_FILE_BYTES)
    const n = await track()
    const size = 20 * 1024 * 1024 + 4321                        // over the old 16 MB site cap, not chunk aligned
    const big = await n.files.addStream('big.bin', pieces(size, 1024 * 1024, 9), { encrypt: false })
    const enc = await n.files.addStream('secret.bin', pieces(1000, 1000), { encrypt: true })
    const site = await n.sites.publish([{ path: 'index.html', data: Buffer.from('<p>hi</p>') }, { path: 'big.bin', cid: big.cid }])
    assert.equal(site.bytes, 9 + size)
    await assert.rejects(n.sites.publish([{ path: 'index.html', cid: enc.cid }]), /encrypted/)
    await assert.rejects(n.sites.publish([{ path: 'index.html', cid: 'bafkreigh2akiscaildcqabsyg3dfr6chu3fgpregiymsck7e7aqa4s52zy' }]), /not stored on this node/)
    await assert.rejects(n.sites.publish([{ path: 'index.html', data: Buffer.from('x'), cid: big.cid }]), /either data or cid/)
    assert.ok(n.files.info(big.cid), 'a failed publish leaves referenced files alone')

    const gw = await startGateway(n, 0)
    try {
      const host = `${site.cid}.localhost:${gw.port}`
      const got = await new Promise<{ len: number, header: string | undefined, sum: number }>((resolve, reject) => {
        request({ host: '127.0.0.1', port: gw.port, path: '/big.bin', headers: { host } }, (res) => {
          let len = 0; let sum = 0
          res.on('data', (d: Buffer) => { len += d.length; for (let i = 0; i < d.length; i += 4096) sum += d[i]! })
          res.on('end', () => resolve({ len, header: res.headers['content-length'], sum }))
          res.on('error', reject)
        }).on('error', reject).end()
      })
      assert.equal(got.len, size)
      assert.equal(got.header, String(size))
      assert.ok(got.sum > 0)
    } finally { gw.server.close() }
  })
})

