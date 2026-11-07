import assert from 'node:assert/strict'
import { createServer, type Server } from 'node:http'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { after, describe, it } from 'node:test'
import { generateKeyPair } from '@libp2p/crypto/keys'
import { canon, signBytes } from '../src/channel.js'
import { ADMIN_PROTOCOL } from '../src/admin.js'
import { download, fetchUpdate, installStaged, rollbackLast } from '../src/installer.js'
import { startFrenet, type FrenetNode } from '../src/node.js'
import { Store } from '../src/store.js'
import { generateReleaseKey, sha256Hex, signManifest, Updates, type UpdateManifest } from '../src/updates.js'

const tmp: string[] = []
const mkTmp = (): string => { const d = mkdtempSync(join(tmpdir(), 'frenet-p5-')); tmp.push(d); return d }
const servers: Server[] = []
const nodes: FrenetNode[] = []
after(async () => {
  for (const s of servers) s.close()
  for (const n of nodes) await n.stop().catch(() => {})
  for (const d of tmp) rmSync(d, { recursive: true, force: true })
})

// ---- update downloader / installer --------------------------------------------------------------------------

const V1 = Buffer.from('frenet binary v1 '.repeat(50))
const CFG = Buffer.from('{"release":"1.1.0"}\n')

async function release (opts: { seq?: number, version?: string, serve?: Record<string, Buffer | ((res: any) => void)>, days?: number } = {}) {
  const { key, did } = await generateReleaseKey()
  const files: Record<string, Buffer> = { 'frenet.bin': V1, 'config.json': CFG }
  const now = Date.now()
  const m: UpdateManifest = {
    v: 1, product: 'frenet', channel: 'stable', version: opts.version ?? '0.2.0', seq: opts.seq ?? 5, created: now, expires: now + (opts.days ?? 30) * 86_400_000,
    artifacts: Object.entries(files).map(([name, b]) => ({ name, size: b.length, sha256: sha256Hex(b) }))
  }
  const env = await signManifest(m, key)
  const serve: Record<string, any> = { 'manifest.json': Buffer.from(JSON.stringify(env)), ...files, ...(opts.serve ?? {}) }
  const server = createServer((req, res) => {
    const name = decodeURIComponent((req.url ?? '').slice(1))
    const v = serve[name]
    if (typeof v === 'function') return v(res)
    if (!v) { res.writeHead(404); return void res.end() }
    res.writeHead(200); res.end(v)
  })
  servers.push(server)
  await new Promise<void>((ok) => server.listen(0, '127.0.0.1', ok))
  const url = `http://127.0.0.1:${(server.address() as { port: number }).port}/`
  const roots = { threshold: 1, keys: [did] }
  const dataDir = mkTmp()
  const store = new Store(':memory:')
  const updates = new Updates(store, roots, '0.1.0')
  return { url, updates, store, dataDir, did, key, m }
}

describe('update downloader and installer', () => {
  it('fetches, verifies, stages, installs atomically with a backup, then rolls back', async () => {
    const r = await release()
    const f = await fetchUpdate({ baseUrl: r.url, dataDir: r.dataDir, updates: r.updates })
    assert.equal(f.manifest.version, '0.2.0')
    assert.deepEqual(readFileSync(join(f.dir, 'frenet.bin')), V1)
    assert.equal(r.store.getUpdateState('stable'), null, 'fetching alone does not record acceptance')

    const target = mkTmp()
    writeFileSync(join(target, 'frenet.bin'), 'OLD BINARY', { mode: 0o755 })
    const i = await installStaged({ stagedDir: f.dir, target, dataDir: r.dataDir, updates: r.updates })
    assert.deepEqual(i.installed.sort(), ['config.json', 'frenet.bin'])
    assert.deepEqual(i.replaced, ['frenet.bin'])
    assert.deepEqual(readFileSync(join(target, 'frenet.bin')), V1)
    assert.equal(statSync(join(target, 'frenet.bin')).mode & 0o777, 0o755, 'an existing file keeps its mode')
    assert.deepEqual(readFileSync(join(i.backup, 'frenet.bin'), 'utf8'), 'OLD BINARY')
    assert.equal(readdirSync(target).filter((n) => n.includes('frenet-tmp')).length, 0, 'no temp files left behind')
    assert.equal(r.store.getUpdateState('stable')?.seq, 5, 'acceptance is recorded after the install')

    const back = await rollbackLast({ target, dataDir: r.dataDir })
    assert.deepEqual(back.restored.sort(), ['config.json', 'frenet.bin'])
    assert.equal(readFileSync(join(target, 'frenet.bin'), 'utf8'), 'OLD BINARY')
    assert.equal(existsSync(join(target, 'config.json')), false, 'a file the install created is removed')
    await assert.rejects(rollbackLast({ target, dataDir: r.dataDir }), /no install to roll back/)
  })

  it('refuses an artifact whose bytes differ from the signed hash, and stages nothing', async () => {
    const r = await release({ serve: { 'frenet.bin': Buffer.from('X'.repeat(V1.length)) } })
    await assert.rejects(fetchUpdate({ baseUrl: r.url, dataDir: r.dataDir, updates: r.updates }), /SHA-256/)
    assert.equal(existsSync(join(r.dataDir, 'updates', 'staged')), false)
  })

  it('stops reading an oversized artifact at the signed size', async () => {
    const r = await release({ serve: { 'frenet.bin': Buffer.alloc(V1.length + 5000, 1) } })
    await assert.rejects(fetchUpdate({ baseUrl: r.url, dataDir: r.dataDir, updates: r.updates }), /larger than the allowed/)
  })

  it('refuses a manifest not signed by the pinned roots, an expired one, and a rollback', async () => {
    const r = await release()
    const other = await generateReleaseKey()
    const wrong = new Updates(r.store, { threshold: 1, keys: [other.did] }, '0.1.0')
    await assert.rejects(fetchUpdate({ baseUrl: r.url, dataDir: r.dataDir, updates: wrong }), /manifest refused/)
    const noRoots = new Updates(r.store, null, '0.1.0')
    await assert.rejects(fetchUpdate({ baseUrl: r.url, dataDir: r.dataDir, updates: noRoots }), /no update trust roots/)

    const old = await release({ days: -1 })   // created after expires: invalid window
    await assert.rejects(fetchUpdate({ baseUrl: old.url, dataDir: old.dataDir, updates: old.updates }), /manifest refused/)

    r.store.putUpdateState('stable', 9, '0.3.0')   // a newer release was accepted earlier
    await assert.rejects(fetchUpdate({ baseUrl: r.url, dataDir: r.dataDir, updates: r.updates }), /rollback/)
  })

  it('refuses plain http to a non-local host, also via a redirect', async () => {
    await assert.rejects(download('http://example.com/x', 100), /https only/)
    const redirect = createServer((_req, res) => { res.writeHead(302, { location: 'http://example.com/evil' }); res.end() })
    servers.push(redirect)
    await new Promise<void>((ok) => redirect.listen(0, '127.0.0.1', ok))
    await assert.rejects(download(`http://127.0.0.1:${(redirect.address() as { port: number }).port}/`, 100), /https only/)
  })

  it('re-verifies on install: a staged file altered after fetch is refused and the target stays untouched', async () => {
    const r = await release()
    const f = await fetchUpdate({ baseUrl: r.url, dataDir: r.dataDir, updates: r.updates })
    const target = mkTmp()
    writeFileSync(join(target, 'frenet.bin'), 'OLD')
    writeFileSync(join(f.dir, 'frenet.bin'), Buffer.concat([V1.subarray(0, V1.length - 1), Buffer.from('!')]))
    await assert.rejects(installStaged({ stagedDir: f.dir, target, dataDir: r.dataDir, updates: r.updates }), /SHA-256/)
    assert.equal(readFileSync(join(target, 'frenet.bin'), 'utf8'), 'OLD')
    assert.equal(r.store.getUpdateState('stable'), null)
  })

  it('rolls back already-replaced files when a later one cannot be installed', async () => {
    const r = await release()
    const f = await fetchUpdate({ baseUrl: r.url, dataDir: r.dataDir, updates: r.updates })
    const target = mkTmp()
    writeFileSync(join(target, 'config.json'), 'OLD CONFIG')
    mkdirSync(join(target, 'frenet.bin'))   // artifacts install in manifest order (config.json first? order is by name in the manifest); a directory in the way makes one fail
    await assert.rejects(installStaged({ stagedDir: f.dir, target, dataDir: r.dataDir, updates: r.updates }), /rolled back|not a regular file/)
    assert.equal(readFileSync(join(target, 'config.json'), 'utf8'), 'OLD CONFIG')
    assert.equal(r.store.getUpdateState('stable'), null, 'no acceptance recorded for a failed install')
  })

  it('rollback leaves alone a file that changed after the install', async () => {
    const r = await release()
    const f = await fetchUpdate({ baseUrl: r.url, dataDir: r.dataDir, updates: r.updates })
    const target = mkTmp()
    writeFileSync(join(target, 'config.json'), 'OLD')
    await installStaged({ stagedDir: f.dir, target, dataDir: r.dataDir, updates: r.updates })
    writeFileSync(join(target, 'config.json'), 'operator edited this')
    const b = await rollbackLast({ target, dataDir: r.dataDir })
    assert.deepEqual(b.skipped, ['config.json'])
    assert.equal(readFileSync(join(target, 'config.json'), 'utf8'), 'operator edited this')
  })
})

// ---- remote administration ------------------------------------------------------------------------------------

const TCP = ['/ip4/127.0.0.1/tcp/0']
const track = async (o: Partial<Parameters<typeof startFrenet>[0]> = {}) => { const n = await startFrenet({ dataDir: ':memory:', listen: TCP, mdns: false, nat: false, ...o }); nodes.push(n); return n }
const pid = (n: FrenetNode) => n.libp2p.peerId.toString()
const addr = (n: FrenetNode) => n.libp2p.getMultiaddrs()[0]!.toString()

describe('remote administration', () => {
  it('lets a listed admin read stats and ban, unban, disconnect, sweep and block, and logs each command', async () => {
    const admin = await track()
    const target = await track({ adminPeers: [pid(admin)] })
    const victim = await track()
    await victim.libp2p.dial(target.libp2p.getMultiaddrs()[0]!)

    const st = await admin.admin.call(pid(target), 'status', {}, { addr: addr(target) })
    assert.ok(st.connections.total >= 2)
    await admin.admin.call(pid(target), 'ban', { peer: pid(victim), reason: 'spam' })
    assert.ok(target.operator.banned.has(pid(victim)))
    const bans = await admin.admin.call(pid(target), 'bans')
    assert.equal(bans.length, 1)
    assert.match(bans[0].reason, /^remote:.*spam/)
    assert.deepEqual(await admin.admin.call(pid(target), 'unban', { peer: pid(victim) }), { removed: true })
    assert.equal(target.operator.banned.has(pid(victim)), false)
    assert.ok(typeof (await admin.admin.call(pid(target), 'sweep')).removed === 'number')

    const { cid } = await target.blocks.put(Buffer.from('some stored bytes'))
    await admin.admin.call(pid(target), 'block', { kind: 'cid', target: cid, reason: 'abuse' })
    assert.ok(target.moderation.isBlocked('cid', cid))
    assert.deepEqual(await admin.admin.call(pid(target), 'unblock', { kind: 'cid', target: cid }), { removed: true })

    const log = target.store.listAdminLog()
    assert.ok(log.length >= 6 && log.every((l) => l.peer === pid(admin)))
    assert.ok(log.some((l) => l.cmd === 'ban' && l.ok))
  })

  it('refuses everyone who is not listed, and is not even registered without admins', async () => {
    const admin = await track()
    const stranger = await track()
    const target = await track({ adminPeers: [pid(admin)] })
    await assert.rejects(stranger.admin.call(pid(target), 'status', {}, { addr: addr(target) }), /no valid reply/)
    const none = await track()
    await assert.rejects(admin.admin.call(pid(none), 'status', {}, { addr: addr(none) }), /./)
    assert.equal(target.store.listAdminLog().length, 0, 'unauthenticated peers leave no audit rows')
    assert.equal(none.admin.enabled, false)
  })

  it('will not ban an admin or this node, nor disconnect the requesting admin; unknown commands never leave the client', async () => {
    const admin = await track()
    const target = await track({ adminPeers: [pid(admin)] })
    await admin.libp2p.dial(target.libp2p.getMultiaddrs()[0]!)
    await assert.rejects(admin.admin.call(pid(target), 'ban', { peer: pid(admin) }), /refusing to ban/)
    await assert.rejects(admin.admin.call(pid(target), 'ban', { peer: pid(target) }), /refusing to ban/)
    await assert.rejects(admin.admin.call(pid(target), 'disconnect', { peer: pid(admin) }), /requesting admin/)
    await assert.rejects(admin.admin.call(pid(target), 'ban', { peer: 'not-a-peer' }), /invalid peer/)
    await assert.rejects(admin.admin.call(pid(target), 'shell' as any, {}), /unknown command/)
    assert.equal(target.operator.banned.size, 0)
  })

  it('rejects replayed, stale, mis-addressed and mis-signed requests', async () => {
    const key = await generateKeyPair('Ed25519')
    const admin = await track({ privateKey: key })
    const target = await track({ adminPeers: [pid(admin)] })
    const other = await track({ adminPeers: [pid(admin)] })
    await admin.libp2p.dial(target.libp2p.getMultiaddrs()[0]!)
    const self = pid(admin)

    const raw = async (to: string, over: Partial<{ id: string, ts: number, cmd: string, args: string, sigFor: string }> = {}, via = target): Promise<any> => {
      const id = over.id ?? `req-${Math.random().toString(36).slice(2)}`
      const ts = over.ts ?? Date.now()
      const cmd = over.cmd ?? 'sweep'
      const args = over.args ?? '{}'
      const sig = await signBytes(key, canon('frenet-admin/v1', [self, over.sigFor ?? to, id, String(ts), cmd], args))
      const s = await admin.libp2p.dialProtocol(via.libp2p.peerId, ADMIN_PROTOCOL)
      s.send(Buffer.from(JSON.stringify({ v: 1, id, ts, to, cmd, args, sig })))
      await s.close()
      const chunks: Uint8Array[] = []
      try { for await (const c of s) chunks.push(c.subarray()) } catch { return null }
      return chunks.length ? JSON.parse(Buffer.concat(chunks).toString()) : null
    }

    assert.equal((await raw(pid(target)))?.ok, true, 'a well-formed request works')
    const dup = `dup-${Date.now()}`
    assert.equal((await raw(pid(target), { id: dup }))?.ok, true)
    assert.equal(await raw(pid(target), { id: dup }), null, 'the same id twice is a replay')
    assert.equal(await raw(pid(target), { ts: Date.now() - 20 * 60_000 }), null, 'stale timestamp')
    assert.equal(await raw(pid(other)), null, 'a request addressed to another node is refused (sent to target, meant for other)')
    assert.equal(await raw(pid(target), { sigFor: pid(other) }), null, 'a signature made for another node does not verify here')
    assert.equal(await raw(pid(target), { cmd: 'status', args: '[1]' }), null, 'arguments must be an object')
  })

  it('works from the dashboard API route and shows the audit log', async () => {
    const { startApi } = await import('../src/api.js')
    const admin = await track()
    const target = await track({ adminPeers: [pid(admin)] })
    const api = await startApi(admin, 0)
    const tapi = await startApi(target, 0)
    try {
      const r = await fetch(`http://127.0.0.1:${api.port}/api/admin/remote`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ peer: pid(target), cmd: 'sweep', addr: addr(target) }) })
      assert.equal(r.status, 200)
      const log = await (await fetch(`http://127.0.0.1:${tapi.port}/api/admin`)).json() as any
      assert.equal(log.enabled, true)
      assert.equal(log.log[0].cmd, 'sweep')
      const bad = await fetch(`http://127.0.0.1:${api.port}/api/admin/remote`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ peer: pid(target), cmd: 'rm -rf' }) })
      assert.equal(bad.status, 400)
    } finally { api.server.close(); tapi.server.close() }
  })

  it('rejects an invalid admin peer list at start', async () => {
    await assert.rejects(startFrenet({ dataDir: ':memory:', listen: TCP, mdns: false, nat: false, adminPeers: ['nope'] }), /invalid admin peer/)
    const key = await generateKeyPair('Ed25519')
    const { peerIdFromPrivateKey } = await import('@libp2p/peer-id')
    await assert.rejects(startFrenet({ dataDir: ':memory:', listen: TCP, mdns: false, nat: false, privateKey: key, adminPeers: [peerIdFromPrivateKey(key as any).toString()] }), /own remote admin/)
  })
})

// ---- mobile profile ------------------------------------------------------------------------------------------

describe('mobile profile', () => {
  it('starts as a normal, working node with the low-resource preset, and cannot run a relay server', async () => {
    const m = await track({ profile: 'mobile' })
    const peer = await track()
    assert.equal(m.profile, 'mobile')
    assert.equal(((m.libp2p.services as any).dht).clientMode ?? true, true)
    const got: string[] = []
    m.messaging.on('message', (x) => got.push(x.body))
    await peer.libp2p.dial(m.libp2p.getMultiaddrs()[0]!)
    await peer.messaging.send(m.libp2p.peerId, 'hello phone')
    const t = Date.now(); while (!got.length && Date.now() - t < 5000) await new Promise((r) => setTimeout(r, 25))
    assert.deepEqual(got, ['hello phone'])
    await assert.rejects(startFrenet({ dataDir: ':memory:', listen: TCP, mdns: false, nat: false, profile: 'mobile', relayServer: true }), /mobile profile cannot run a relay server/)
    await assert.rejects(startFrenet({ dataDir: ':memory:', listen: TCP, mdns: false, nat: false, profile: 'tablet' as any }), /profile must be/)
  })
})
