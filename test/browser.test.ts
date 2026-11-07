import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { request } from 'node:http'
import { createServer as tcpServer, connect, type Server as NetServer } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { after, describe, it } from 'node:test'
import { startApi } from '../src/api.js'
import { startGateway } from '../src/gateway.js'
import { startFrenet, type FrenetNode } from '../src/node.js'
import { PERMISSION_FEATURES, validOrigin } from '../src/permissions.js'
import { normalizeHost } from '../src/trackers.js'
import { isNonPublicAddress, parseAuthority, startWebProxy } from '../src/webproxy.js'

const nodes: FrenetNode[] = []
const dirs: string[] = []
const track = async (o: Partial<Parameters<typeof startFrenet>[0]> = {}) => { const n = await startFrenet({ dataDir: ':memory:', listen: ['/ip4/127.0.0.1/tcp/0'], mdns: false, nat: false, ...o }); nodes.push(n); return n }
after(async () => { for (const n of nodes) await n.stop().catch(() => {}); for (const d of dirs) rmSync(d, { recursive: true, force: true }) })
const bytes = (s: string) => Buffer.from(s)

const get = (port: number, host: string, path = '/') =>
  new Promise<{ status: number, headers: Record<string, any>, body: Buffer }>((resolve, reject) => {
    const r = request({ host: '127.0.0.1', port, path, method: 'GET', headers: { host } }, (res) => {
      const c: Buffer[] = []; res.on('data', (d) => c.push(d)); res.on('end', () => resolve({ status: res.statusCode!, headers: res.headers, body: Buffer.concat(c) }))
    })
    r.on('error', reject); r.end()
  })

/** Send a raw CONNECT and return the status line plus (if 200) a socket to talk through. */
const connectVia = (proxyPort: number, target: string) =>
  new Promise<{ status: number, text: string, sock: ReturnType<typeof connect> }>((resolve, reject) => {
    const sock = connect(proxyPort, '127.0.0.1')
    let buf = ''
    sock.setEncoding('utf8')
    sock.once('error', reject)
    sock.write(`CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n\r\n`)
    const onData = (d: string): void => {
      buf += d
      if (!buf.includes('\r\n\r\n')) return
      sock.off('data', onData)
      resolve({ status: Number(/^HTTP\/1\.1 (\d{3})/.exec(buf)![1]), text: buf, sock })
    }
    sock.on('data', onData)
  })

describe('tracker blocker', () => {
  it('matches on a label boundary, supports user rules and allow overrides, and persists', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'frenet-trk-')); dirs.push(dir)
    const n = await track({ dataDir: dir })
    assert.equal(n.trackers.check('ad.doubleclick.net').blocked, true)
    assert.equal(n.trackers.check('doubleclick.net').blocked, true)
    assert.equal(n.trackers.check('notdoubleclick.net').blocked, false)   // suffix confusion
    assert.equal(n.trackers.check('example.com').blocked, false)
    assert.equal(n.trackers.check('AD.DoubleClick.NET.').blocked, true)   // case and trailing dot
    n.trackers.addRule('metrics.example.org', 'block')
    assert.deepEqual(n.trackers.check('x.metrics.example.org'), { blocked: true, reason: 'user', rule: 'metrics.example.org' })
    n.trackers.addRule('ok.doubleclick.net', 'allow')                     // allow beats the built-in list, but only for its own subtree
    assert.equal(n.trackers.check('ok.doubleclick.net').blocked, false)
    assert.equal(n.trackers.check('ad.doubleclick.net').blocked, true)
    assert.throws(() => n.trackers.addRule('not a host', 'block'), /valid domain/)
    assert.throws(() => n.trackers.addRule('127.0.0.1', 'block'), /valid domain/)
    assert.equal(normalizeHost('a..b'), null)
    assert.equal(n.trackers.removeRule('metrics.example.org'), true)
    assert.equal(n.trackers.check('x.metrics.example.org').blocked, false)
    n.trackers.addRule('keep.example.net', 'block')
    await n.stop()
    const again = await track({ dataDir: dir })
    assert.equal(again.trackers.check('keep.example.net').blocked, true)
    assert.equal(again.trackers.check('ok.doubleclick.net').blocked, false)
  })
})

describe('web proxy', () => {
  it('classifies non-public addresses and parses CONNECT targets strictly', () => {
    for (const a of ['127.0.0.1', '10.1.2.3', '172.16.0.1', '172.31.255.255', '192.168.1.1', '169.254.169.254', '100.64.0.1', '0.0.0.0', '::1', 'fe80::1', 'fc00::1', '::ffff:127.0.0.1', '::ffff:10.0.0.1', '224.0.0.1']) assert.equal(isNonPublicAddress(a), true, a)
    for (const a of ['8.8.8.8', '1.1.1.1', '172.32.0.1', '2606:4700:4700::1111', '::ffff:8.8.8.8']) assert.equal(isNonPublicAddress(a), false, a)
    assert.deepEqual(parseAuthority('Example.com:443'), { host: 'example.com', port: 443 })
    assert.deepEqual(parseAuthority('[2606:4700::1111]:443'), { host: '2606:4700::1111', port: 443 })
    for (const bad of ['example.com', 'user@example.com:443', 'example.com:0', 'example.com:70000', 'exa mple.com:443', '[::1:443', 'a/b:443', '']) assert.equal(parseAuthority(bad), null, bad)
  })

  it('tunnels HTTPS ports only, blocks trackers before DNS, refuses private targets, and refuses plain HTTP', async () => {
    const n = await track()
    // A plain TCP echo server stands in for an HTTPS origin: the proxy only moves bytes, it never looks inside.
    const echo: NetServer = tcpServer((s) => s.pipe(s)); await new Promise<void>((r) => echo.listen(0, '127.0.0.1', r))
    const echoPort = (echo.address() as { port: number }).port
    const strict = await startWebProxy(n.trackers, 0)
    const lax = await startWebProxy(n.trackers, 0, { allowPrivate: true, ports: [echoPort] })
    try {
      // Default policy: loopback is a non-public address, so a page cannot reach local services through the proxy.
      const priv = await connectVia(strict.port, '127.0.0.1:443'); priv.sock.destroy()
      assert.equal(priv.status, 403)
      const local = await connectVia(strict.port, 'localhost:443'); local.sock.destroy()
      assert.equal(local.status, 403)
      const wrongPort = await connectVia(strict.port, 'example.com:8080'); wrongPort.sock.destroy()
      assert.equal(wrongPort.status, 403)
      const bad = await connectVia(strict.port, 'example.com'); bad.sock.destroy()
      assert.equal(bad.status, 400)
      // Trackers: refused, counted, remembered in memory, and no tunnel was opened.
      const trk = await connectVia(strict.port, 'ad.doubleclick.net:443'); trk.sock.destroy()
      assert.equal(trk.status, 403)
      assert.match(trk.text, /tracker blocker/)
      assert.equal(n.trackers.snapshot().blocked, 1)
      assert.equal(n.trackers.snapshot().recent[0]!.host, 'ad.doubleclick.net')
      assert.equal(strict.stats().tunnels, 0)
      assert.deepEqual({ p: strict.stats().refusedPrivate, port: strict.stats().refusedPort, t: strict.stats().trackersBlocked }, { p: 2, port: 1, t: 1 })

      // A permitted tunnel moves bytes both ways, and allowed hosts are not recorded anywhere.
      const ok = await connectVia(lax.port, `127.0.0.1:${echoPort}`)
      assert.equal(ok.status, 200)
      const echoed = await new Promise<string>((resolve) => { ok.sock.once('data', (d) => resolve(String(d))); ok.sock.write('hello through the tunnel') })
      assert.equal(echoed, 'hello through the tunnel')
      assert.equal(lax.stats().tunnels, 1)
      ok.sock.destroy()
      assert.equal(JSON.stringify(n.trackers.snapshot()).includes('127.0.0.1'), false)

      // Plain HTTP is refused; the PAC file is served only for the proxy's own Host.
      assert.equal((await get(strict.port, `127.0.0.1:${strict.port}`, 'http://example.com/')).status, 426)
      assert.equal((await get(strict.port, 'evil.example', '/proxy.pac')).status, 403)
      const pac = await get(strict.port, `127.0.0.1:${strict.port}`, '/proxy.pac')
      assert.equal(pac.status, 200)
      assert.match(pac.body.toString(), new RegExp(`PROXY 127\\.0\\.0\\.1:${strict.port}`))
      assert.match(pac.body.toString(), /\.localhost/)   // FRENET sites bypass the proxy
    } finally {
      strict.server.close(); lax.server.close(); echo.close()
    }
  })
})

describe('site permissions and secure downloads', () => {
  it('denies everything by default, grants one feature to one origin, and revokes', async () => {
    const n = await track()
    const site = await n.sites.publish([{ path: 'index.html', data: bytes('<p>hi</p>') }])
    const origin = `site:${site.cid}`
    assert.equal(validOrigin(origin), true)
    for (const bad of ['site:nope', 'name:x', 'https://example.com', `site:${site.cid}x`, '']) assert.equal(validOrigin(bad), false, bad)
    const policy = () => n.permissions.policy(origin)
    for (const f of PERMISSION_FEATURES) assert.match(policy(), new RegExp(`${f}=\\(\\)`))
    assert.match(policy(), /interest-cohort=\(\)/)

    const gw = await startGateway(n, 0)
    try {
      const host = `${site.cid}.localhost:${gw.port}`
      assert.match((await get(gw.port, host)).headers['permissions-policy'], /camera=\(\)/)
      n.permissions.grant(origin, 'camera')
      const r = await get(gw.port, host)
      assert.match(r.headers['permissions-policy'], /camera=\(self\)/)
      assert.match(r.headers['permissions-policy'], /microphone=\(\)/)       // nothing else changed
      assert.match(r.headers['content-security-policy'], /default-src 'none'/) // a grant never loosens the CSP
      // Another site is unaffected.
      const other = await n.sites.publish([{ path: 'index.html', data: bytes('<p>other</p>') }])
      assert.match((await get(gw.port, `${other.cid}.localhost:${gw.port}`)).headers['permissions-policy'], /camera=\(\)/)
      assert.throws(() => n.permissions.grant(origin, 'payment'), /unknown permission/)
      assert.throws(() => n.permissions.grant('site:bad', 'camera'), /invalid origin/)
      assert.deepEqual(n.permissions.list().map((o) => [o.origin, o.grants.map((g) => g.feature)]), [[origin, ['camera']]])
      assert.equal(n.permissions.revoke(origin, 'camera'), true)
      assert.match((await get(gw.port, host)).headers['permissions-policy'], /camera=\(\)/)
    } finally { gw.server.close() }
  })

  it('serves non-renderable files, and anything with ?download=1, as sandboxed attachments with a safe filename', async () => {
    const n = await track()
    const site = await n.sites.publish([{ path: 'index.html', data: bytes('<p>x</p>') }, { path: 'files/tool.exe', data: bytes('MZ') }, { path: 'notes.txt', data: bytes('plain') }])
    const gw = await startGateway(n, 0)
    try {
      const host = `${site.cid}.localhost:${gw.port}`
      const exe = await get(gw.port, host, '/files/tool.exe')
      assert.equal(exe.headers['content-disposition'], 'attachment; filename="tool.exe"')
      assert.equal(exe.headers['content-type'], 'application/octet-stream')
      assert.match(exe.headers['content-security-policy'], /sandbox/)
      assert.equal(exe.headers['x-content-type-options'], 'nosniff')
      assert.ok(exe.headers['x-frenet-file'])
      const view = await get(gw.port, host, '/notes.txt')
      assert.equal(view.headers['content-disposition'], undefined)
      const dl = await get(gw.port, host, '/notes.txt?download=1')
      assert.equal(dl.headers['content-disposition'], 'attachment; filename="notes.txt"')
      assert.equal(dl.headers['content-type'], 'text/plain; charset=utf-8')
      assert.equal(dl.body.toString(), 'plain')
    } finally { gw.server.close() }
  })

  it('exposes it all through the local API with CSRF protection', async () => {
    const n = await track()
    const proxy = await startWebProxy(n.trackers, 0)
    const api = await startApi(n, 0, '127.0.0.1', undefined, proxy)
    const site = await n.sites.publish([{ path: 'index.html', data: bytes('<p>x</p>') }])
    const post = (path: string, body: unknown, headers: Record<string, string> = {}) => new Promise<{ status: number, json: any }>((resolve, reject) => {
      const r = request({ host: '127.0.0.1', port: api.port, path, method: 'POST', headers: { 'content-type': 'application/json', host: `127.0.0.1:${api.port}`, ...headers } }, (res) => {
        const c: Buffer[] = []; res.on('data', (d) => c.push(d)); res.on('end', () => resolve({ status: res.statusCode!, json: JSON.parse(Buffer.concat(c).toString() || '{}') }))
      })
      r.on('error', reject); r.end(JSON.stringify(body))
    })
    try {
      assert.equal((await post('/api/browser/permissions/grant', { origin: `site:${site.cid}`, feature: 'camera' }, { origin: 'http://evil.example' })).status, 403)
      assert.deepEqual(n.permissions.list(), [])
      const g = await post('/api/browser/permissions/grant', { origin: `site:${site.cid}`, feature: 'microphone' })
      assert.equal(g.status, 200)
      assert.equal(g.json.permissions.origins[0].grants[0].feature, 'microphone')
      assert.equal((await post('/api/browser/permissions/grant', { origin: 'bogus', feature: 'camera' })).status >= 400, true)
      const t = await post('/api/browser/trackers', { host: 'ads.example.net', action: 'block' })
      assert.equal(t.json.trackers.rules[0].host, 'ads.example.net')
      assert.equal(t.json.proxy.httpsOnly, true)
      assert.equal(n.trackers.check('ads.example.net').blocked, true)
    } finally { api.server.close(); proxy.server.close() }
  })
})
