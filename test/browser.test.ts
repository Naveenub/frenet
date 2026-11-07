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
import { createArchive, restoreArchive } from '../src/archive.js'
import { BUILTIN_TRACKERS, normalizeHost } from '../src/trackers.js'
import { isNonPublicAddress, parseAuthority, parseUpstream, startWebProxy } from '../src/webproxy.js'

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

describe('imported tracker lists', () => {
  it('parses hosts, bare-domain and Adblock domain lines, skips the rest, and never overrides an allow rule', async () => {
    const n = await track()
    n.trackers.addRule('keep.example.com', 'allow')
    const r = n.trackers.importList([
      '# a comment', '! another', '[Adblock Plus 2.0]', '',
      '0.0.0.0 ads.one.test', '127.0.0.1 track.two.test  # trailing comment', 'bare.three.test', '||adblock.four.test^', '||adblock.five.test^$third-party',
      '0.0.0.0 keep.example.com', '127.0.0.1 localhost', '::1 ip6-localhost', '0.0.0.0 0.0.0.0',
      '||example.org/path^', '##.banner', 'not a domain line', '@@||allow.six.test^', '0.0.0.0 foo.local'
    ].join('\n'))
    assert.equal(r.added, 5)
    for (const h of ['ads.one.test', 'x.track.two.test', 'bare.three.test', 'adblock.four.test', 'adblock.five.test']) assert.equal(n.trackers.check(h).blocked, true, h)
    assert.equal(n.trackers.check('keep.example.com').blocked, false)
    assert.equal(n.trackers.check('example.org').blocked, false)
    assert.equal(n.trackers.snapshot().ruleCount, 6)                   // 5 imported + the allow rule
    assert.equal(n.trackers.importList('ads.one.test\nnew.seven.test').added, 1)   // re-import adds only what is new
    assert.throws(() => n.trackers.importList('x'.repeat(9 * 1024 * 1024)), /larger than/)
    assert.throws(() => n.trackers.importList(42), /text/)
    assert.equal(n.trackers.clearRules('block'), 6)
    assert.equal(n.trackers.check('ads.one.test').blocked, false)
    assert.equal(n.trackers.check('keep.example.com').blocked, false)
  })
  it('ships a built-in list of well over a hundred well-known domains with no duplicates or malformed entries', () => {
    assert.ok(BUILTIN_TRACKERS.length >= 150, String(BUILTIN_TRACKERS.length))
    for (const h of BUILTIN_TRACKERS) assert.equal(normalizeHost(h), h, h)
    assert.equal(new Set(BUILTIN_TRACKERS).size, BUILTIN_TRACKERS.length)
  })
})

describe('archive carries browser settings', () => {
  it('restores permission grants and tracker rules into a fresh data directory', async () => {
    const src = mkdtempSync(join(tmpdir(), 'frenet-ba-')); const dst = mkdtempSync(join(tmpdir(), 'frenet-bb-')); dirs.push(src, dst)
    const a = await startFrenet({ dataDir: src, listen: ['/ip4/127.0.0.1/tcp/0'], mdns: false, nat: false })
    const site = await a.sites.publish([{ path: 'index.html', data: bytes('<p>a</p>') }])
    a.permissions.grant(`site:${site.cid}`, 'camera'); a.permissions.grant(`site:${site.cid}`, 'fullscreen')
    a.trackers.addRule('ads.example.net', 'block'); a.trackers.addRule('fine.example.net', 'allow')
    await a.stop()
    const { bytes: arc, counts } = await createArchive(src, 'correct horse battery', { N: 2 ** 10 })
    assert.equal(counts.site_permissions, 2); assert.equal(counts.tracker_rules, 2)
    await restoreArchive(dst, arc, 'correct horse battery')
    const b = await track({ dataDir: dst })
    assert.deepEqual(b.permissions.granted(`site:${site.cid}`).sort(), ['camera', 'fullscreen'])
    assert.equal(b.trackers.check('ads.example.net').blocked, true)
    assert.equal(b.trackers.check('ok.fine.example.net').blocked, false)
  })
})

describe('SOCKS5 upstream', () => {
  it('parses upstream specs strictly', () => {
    assert.deepEqual(parseUpstream('socks5://127.0.0.1:9050'), { host: '127.0.0.1', port: 9050 })
    assert.deepEqual(parseUpstream('socks5h://localhost:9150'), { host: 'localhost', port: 9150 })
    for (const bad of ['http://127.0.0.1:9050', 'socks5://127.0.0.1', 'socks5://:9050', 'socks5://127.0.0.1:0', '127.0.0.1:9050']) assert.throws(() => parseUpstream(bad), /upstream/, bad)
  })

  it('hands the host name to the upstream unresolved (no local DNS), still blocks trackers first, and reports failures', async () => {
    const n = await track()
    const seen: Array<{ atyp: number, host: string, port: number }> = []
    const echo = tcpServer((s) => s.pipe(s)); await new Promise<void>((r) => echo.listen(0, '127.0.0.1', r))
    // A minimal no-auth SOCKS5 server that records what it was asked for, then bridges to the echo server.
    const socks = tcpServer((c) => {
      let stage = 0; let buf = Buffer.alloc(0)
      c.on('error', () => {})
      c.on('data', (d) => {
        if (stage === 2) return
        buf = Buffer.concat([buf, d])
        if (stage === 0 && buf.length >= 3) { c.write(Buffer.from([5, 0])); buf = buf.subarray(3); stage = 1 }
        if (stage === 1 && buf.length >= 5) {
          const atyp = buf[3]!; const len = atyp === 3 ? buf[4]! : atyp === 1 ? 4 : 16
          const need = 4 + (atyp === 3 ? 1 : 0) + len + 2
          if (buf.length < need) return
          const off = 4 + (atyp === 3 ? 1 : 0)
          const host = atyp === 3 ? buf.subarray(off, off + len).toString() : atyp === 1 ? [...buf.subarray(off, off + 4)].join('.') : 'v6'
          const port = buf.readUInt16BE(off + len)
          seen.push({ atyp, host, port }); stage = 2
          if (host.startsWith('refuse.')) { c.end(Buffer.from([5, 2, 0, 1, 0, 0, 0, 0, 0, 0])); return }
          const up = connect((echo.address() as { port: number }).port, '127.0.0.1', () => {
            c.write(Buffer.from([5, 0, 0, 1, 0, 0, 0, 0, 0, 0])); c.pipe(up); up.pipe(c)
          })
          up.on('error', () => c.destroy())
        }
      })
    })
    await new Promise<void>((r) => socks.listen(0, '127.0.0.1', r))
    const proxy = await startWebProxy(n.trackers, 0, { upstream: { host: '127.0.0.1', port: (socks.address() as { port: number }).port } })
    try {
      assert.equal(proxy.stats().upstream, `socks5://127.0.0.1:${(socks.address() as { port: number }).port}`)
      // This name cannot be resolved by this machine; it only works because resolution is left to the upstream.
      const ok = await connectVia(proxy.port, 'only-the-upstream-knows-me.invalid:443')
      assert.equal(ok.status, 200)
      const back = await new Promise<string>((resolve) => { ok.sock.once('data', (d) => resolve(String(d))); ok.sock.write('via socks') })
      assert.equal(back, 'via socks'); ok.sock.destroy()
      assert.deepEqual(seen[0], { atyp: 3, host: 'only-the-upstream-knows-me.invalid', port: 443 })
      // Non-public IP literals are still refused locally and never reach the upstream.
      const lit = await connectVia(proxy.port, '10.0.0.5:443'); lit.sock.destroy()
      assert.equal(lit.status, 403)
      // Trackers are refused before the upstream is contacted.
      const trk = await connectVia(proxy.port, 'ad.doubleclick.net:443'); trk.sock.destroy()
      assert.equal(trk.status, 403)
      assert.equal(seen.length, 1)
      // An upstream refusal comes back as a 502.
      const refused = await connectVia(proxy.port, 'refuse.example.com:443'); refused.sock.destroy()
      assert.equal(refused.status, 502)
      assert.match(refused.text, /upstream proxy refused/)
    } finally { proxy.server.close(); socks.close(); echo.close() }
  })
})
