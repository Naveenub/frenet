import { lookup } from 'node:dns/promises'
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http'
import { BlockList, connect, isIP, type Socket } from 'node:net'
import type { Duplex } from 'node:stream'
import { normalizeHost } from './trackers.js'
import type { TrackerBlocker } from './trackers.js'

/**
 * HTTPS browsing through a local, HTTPS-only CONNECT proxy.
 *
 * Point a normal browser at it (proxy auto-config at `http://127.0.0.1:<port>/proxy.pac`, or set the proxy by hand) and
 * regular HTTPS sites load as usual while FRENET sites on `*.localhost` go straight to the gateway. What it does:
 *  - **Tunnels TLS end to end.** It never decrypts, re-signs or inspects traffic and installs no certificate, so the
 *    site's own TLS (1.3 where the site supports it) is what protects the connection.
 *  - **Blocks trackers by host** before any DNS lookup (see TrackerBlocker).
 *  - **HTTPS only.** Plain-HTTP requests are refused (426); only port 443 is tunnelled unless configured otherwise.
 *  - **Cannot be used to reach your own machine or network.** The host is resolved here, every answer must be a public
 *    address, and the tunnel connects to that exact address, so a page cannot use DNS tricks to make the proxy talk to
 *    the FRENET control API, a router or a LAN service.
 *  - **Keeps no browsing history.** Allowed destinations are never logged or stored; only counters exist.
 *
 * Limits (inherent to not decrypting): it cannot block by URL, strip cookies or referrers, or filter content, and the
 * DNS lookup for each host is done by this machine's resolver. It is not an anonymity tool: the sites and your network
 * still see your IP. Use FRENET sites or a VPN/Tor for that.
 */
const PRIVATE = new BlockList()
for (const [a, p] of [['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16], ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15], ['198.51.100.0', 24], ['203.0.113.0', 24], ['224.0.0.0', 4], ['240.0.0.0', 4]] as const) PRIVATE.addSubnet(a, p, 'ipv4')
for (const [a, p] of [['::', 128], ['::1', 128], ['64:ff9b::', 96], ['100::', 64], ['2001:db8::', 32], ['fc00::', 7], ['fe80::', 10], ['ff00::', 8]] as const) PRIVATE.addSubnet(a, p, 'ipv6')

/** True for loopback, LAN, link-local, CGNAT, multicast, documentation and other non-public addresses (IPv4-mapped IPv6 included). */
export function isNonPublicAddress (ip: string): boolean {
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(ip)
  const v = isIP(mapped ? mapped[1]! : ip)
  if (!v) return true   // unparseable: refuse
  return PRIVATE.check(mapped ? mapped[1]! : ip, v === 4 ? 'ipv4' : 'ipv6')
}

export interface WebProxyOptions {
  /** Ports that may be tunnelled. Default [443]. */
  ports?: number[]
  /** Allow tunnels to loopback/LAN addresses. Default false; only for tests or a deliberate LAN setup. */
  allowPrivate?: boolean
  maxTunnels?: number
  idleMs?: number
  connectTimeoutMs?: number
  /**
   * Send every tunnel through a SOCKS5 proxy (no authentication), e.g. Tor at 127.0.0.1:9050. The host name is handed to
   * it unresolved, so this machine does not look it up (no DNS leak) and the destination site sees the upstream's address,
   * not yours. The non-public-address check can then only cover IP literals: the upstream resolves names, so use one that
   * refuses private destinations (Tor exits do). The tracker list and port rules still apply first.
   */
  upstream?: { host: string, port: number }
}

/** `socks5://host:port` (host may be `[v6]`). Throws on anything else. */
export function parseUpstream (spec: string): { host: string, port: number } {
  const m = /^socks5h?:\/\/(?:\[([0-9a-fA-F:]+)\]|([A-Za-z0-9.-]+)):(\d{1,5})$/.exec(spec.trim())
  const port = m ? Number(m[3]) : 0
  if (!m || port < 1 || port > 65535) throw new Error('upstream must look like socks5://127.0.0.1:9050')
  return { host: (m[1] ?? m[2])!, port }
}

/** Read exactly n bytes from a socket in paused (readable) mode, so nothing is lost between handshake steps. */
function readExact (s: Socket, n: number, ms: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const finish = (e: Error | null, b?: Buffer): void => {
      clearTimeout(timer); s.off('readable', tryRead); s.off('error', onErr); s.off('close', onClose)
      if (e) reject(e); else resolve(b!)
    }
    const tryRead = (): void => { const b = s.read(n) as Buffer | null; if (b) finish(null, b) }
    const onErr = (e: Error): void => finish(e)
    const onClose = (): void => finish(new Error('upstream closed'))
    const timer = setTimeout(() => finish(new Error('upstream timed out')), ms)
    s.on('readable', tryRead); s.once('error', onErr); s.once('close', onClose)
    tryRead()
  })
}

/** SOCKS5 CONNECT with no authentication. Resolves once the upstream says the tunnel is open. */
async function socks5Connect (s: Socket, host: string, port: number, ms: number): Promise<void> {
  s.write(Buffer.from([5, 1, 0]))
  const m = await readExact(s, 2, ms)
  if (m[0] !== 5 || m[1] !== 0) throw new Error('upstream refused no-auth SOCKS5')
  const v = isIP(host)
  if (v === 6 && host.includes('.')) throw new Error('unsupported IPv6 form')
  const addr = v === 4 ? Buffer.from([1, ...host.split('.').map(Number)])
    : v === 6 ? Buffer.concat([Buffer.from([4]), ipv6Bytes(host)])
      : Buffer.concat([Buffer.from([3, Buffer.byteLength(host)]), Buffer.from(host)])
  s.write(Buffer.concat([Buffer.from([5, 1, 0]), addr, Buffer.from([port >> 8, port & 255])]))
  const h = await readExact(s, 4, ms)
  if (h[0] !== 5 || h[1] !== 0) throw new Error(`upstream connect failed (code ${h[1]})`)
  const tail = h[3] === 1 ? 6 : h[3] === 4 ? 18 : h[3] === 3 ? (await readExact(s, 1, ms))[0]! + 2 : -1
  if (tail < 0) throw new Error('bad upstream reply')
  await readExact(s, tail, ms)   // bound address and port: not needed
}

function ipv6Bytes (ip: string): Buffer {
  const [head, tail = ''] = ip.split('::')
  const parse = (x: string): number[] => x ? x.split(':').flatMap((g) => { const n = parseInt(g, 16); return [n >> 8, n & 255] }) : []
  const a = parse(head!); const b = ip.includes('::') ? parse(tail) : []
  return Buffer.from(ip.includes('::') ? [...a, ...new Array(16 - a.length - b.length).fill(0), ...b] : a)
}

export interface ProxyStats { upstream: string | null, active: number, tunnels: number, trackersBlocked: number, refusedPrivate: number, refusedPort: number, refusedHttp: number, failed: number }

/** `host:port` or `[v6]:port` -> parts, or null. No userinfo, no paths. */
export function parseAuthority (a: string): { host: string, port: number } | null {
  const m = /^(?:\[([0-9a-fA-F:.]+)\]|([^:\[\]\s/@]+)):(\d{1,5})$/.exec(a)
  if (!m) return null
  const port = Number(m[3])
  if (port < 1 || port > 65535) return null
  if (m[1]) return isIP(m[1]) === 6 ? { host: m[1].toLowerCase(), port } : null
  const raw = m[2]!.toLowerCase().replace(/\.$/, '')
  if (isIP(raw) === 4) return { host: raw, port }
  if (raw === 'localhost') return { host: raw, port }   // refused later, with a clear reason
  const h = normalizeHost(raw)
  return h ? { host: h, port } : null
}

function deny (sock: Duplex, code: number, reason: string, why: string): void {
  if (!sock.writable) { sock.destroy(); return }
  sock.end(`HTTP/1.1 ${code} ${reason}\r\ncontent-type: text/plain; charset=utf-8\r\ncontent-length: ${Buffer.byteLength(why)}\r\nconnection: close\r\nx-frenet-proxy: refused\r\n\r\n${why}`)
}

export function startWebProxy (trackers: TrackerBlocker, port: number, opts: WebProxyOptions = {}, host = '127.0.0.1'): Promise<{ server: Server, port: number, stats: () => ProxyStats }> {
  const ports = new Set(opts.ports ?? [443])
  const maxTunnels = opts.maxTunnels ?? 256
  const idleMs = opts.idleMs ?? 5 * 60_000
  const connectMs = opts.connectTimeoutMs ?? 10_000
  const stats: ProxyStats = { upstream: opts.upstream ? `socks5://${opts.upstream.host}:${opts.upstream.port}` : null, active: 0, tunnels: 0, trackersBlocked: 0, refusedPrivate: 0, refusedPort: 0, refusedHttp: 0, failed: 0 }
  let listenPort = port

  const server = createServer((req: IncomingMessage, res: ServerResponse) => {
    // Only the PAC file is served over plain HTTP; the Host must be this proxy (DNS-rebinding defence).
    const hostOk = req.headers.host === `127.0.0.1:${listenPort}` || req.headers.host === `localhost:${listenPort}`
    if (req.method === 'GET' && hostOk && req.url === '/proxy.pac') {
      const pac = `function FindProxyForURL(url, host) {\n  if (host === "localhost" || dnsDomainIs(host, ".localhost") || host === "127.0.0.1") return "DIRECT";\n  if (url.substring(0, 6) === "https:") return "PROXY 127.0.0.1:${listenPort}";\n  return "DIRECT";\n}\n`
      res.writeHead(200, { 'content-type': 'application/x-ns-proxy-autoconfig', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' })
      return void res.end(pac)
    }
    stats.refusedHttp++
    const msg = 'FRENET web proxy is HTTPS-only: plain http:// requests are refused. Use https://.'
    res.writeHead(hostOk ? 426 : 403, { 'content-type': 'text/plain; charset=utf-8', upgrade: 'TLS/1.2, TLS/1.3', connection: 'close', 'cache-control': 'no-store' })
    res.end(msg)
  })

  server.on('connect', (req: IncomingMessage, client: Duplex, head: Buffer) => {
    client.on('error', () => client.destroy())
    void (async () => {
      const t = parseAuthority(req.url ?? '')
      if (!t) return deny(client, 400, 'Bad Request', 'bad CONNECT target')
      if (!ports.has(t.port)) { stats.refusedPort++; return deny(client, 403, 'Forbidden', `only HTTPS (port ${[...ports].join(', ')}) is allowed`) }
      if (t.host === 'localhost' || t.host.endsWith('.localhost')) { stats.refusedPrivate++; return deny(client, 403, 'Forbidden', 'local names are not proxied') }
      // Trackers are refused before any DNS lookup.
      if (!isIP(t.host) && trackers.refuse(t.host).blocked) { stats.trackersBlocked++; return deny(client, 403, 'Blocked by FRENET', 'blocked by the FRENET tracker blocker') }
      if (stats.active >= maxTunnels) return deny(client, 503, 'Service Unavailable', 'too many tunnels')

      let addr: string
      try {
        if (opts.upstream) {
          // Names are resolved by the upstream, not here; only IP literals can be checked locally.
          if (isIP(t.host) && !opts.allowPrivate && isNonPublicAddress(t.host)) { stats.refusedPrivate++; return deny(client, 403, 'Forbidden', 'refusing to connect to a non-public address') }
          addr = opts.upstream.host
        } else {
          const answers = isIP(t.host) ? [{ address: t.host }] : await lookup(t.host, { all: true, verbatim: true })
          if (answers.length === 0) throw new Error('no address')
          // Every answer must be public: one private record is enough to refuse (no picking the "good" one for an attacker-controlled name).
          if (!opts.allowPrivate && answers.some((a) => isNonPublicAddress(a.address))) { stats.refusedPrivate++; return deny(client, 403, 'Forbidden', 'refusing to connect to a non-public address') }
          addr = answers[0]!.address
        }
      } catch { stats.failed++; return deny(client, 502, 'Bad Gateway', 'could not resolve host') }
      if (!client.writable) return

      // Connect to the exact address that was checked (or to the SOCKS5 upstream), not to the name again.
      const upstream: Socket = connect({ host: addr, port: opts.upstream ? opts.upstream.port : t.port })
      upstream.setNoDelay(true)
      const cleanup = (): void => { client.destroy(); upstream.destroy() }
      let connected = false
      const timer = setTimeout(() => { if (connected) return; stats.failed++; deny(client, 504, 'Gateway Timeout', 'connect timed out'); upstream.destroy() }, connectMs)
      upstream.on('error', () => {
        clearTimeout(timer)
        if (connected) return cleanup()
        stats.failed++; deny(client, 502, 'Bad Gateway', 'connection failed'); upstream.destroy()
      })
      upstream.once('connect', () => { void (async () => {
        if (opts.upstream) {
          try { await socks5Connect(upstream, t.host, t.port, connectMs) } catch { clearTimeout(timer); stats.failed++; deny(client, 502, 'Bad Gateway', 'upstream proxy refused the connection'); upstream.destroy(); return }
        }
        clearTimeout(timer); connected = true
        stats.active++; stats.tunnels++
        let done = false
        const end = (): void => { if (!done) { done = true; stats.active-- } cleanup() }
        client.once('close', end); upstream.once('close', end)
        upstream.setTimeout(idleMs, end); (client as Socket).setTimeout(idleMs, end)
        client.write('HTTP/1.1 200 Connection Established\r\n\r\n')
        if (head.length) upstream.write(head)
        client.pipe(upstream); upstream.pipe(client)
      })() })
    })().catch(() => client.destroy())
  })

  server.on('clientError', (_e, s) => { s.destroy() })
  return new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(port, host, () => {
      listenPort = (server.address() as { port: number }).port
      resolve({ server, port: listenPort, stats: () => ({ ...stats }) })
    })
  })
}
