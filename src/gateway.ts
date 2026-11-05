import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http'
import { CID } from 'multiformats/cid'
import { ContentBlocked } from './blocks.js'
import { NameNotFound, NAME_RE, validPub } from './names.js'
import type { FrenetNode } from './node.js'

/** Only types we are willing to render. Anything else is downloaded, never interpreted. */
const MIME: Record<string, string> = {
  html: 'text/html; charset=utf-8', htm: 'text/html; charset=utf-8', css: 'text/css; charset=utf-8',
  js: 'text/javascript; charset=utf-8', mjs: 'text/javascript; charset=utf-8', json: 'application/json',
  txt: 'text/plain; charset=utf-8', md: 'text/plain; charset=utf-8',
  png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg', gif: 'image/gif', webp: 'image/webp', svg: 'image/svg+xml', ico: 'image/x-icon',
  woff2: 'font/woff2', woff: 'font/woff', mp3: 'audio/mpeg', ogg: 'audio/ogg', mp4: 'video/mp4', webm: 'video/webm'
}

/**
 * Privacy-first CSP: a site can only load its own files. No third-party requests (they would leak the
 * visitor's IP and defeat the point), no framing, no <base>, forms only to itself.
 */
const SITE_CSP = "default-src 'none'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; font-src 'self'; media-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"

/** `<siteCid>.localhost` — every site gets its own browser origin, so sites cannot script each other. */
export function siteFromHost (host: string | undefined): string | null {
  const m = /^([a-z2-7]{20,63})\.localhost(?::\d+)?$/.exec(host ?? '')
  if (!m) return null
  try { return CID.parse(m[1]).toString() === m[1] ? m[1] : null } catch { return null }
}

/** `<name>.<publisher-key>.localhost` — a mutable name; its own browser origin, independent of which site version it points at. */
export function nameFromHost (host: string | undefined): { name: string, pub: string } | null {
  const m = /^([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)\.([a-z2-7]{52})\.localhost(?::\d+)?$/.exec(host ?? '')
  return m && NAME_RE.test(m[1]) && validPub(m[2]) ? { name: m[1], pub: m[2] } : null
}

/**
 * Block drive-by loads: a web page the user visits must not be able to make this node fetch
 * arbitrary CIDs via <img>/<iframe>/fetch. Browsers always send Sec-Fetch-*; plain clients (curl) send none.
 */
function fetchAllowed (req: IncomingMessage): boolean {
  const site = req.headers['sec-fetch-site']; const dest = req.headers['sec-fetch-dest']
  if (!site && !dest) return true
  return site === 'same-origin' || dest === 'document'
}

function text (res: ServerResponse, code: number, msg: string): void {
  res.writeHead(code, { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' })
  res.end(msg)
}

/** 451: the operator of this node has chosen not to serve this content (see Moderation). */
const blocked = (res: ServerResponse): void => text(res, 451, 'This content is blocked by the operator of this node.')

export function startGateway (n: FrenetNode, port: number, host = '127.0.0.1'): Promise<{ server: Server, port: number }> {
  const server = createServer(async (req, res) => {
    try {
      let siteCid = siteFromHost(req.headers.host)
      const named = siteCid ? null : nameFromHost(req.headers.host)
      if (!siteCid && !named) return text(res, 404, 'Open a site at http://<site-id>.localhost:' + port + '/ or http://<name>.<publisher-key>.localhost:' + port + '/')
      if (req.method !== 'GET' && req.method !== 'HEAD') return text(res, 405, 'method not allowed')
      if (!fetchAllowed(req)) return text(res, 403, 'blocked cross-site subresource request')
      // A blocked name or site is refused before any lookup: no DHT traffic for content the operator has refused.
      if (named && n.moderation.nameBlocked(named.name, named.pub)) return blocked(res)
      if (siteCid && n.moderation.isBlocked('cid', siteCid)) return blocked(res)
      // Resolve only after the checks above, so a drive-by request cannot make this node run DHT lookups.
      if (named) {
        try { siteCid = (await n.names.resolve(named.name, named.pub)).target } catch (e) {
          if (e instanceof ContentBlocked) return blocked(res)
          return text(res, e instanceof NameNotFound ? 404 : 502, (e as Error).message)
        }
        if (n.moderation.isBlocked('cid', siteCid)) return blocked(res)
      }
      let path: string
      try { path = decodeURIComponent(new URL(req.url ?? '/', 'http://x').pathname) } catch { return text(res, 400, 'bad path') }
      const r = await n.sites.resolve(siteCid!, path)
      if (!r) return text(res, 404, 'no such file in this site')
      const type = MIME[r.path.slice(r.path.lastIndexOf('.') + 1).toLowerCase()]
      res.writeHead(200, {
        'content-type': type ?? 'application/octet-stream',
        ...(type ? {} : { 'content-disposition': 'attachment' }),
        'content-length': r.data.length,
        'content-security-policy': SITE_CSP,
        'x-content-type-options': 'nosniff',
        'x-frame-options': 'DENY',
        'referrer-policy': 'no-referrer',
        'cross-origin-resource-policy': 'same-origin',
        'permissions-policy': 'camera=(), microphone=(), geolocation=(), interest-cohort=()',
        'cache-control': 'no-store'
      })
      res.end(req.method === 'HEAD' ? undefined : r.data)
    } catch (err) {
      if (err instanceof ContentBlocked) return blocked(res)   // e.g. one blocked file inside an otherwise fine site
      text(res, 502, (err as Error).message)
    }
  })
  return new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(port, host, () => resolve({ server, port: (server.address() as { port: number }).port }))
  })
}
