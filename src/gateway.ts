import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http'
import { CID } from 'multiformats/cid'
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

export function startGateway (n: FrenetNode, port: number, host = '127.0.0.1'): Promise<{ server: Server, port: number }> {
  const server = createServer(async (req, res) => {
    try {
      const siteCid = siteFromHost(req.headers.host)
      if (!siteCid) return text(res, 404, 'Open a site at http://<site-id>.localhost:' + port + '/')
      if (req.method !== 'GET' && req.method !== 'HEAD') return text(res, 405, 'method not allowed')
      if (!fetchAllowed(req)) return text(res, 403, 'blocked cross-site subresource request')
      let path: string
      try { path = decodeURIComponent(new URL(req.url ?? '/', 'http://x').pathname) } catch { return text(res, 400, 'bad path') }
      const r = await n.sites.resolve(siteCid, path)
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
      text(res, 502, (err as Error).message)
    }
  })
  return new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(port, host, () => resolve({ server, port: (server.address() as { port: number }).port }))
  })
}
