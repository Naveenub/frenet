import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http'
import { existsSync } from 'node:fs'
import { readFile } from 'node:fs/promises'
import { dirname, join, normalize } from 'node:path'
import { fileURLToPath } from 'node:url'
import { multiaddr } from '@multiformats/multiaddr'
import { peerIdFromString } from '@libp2p/peer-id'
import { ContentBlocked, DAY_MS } from './blocks.js'
import { didDocument, frenetId, isFrenetDid, resolveDid, toDid } from './did.js'
import { didDocumentFor } from './identity-log.js'
import { cleanKeywords, cleanTitle, NameNotFound, NAME_RE } from './names.js'
import { REPORT_CATEGORIES, TARGET_KINDS } from './moderation.js'
import type { FrenetNode } from './node.js'

const here = dirname(fileURLToPath(import.meta.url))

function webRoot (): string {
  // dist/web when built, ../web when run via tsx
  return [join(here, 'web'), join(here, '..', 'web')].find((p) => existsSync(join(p, 'index.html'))) ?? join(here, '..', 'web')
}

const MIME: Record<string, string> = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css' }

/**
 * Local control API. Binds to loopback only, rejects foreign Host headers (DNS rebinding)
 * and cross-origin state-changing requests (CSRF).
 */
export function startApi (n: FrenetNode, port: number, host = '127.0.0.1', gatewayPort?: number): Promise<{ server: Server, port: number }> {
  const clients = new Set<ServerResponse>()
  const push = (event: string, data: unknown): void => {
    const line = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`
    for (const c of clients) c.write(line)
  }
  n.libp2p.addEventListener('peer:connect', (e) => push('peer', { type: 'connect', peer: e.detail.toString() }))
  n.libp2p.addEventListener('peer:disconnect', (e) => push('peer', { type: 'disconnect', peer: e.detail.toString() }))
  n.messaging.on('message', (m) => push('message', { ...m, direction: 'in' }))
  n.messaging.on('dropped', (d) => push('dropped', d))
  n.calls.on('signal', (g) => push('signal', g))
  n.calls.on('dropped', (d) => push('dropped', { peer: d.peer, reason: `call: ${d.reason}` }))
  n.groups.on('community', (id) => push('community', { id }))
  n.groups.on('event', (e) => push('group', e))
  n.groups.on('dropped', (d) => push('dropped', { peer: d.peer, reason: `group: ${d.reason}` }))

  const root = webRoot()

  const server = createServer(async (req, res) => {
    try {
      if (!hostOk(req)) return json(res, 403, { error: 'bad host' })
      const url = new URL(req.url ?? '/', 'http://localhost')

      if (req.method === 'POST') {
        const origin = req.headers.origin
        if (origin && new URL(origin).host !== req.headers.host) return json(res, 403, { error: 'cross-origin' })
        if (!String(req.headers['content-type'] ?? '').startsWith('application/json')) return json(res, 415, { error: 'json only' })
      }

      if (req.method === 'GET' && url.pathname === '/api/status') return json(res, 200, await status(n, gatewayPort))
      if (req.method === 'GET' && url.pathname === '/api/peers') return json(res, 200, await peers(n))
      if (req.method === 'GET' && url.pathname === '/api/messages') {
        return json(res, 200, n.store.list(url.searchParams.get('peer') ?? undefined))
      }
      if (req.method === 'GET' && url.pathname === '/api/events') {
        res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-store', connection: 'keep-alive' })
        res.write(': ok\n\n')
        clients.add(res)
        req.on('close', () => clients.delete(res))
        return
      }
      if (req.method === 'POST' && url.pathname === '/api/blocks') {
        const b = await body(req)
        const ttl = b.ttlDays ? Number(b.ttlDays) * DAY_MS : undefined
        return json(res, 200, await n.blocks.put(Buffer.from(String(b.data ?? ''), 'base64'), ttl))
      }
      if (req.method === 'GET' && url.pathname.startsWith('/api/blocks/')) {
        const data = await n.blocks.get(decodeURIComponent(url.pathname.slice('/api/blocks/'.length)))
        if (!data) return json(res, 404, { error: 'no provider returned this block' })
        return json(res, 200, { data: Buffer.from(data).toString('base64') })
      }
      if (req.method === 'GET' && url.pathname === '/api/files') return json(res, 200, n.files.list().map((f) => ({ ...f, remembered: n.files.rememberedLink(f.cid) !== null })))
      if (req.method === 'GET' && url.pathname === '/api/files/link') return json(res, 200, { link: n.files.rememberedLink(String(url.searchParams.get('cid') ?? '')) })
      if (req.method === 'POST' && url.pathname === '/api/files') {
        const b = await body(req, 24 * 1024 * 1024)
        const ttl = b.ttlDays ? Number(b.ttlDays) * DAY_MS : undefined
        return json(res, 200, await n.files.add(String(b.name ?? 'file').slice(0, 255), Buffer.from(String(b.data ?? ''), 'base64'), { encrypt: b.encrypt !== false, ttlMs: ttl, remember: b.remember === true }))
      }
      if (req.method === 'POST' && url.pathname === '/api/files/get') {
        const b = await body(req)
        const f = await n.files.get(String(b.cid), b.key ? String(b.key) : null)
        return json(res, 200, { name: f.name, size: f.data.length, data: f.data.toString('base64') })
      }
      if (req.method === 'POST' && url.pathname === '/api/files/delete') {
        const b = await body(req)
        return json(res, 200, { deleted: n.files.remove(String(b.cid)) })
      }
      if (req.method === 'POST' && url.pathname === '/api/sites') {
        const b = await body(req, 48 * 1024 * 1024)
        if (!Array.isArray(b.files)) throw new Error('files must be an array')
        const entries = b.files.map((f: any) => ({ path: String(f?.path), data: Buffer.from(String(f?.data ?? ''), 'base64') }))
        const ttl = b.ttlDays ? Number(b.ttlDays) * DAY_MS : undefined
        // Validate the naming fields first so a bad name does not leave a published-but-unnamed site behind.
        const name = b.name === undefined || b.name === '' ? null : String(b.name)
        if (name !== null && !NAME_RE.test(name)) throw new Error('invalid name (1-63 chars: a-z, 0-9, hyphen; not starting/ending with a hyphen)')
        const title = cleanTitle(b.title)
        const keywords = cleanKeywords(b.keywords)
        const r = await n.sites.publish(entries, { ...(b.index ? { index: String(b.index) } : {}), ...(ttl ? { ttlMs: ttl } : {}) })
        const named = name ? await n.names.publish(name, r.cid, { title, keywords }) : null
        const url = gatewayPort ? `http://${named ? `${name}.${named.record.pub}` : r.cid}.localhost:${gatewayPort}/` : null
        return json(res, 200, { ...r, url, siteUrl: gatewayPort ? `http://${r.cid}.localhost:${gatewayPort}/` : null, name: named ? { link: named.link, seq: named.record.seq, announced: named.announced } : null })
      }
      if (req.method === 'GET' && url.pathname === '/api/names') return json(res, 200, { publisher: n.names.publisherKey, names: n.names.list() })
      if (req.method === 'GET' && url.pathname === '/api/names/resolve') {
        const r = await n.names.resolve(String(url.searchParams.get('name') ?? ''), String(url.searchParams.get('pub') ?? ''), { fresh: true }).catch((e) => { if (e instanceof NameNotFound) return null; throw e })
        return r ? json(res, 200, r) : json(res, 404, { error: 'name not found' })
      }
      if (req.method === 'GET' && url.pathname === '/api/search') {
        const q = String(url.searchParams.get('q') ?? '').slice(0, 200)
        return json(res, 200, { query: q, results: await n.names.search(q) })
      }
      if (req.method === 'GET' && url.pathname === '/api/identity') {
        const st = n.identity
        return json(res, 200, {
          peerId: n.libp2p.peerId.toString(),
          did: n.did,
          keyDid: n.keyDid,
          document: st ? didDocumentFor(st) : didDocument(n.keyDid),
          rotation: st ? { enabled: true, seq: st.seq, events: st.events.length, nextKeyDigest: st.next } : { enabled: false }
        })
      }
      if (req.method === 'GET' && url.pathname === '/api/identity/log') {
        // Public, self-certifying key log of a did:frenet (ours by default). Save it with your next-key backup.
        const id = url.searchParams.get('id') ?? n.identity?.id ?? ''
        const st = await n.identityLogs.resolve(id)
        return st ? json(res, 200, st.events) : json(res, 404, { error: 'no key log known for this identity' })
      }
      if (req.method === 'GET' && url.pathname === '/api/did/resolve') {
        // Accepts a DID / DID URL, or an Ed25519 peer ID (converted to its did:key). did:key needs no network; did:frenet uses its key log.
        const q = String(url.searchParams.get('did') ?? url.searchParams.get('peer') ?? '')
        const bare = q.split('#')[0]!
        if (isFrenetDid(bare)) {
          const st = await n.identityLogs.resolve(frenetId(bare))
          return st ? json(res, 200, didDocumentFor(st)) : json(res, 404, { error: 'no key log known for this identity' })
        }
        return json(res, 200, resolveDid(q.startsWith('did:') ? q : toDid(q)).document)
      }
      if (req.method === 'GET' && url.pathname === '/api/credentials') return json(res, 200, { did: n.did, credentials: n.credentials.list(), revocations: n.store.listRevocations().length })
      if (req.method === 'POST' && url.pathname === '/api/credentials/issue') {
        const b = await body(req)
        const ttl = b.ttlDays === undefined || b.ttlDays === null || b.ttlDays === '' ? undefined : Number(b.ttlDays) * DAY_MS
        return json(res, 200, await n.credentials.issue(String(b.subject ?? ''), String(b.type ?? ''), b.claims, ttl === undefined ? {} : { ttlMs: ttl }))
      }
      if (req.method === 'POST' && url.pathname === '/api/credentials/verify') {
        // online (default): also looks for revocations / key rotations on the network; offline: local knowledge only. strict: refuse superseded keys.
        const b = await body(req, 20 * 1024)
        return json(res, 200, await n.credentials.verify(b.jwt, { online: b.offline !== true, strict: b.strict === true }))
      }
      if (req.method === 'POST' && url.pathname === '/api/credentials/import') return json(res, 200, { credential: await n.credentials.hold((await body(req, 20 * 1024)).jwt) })
      if (req.method === 'POST' && url.pathname === '/api/credentials/delete') { const b = await body(req); return json(res, 200, { deleted: n.credentials.remove(String(b.id), b.role === 'issued' ? 'issued' : 'held') }) }
      if (req.method === 'POST' && url.pathname === '/api/credentials/revoke') return json(res, 200, await n.credentials.revoke(String((await body(req)).id)))
      if (req.method === 'POST' && url.pathname === '/api/credentials/revocations') return json(res, 200, await n.credentials.importRevocation((await body(req, 4096)).jwt))
      if (req.method === 'POST' && url.pathname === '/api/presentations/create') {
        const b = await body(req)
        const ttl = b.ttlSeconds === undefined || b.ttlSeconds === null || b.ttlSeconds === '' ? undefined : Number(b.ttlSeconds) * 1000
        return json(res, 200, await n.credentials.present(b.credentials as string[], String(b.nonce ?? ''), { ...(b.audience !== undefined ? { audience: String(b.audience) } : {}), ...(ttl === undefined ? {} : { ttlMs: ttl }) }))
      }
      if (req.method === 'POST' && url.pathname === '/api/presentations/verify') {
        const b = await body(req, 100 * 1024)
        return json(res, 200, await n.credentials.verifyPresentation(b.jwt, String(b.nonce ?? ''), b.audience === undefined ? undefined : String(b.audience), { online: b.offline !== true, strict: b.strict === true }))
      }
      if (req.method === 'POST' && url.pathname === '/api/send') {
        const b = await body(req)
        const r = await n.messaging.send(peerIdFromString(String(b.peer)), String(b.body ?? ''))
        push('message', { ...r, peer: b.peer, body: b.body, direction: 'out' })
        return json(res, 200, r)
      }
      if (req.method === 'POST' && url.pathname === '/api/call/signal') {
        const b = await body(req)
        await n.calls.send(peerIdFromString(String(b.peer)), String(b.call), String(b.kind), String(b.data ?? ''))
        return json(res, 200, { ok: true })
      }
      if (req.method === 'GET' && url.pathname === '/api/operator') return json(res, 200, n.operator.snapshot())
      if (req.method === 'POST' && url.pathname === '/api/operator/ban') { const b = await body(req); await n.operator.ban(b.peer, b.reason); return json(res, 200, { ok: true }) }
      if (req.method === 'POST' && url.pathname === '/api/operator/unban') return json(res, 200, { removed: n.operator.unban((await body(req)).peer) })
      if (req.method === 'POST' && url.pathname === '/api/operator/disconnect') { await n.operator.disconnect((await body(req)).peer); return json(res, 200, { ok: true }) }
      if (req.method === 'POST' && url.pathname === '/api/operator/sweep') return json(res, 200, { removed: n.operator.sweep() })
      if (req.method === 'POST' && url.pathname === '/api/operator/reannounce') return json(res, 200, await n.blocks.reannounce())
      if (req.method === 'GET' && url.pathname === '/api/moderation') {
        return json(res, 200, { kinds: TARGET_KINDS, categories: REPORT_CATEGORIES, blocklist: n.moderation.list(), reports: n.moderation.listReports() })
      }
      if (req.method === 'POST' && url.pathname === '/api/moderation/report') {
        // `block: true` files the report and blocks its target in one step; otherwise it only records it.
        const b = await body(req)
        const report = await n.moderation.report(b)
        if (b.block !== true) return json(res, 200, { report, purged: null })
        const done = n.moderation.resolve(report.id, 'block', b.reason)
        return json(res, 200, { report: done.report, purged: done.purged })
      }
      if (req.method === 'POST' && url.pathname === '/api/moderation/block') { const b = await body(req); return json(res, 200, n.moderation.block(b.kind, b.target, b.reason)) }
      if (req.method === 'POST' && url.pathname === '/api/moderation/unblock') { const b = await body(req); return json(res, 200, { removed: n.moderation.unblock(b.kind, b.target) }) }
      if (req.method === 'POST' && url.pathname === '/api/moderation/resolve') { const b = await body(req); return json(res, 200, n.moderation.resolve(b.id, b.action, b.reason)) }
      if (req.method === 'GET' && url.pathname === '/api/communities') return json(res, 200, n.groups.list())
      if (req.method === 'POST' && url.pathname === '/api/communities') { const b = await body(req); return json(res, 200, await n.groups.create(b.name, b.members ?? [])) }
      if (req.method === 'POST' && url.pathname === '/api/communities/members') { const b = await body(req); return json(res, 200, await n.groups.setMembers(String(b.id), b.members)) }
      if (req.method === 'POST' && url.pathname === '/api/communities/join') { n.groups.join(String((await body(req)).id)); return json(res, 200, { ok: true }) }
      if (req.method === 'POST' && url.pathname === '/api/communities/leave') { n.groups.leave(String((await body(req)).id)); return json(res, 200, { ok: true }) }
      if (req.method === 'GET' && url.pathname === '/api/communities/messages') return json(res, 200, n.groups.messages(String(url.searchParams.get('id') ?? '')))
      if (req.method === 'POST' && url.pathname === '/api/communities/post') { const b = await body(req); return json(res, 200, await n.groups.post(String(b.id), b.text)) }
      if (req.method === 'GET' && url.pathname === '/api/communities/proposals') return json(res, 200, n.groups.proposals(String(url.searchParams.get('id') ?? '')))
      if (req.method === 'POST' && url.pathname === '/api/communities/propose') { const b = await body(req); return json(res, 200, await n.groups.propose(String(b.id), b.title, b.text, Number(b.hours) * 3_600_000)) }
      if (req.method === 'POST' && url.pathname === '/api/communities/vote') { const b = await body(req); return json(res, 200, await n.groups.vote(String(b.id), b.proposal, b.choice)) }
      if (req.method === 'POST' && url.pathname === '/api/dial') {
        const b = await body(req)
        await n.libp2p.dial(multiaddr(String(b.addr)))
        return json(res, 200, { ok: true })
      }

      if (req.method === 'GET') {
        const rel = url.pathname === '/' ? 'index.html' : normalize(url.pathname).replace(/^(\.\.[/\\])+/, '')
        const file = join(root, rel)
        if (!file.startsWith(root)) return json(res, 403, { error: 'forbidden' })
        const ext = file.slice(file.lastIndexOf('.'))
        const data = await readFile(file).catch(() => null)
        if (!data) return json(res, 404, { error: 'not found' })
        res.writeHead(200, {
          'content-type': MIME[ext] ?? 'application/octet-stream',
          'content-security-policy': "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'",
          'x-content-type-options': 'nosniff',
          'referrer-policy': 'no-referrer'
        })
        return void res.end(data)
      }
      json(res, 405, { error: 'method not allowed' })
    } catch (err) {
      // 451: the operator of this node has chosen not to store, fetch or serve this content (see Moderation).
      json(res, err instanceof ContentBlocked ? 451 : 400, { error: (err as Error).message })
    }
  })

  return new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(port, host, () => resolve({ server, port: (server.address() as { port: number }).port }))
  })
}

function hostOk (req: IncomingMessage): boolean {
  const h = (req.headers.host ?? '').replace(/:\d+$/, '')
  return h === '127.0.0.1' || h === 'localhost' || h === '[::1]'
}

function json (res: ServerResponse, code: number, data: unknown): void {
  res.writeHead(code, { 'content-type': 'application/json', 'cache-control': 'no-store' })
  res.end(JSON.stringify(data))
}

async function body (req: IncomingMessage, max = 64 * 1024): Promise<Record<string, unknown>> {
  let size = 0
  const chunks: Buffer[] = []
  for await (const c of req) {
    size += (c as Buffer).length
    if (size > max) throw new Error('body too large')
    chunks.push(c as Buffer)
  }
  return JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}')
}

async function status (n: FrenetNode, gatewayPort?: number): Promise<unknown> {
  const l = n.libp2p
  const dht = (l.services as any).dht
  return {
    peerId: l.peerId.toString(),
    did: n.did,
    keyDid: n.keyDid,
    addresses: l.getMultiaddrs().map(String),
    connections: l.getConnections().length,
    gatewayPort: gatewayPort ?? null,
    nat: {
      enabled: !!(l.services as any).autonat,
      relayServer: !!(l.services as any).relay,
      relayedAddresses: l.getMultiaddrs().map(String).filter((a) => a.includes('/p2p-circuit'))
    },
    calls: { iceServers: n.iceServers },
    uptimeMs: Date.now() - n.startedAt,
    dht: { protocol: '/frenet/kad/1.0.0', routingTableSize: dht?.routingTable?.size ?? 0 },
    messages: n.store.count(),
    blocks: {
      ...n.store.blockStats(),
      quotaBytes: n.blocks.retention.quotaBytes,
      replicaTtlDays: n.blocks.retention.replicaTtlMs / DAY_MS,
      reannounceHours: n.blocks.retention.reannounceMs / 3_600_000,
      lastReannounce: n.blocks.lastReannounce
    },
    moderation: n.moderation.counts(),
    files: n.files.list().length,
    names: { publisher: n.names.publisherKey, known: n.names.list().length },
    privacy: {
      transportEncryption: 'Noise XX (ChaCha20-Poly1305), forward secret',
      identity: 'Ed25519, key stored locally only',
      telemetry: 'none',
      apiBind: 'loopback only'
    }
  }
}

async function peers (n: FrenetNode): Promise<unknown[]> {
  const out = []
  for (const c of n.libp2p.getConnections()) {
    let latencyMs: number | null = null
    try { latencyMs = await (n.libp2p.services as any).ping.ping(c.remotePeer, { signal: AbortSignal.timeout(2000) }) } catch {}
    out.push({
      peer: c.remotePeer.toString(),
      address: c.remoteAddr.toString(),
      direction: c.direction,
      relayed: c.remoteAddr.toString().includes('/p2p-circuit'),
      encryption: c.encryption,
      muxer: c.multiplexer,
      openedAt: c.timeline.open,
      latencyMs
    })
  }
  return out
}
