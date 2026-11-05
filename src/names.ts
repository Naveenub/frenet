import { publicKeyFromRaw } from '@libp2p/crypto/keys'
import type { Libp2p, PeerId, PrivateKey } from '@libp2p/interface'
import { base32 } from 'multiformats/bases/base32'
import { CID } from 'multiformats/cid'
import { cidFor, ContentBlocked, type Blocks } from './blocks.js'
import { RateLimiter } from './messaging.js'
import type { Moderation } from './moderation.js'
import type { ReputationEvent } from './reputation.js'
import { validCid } from './sites.js'
import type { Store } from './store.js'

export const NAME_PROTOCOL = '/frenet/name/1.0.0'
export const NAME_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/
export const KEYWORD_RE = /^[a-z0-9]{2,32}$/
const PUB_RE = /^[a-z2-7]{52}$/
const MAX_TITLE = 80
const MAX_KEYWORDS = 8
const MAX_SKEW_MS = 5 * 60 * 1000
const MAX_REQUEST_BYTES = 512
const MAX_RESPONSE_BYTES = 64 * 1024
const KW_RESULTS = 20
const PROVIDERS_PER_LOOKUP = 8
const SIG_DOMAIN = 'frenet-name/v1'
const REANNOUNCE_MS = 6 * 60 * 60 * 1000
const RESOLVE_CACHE_MS = 15_000
const SIG_RE = /^[A-Za-z0-9+/]{86}==$/

/**
 * A name record points `<name>.<pub>` at a site ID. It is signed by the publisher's Ed25519 key, and `pub`
 * (the base32 raw public key) is part of the name itself, so names are self-certifying: nobody else can
 * issue or change a record for your names, and no registry exists that could be captured or censored.
 * A higher `seq` replaces a lower one: that is how a site is updated while its name stays the same.
 */
export interface NameRecord {
  v: 1
  name: string
  pub: string
  target: string
  seq: number
  ts: number
  keywords: string[]
  title: string
  sig: string
}

export interface NameHit extends NameRecord { link: string, own: boolean }

export class NameNotFound extends Error { constructor () { super('name not found'); this.name = 'NameNotFound' } }

export const pubToB32 = (raw: Uint8Array): string => base32.baseEncode(raw)

/** 52-char base32 of a raw Ed25519 public key (round-trip checked so non-canonical encodings are rejected). */
export function validPub (p: unknown): p is string {
  if (typeof p !== 'string' || !PUB_RE.test(p)) return false
  try { const raw = base32.baseDecode(p); return raw.length === 32 && base32.baseEncode(raw) === p } catch { return false }
}

export const nameLink = (name: string, pub: string): string => `frenet-name://${name}.${pub}`

/** Lowercase alphanumeric tokens (deduped, bounded) from free text; used for search queries. */
export function tokenize (q: string): string[] {
  return [...new Set(q.toLowerCase().split(/[^a-z0-9]+/).filter((t) => KEYWORD_RE.test(t)))].slice(0, 5)
}

/** Fields before `title` cannot contain newlines; `title` is last and control characters are rejected. */
function signedBytes (r: Omit<NameRecord, 'sig'>): Uint8Array {
  return Buffer.from(`${SIG_DOMAIN}\n${r.name}\n${r.pub}\n${r.target}\n${r.seq}\n${r.ts}\n${r.keywords.join(',')}\n${r.title}`, 'utf8')
}

export async function signRecord (key: PrivateKey, r: Omit<NameRecord, 'sig'>): Promise<NameRecord> {
  return { ...r, sig: Buffer.from(await key.sign(signedBytes(r))).toString('base64') }
}

/** Normalise publisher-supplied keywords: lowercase, valid, deduped, max 8. Throws on junk instead of silently dropping. */
export function cleanKeywords (input: unknown): string[] {
  if (input === undefined || input === null) return []
  if (!Array.isArray(input)) throw new Error('keywords must be an array')
  const out = [...new Set(input.map((k) => String(k).trim().toLowerCase()).filter((k) => k !== ''))]
  if (out.length > MAX_KEYWORDS) throw new Error(`too many keywords (max ${MAX_KEYWORDS})`)
  for (const k of out) if (!KEYWORD_RE.test(k)) throw new Error(`invalid keyword: ${k.slice(0, 40)} (use 2-32 letters/digits)`)
  return out
}

export function cleanTitle (input: unknown): string {
  const t = typeof input === 'string' ? input.trim() : ''
  // eslint-disable-next-line no-control-regex
  if (t.length > MAX_TITLE || /[\u0000-\u001f\u007f]/.test(t)) throw new Error(`invalid title (max ${MAX_TITLE} chars, no control characters)`)
  return t
}

/** The publisher is untrusted: validate every field and the signature. Returns null for anything off. */
export async function validateRecord (x: unknown, now = Date.now()): Promise<NameRecord | null> {
  try {
    const r = x as any
    if (typeof r !== 'object' || r === null || r.v !== 1) return null
    if (typeof r.name !== 'string' || !NAME_RE.test(r.name)) return null
    if (!validPub(r.pub) || !validCid(r.target)) return null
    if (!Number.isSafeInteger(r.seq) || r.seq < 1 || !Number.isSafeInteger(r.ts) || r.ts <= 0 || r.ts > now + MAX_SKEW_MS) return null
    if (!Array.isArray(r.keywords) || r.keywords.length > MAX_KEYWORDS || !r.keywords.every((k: unknown) => typeof k === 'string' && KEYWORD_RE.test(k))) return null
    if (new Set(r.keywords).size !== r.keywords.length) return null
    if (typeof r.title !== 'string' || r.title.length > MAX_TITLE || /[\u0000-\u001f\u007f]/.test(r.title)) return null   // eslint-disable-line no-control-regex
    if (typeof r.sig !== 'string' || !SIG_RE.test(r.sig)) return null
    const rec: NameRecord = { v: 1, name: r.name, pub: r.pub, target: r.target, seq: r.seq, ts: r.ts, keywords: [...r.keywords], title: r.title, sig: r.sig }
    const pk = publicKeyFromRaw(base32.baseDecode(rec.pub))
    return (await pk.verify(signedBytes(rec), Buffer.from(rec.sig, 'base64'))) ? rec : null
  } catch { return null }
}

const nameKeyCid = (name: string, pub: string): CID => cidFor(Buffer.from(`frenet-name/v1\n${name}\n${pub}`))
const keywordCid = (word: string): CID => cidFor(Buffer.from(`frenet-kw/v1\n${word}`))

/**
 * Names and search on top of the DHT. A record is announced as a provider record under a key derived from its name
 * (resolution) and under one key per keyword (search); peers that provide those keys serve the signed records over
 * `/frenet/name/1.0.0`. Everything fetched is verified, and the highest `seq` seen wins.
 */
export class Names {
  private limiter = new RateLimiter(60, 10)
  private cache = new Map<string, { rec: NameRecord, at: number }>()
  private timer: NodeJS.Timeout | null = null
  readonly publisherKey: string
  /** Set by the node: told which provider served a valid or a forged record. */
  report: (peer: string, event: ReputationEvent, detail?: string) => void = () => {}

  constructor (private node: Libp2p, private store: Store, private blocks: Blocks, private key: PrivateKey, private moderation: Moderation) {
    this.publisherKey = pubToB32(key.publicKey.raw)
  }

  async start (): Promise<void> {
    await this.node.handle(NAME_PROTOCOL, async (stream, connection) => {
      try {
        if (!this.limiter.allow(connection.remotePeer.toString())) { stream.abort(new Error('rate limited')); return }
        const chunks: Uint8Array[] = []
        let n = 0
        for await (const c of stream) { n += c.byteLength; if (n > MAX_REQUEST_BYTES) { stream.abort(new Error('too large')); return }; chunks.push(c.subarray()) }
        const req = JSON.parse(Buffer.concat(chunks).toString('utf8'))
        let out: unknown = null
        if (req?.k === 'name' && typeof req.name === 'string' && NAME_RE.test(req.name) && validPub(req.pub)) {
          out = this.allowed(this.store.getName(req.name, req.pub)?.record)
        } else if (req?.k === 'kw' && typeof req.word === 'string' && KEYWORD_RE.test(req.word)) {
          out = this.store.listNames().filter((r) => r.record.keywords.includes(req.word) && this.allowed(r.record)).slice(0, KW_RESULTS).map((r) => r.record)
        } else { stream.abort(new Error('bad request')); return }
        stream.send(Buffer.from(JSON.stringify(out)))
        await stream.close()
      } catch { stream.abort(new Error('bad request')) }
    }, { maxInboundStreams: 32, maxOutboundStreams: 32, runOnLimitedConnection: true })
    // DHT provider records expire, so keep our own names findable.
    this.timer = setInterval(() => { void this.reannounceOwn() }, REANNOUNCE_MS)
    this.timer.unref()
  }

  async stop (): Promise<void> {
    if (this.timer) clearInterval(this.timer)
    await this.node.unhandle(NAME_PROTOCOL)
  }

  /** Sign and publish a record for `<name>.<our key>`. seq = highest known (locally or on the network) + 1. */
  async publish (name: string, target: string, opts: { title?: unknown, keywords?: unknown } = {}): Promise<{ record: NameRecord, link: string, announced: boolean }> {
    if (!NAME_RE.test(name)) throw new Error('invalid name (1-63 chars: a-z, 0-9, hyphen; not starting/ending with a hyphen)')
    if (!validCid(target)) throw new Error('invalid site id')
    if (this.moderation.nameBlocked(name, this.publisherKey, target)) throw new ContentBlocked('this name or site')
    const title = cleanTitle(opts.title)
    const keywords = cleanKeywords(opts.keywords)
    const pub = this.publisherKey
    // If our data dir was lost but the key kept, the network may know a higher seq than we do.
    let seq = this.store.getName(name, pub)?.seq ?? 0
    const known = await this.fetchFromNetwork(name, pub, 3000).catch(() => null)
    if (known && known.seq > seq) seq = known.seq
    const unsigned = { v: 1 as const, name, pub, target, seq: seq + 1, ts: Date.now(), keywords, title }
    const record = await validateRecord(await signRecord(this.key, unsigned))
    if (!record) throw new Error('internal error: produced an invalid record')
    this.store.putName(record, true)
    this.cache.set(`${name}.${pub}`, { rec: record, at: Date.now() })
    const announced = await this.announce(record)
    return { record, link: nameLink(name, pub), announced }
  }

  /** Store a verified record from the network. Returns true if it replaced/created our copy. */
  private async accept (x: unknown): Promise<NameRecord | null> {
    const rec = await validateRecord(x)
    if (!rec) return null
    // A valid record the operator has blocked is simply not kept (and not held against the peer that sent it).
    if (!this.moderation.nameBlocked(rec.name, rec.pub, rec.target)) this.store.putName(rec, false)
    return rec
  }

  /** Latest record for a name. Asks the network (highest seq wins) and falls back to our cached copy. */
  async resolve (name: string, pub: string, opts: { fresh?: boolean } = {}): Promise<NameRecord> {
    if (!NAME_RE.test(name) || !validPub(pub)) throw new Error('invalid name')
    if (this.moderation.nameBlocked(name, pub)) throw new ContentBlocked('this name')
    const k = `${name}.${pub}`
    const hit = this.cache.get(k)
    if (hit && !opts.fresh && Date.now() - hit.at < RESOLVE_CACHE_MS) return hit.rec
    const local = this.store.getName(name, pub)?.record ?? null
    const remote = pub === this.publisherKey ? null : await this.fetchFromNetwork(name, pub, 6000).catch(() => null)
    const best = remote && (!local || remote.seq > local.seq) ? remote : local
    if (!best) throw new NameNotFound()
    if (this.moderation.nameBlocked(name, pub, best.target)) throw new ContentBlocked('the site this name points to')
    this.cache.set(k, { rec: best, at: Date.now() })
    return best
  }

  private async fetchFromNetwork (name: string, pub: string, ms: number): Promise<NameRecord | null> {
    const signal = AbortSignal.timeout(ms)
    let best: NameRecord | null = null
    let asked = 0
    try {
      for await (const prov of this.node.contentRouting.findProviders(nameKeyCid(name, pub), { signal })) {
        if (prov.id.equals(this.node.peerId)) continue
        if (++asked > PROVIDERS_PER_LOOKUP) break
        const raw = await this.ask(prov, { k: 'name', name, pub }, signal)
        const rec = await this.accept(raw)
        if (raw !== null && raw !== undefined) this.report(prov.id.toString(), rec && rec.name === name && rec.pub === pub ? 'valid-record' : 'bad-record', 'name lookup')
        if (rec && rec.name === name && rec.pub === pub && (!best || rec.seq > best.seq)) best = rec
      }
    } catch { /* no providers / timeout: use what we have */ }
    return best
  }

  private async ask (prov: { id: PeerId, multiaddrs: any[] }, req: object, signal: AbortSignal): Promise<unknown> {
    try {
      if (prov.multiaddrs.length) await this.node.peerStore.merge(prov.id, { multiaddrs: prov.multiaddrs })
      const stream = await this.node.dialProtocol(prov.id, NAME_PROTOCOL, { signal, runOnLimitedConnection: true })
      stream.send(Buffer.from(JSON.stringify(req)))
      await stream.close()
      const chunks: Uint8Array[] = []
      let n = 0
      for await (const c of stream) { n += c.byteLength; if (n > MAX_RESPONSE_BYTES) throw new Error('oversize'); chunks.push(c.subarray()) }
      return JSON.parse(Buffer.concat(chunks).toString('utf8'))
    } catch { return null }
  }

  /** The record itself if the operator has not blocked it (by name, publisher or target site), else null. */
  private allowed (rec: NameRecord | null | undefined): NameRecord | null {
    return rec && !this.moderation.nameBlocked(rec.name, rec.pub, rec.target) ? rec : null
  }

  async announce (rec: NameRecord): Promise<boolean> {
    let ok = true
    for (const cid of [nameKeyCid(rec.name, rec.pub), ...rec.keywords.map(keywordCid)]) {
      try { await this.node.contentRouting.provide(cid, { signal: AbortSignal.timeout(5000) }) } catch { ok = false }
    }
    return ok
  }

  private async reannounceOwn (): Promise<void> {
    for (const r of this.store.listNames(true)) if (this.allowed(r.record)) await this.announce(r.record)
  }

  /**
   * Keyword search. Local: every record this node knows. Network: for each query word, providers of that keyword
   * are asked for their records; each is signature-checked and must really carry the word. A hit must match every
   * word. Limits: only names whose publisher chose keywords are findable, and there is no ranking beyond
   * "own first, then newest": anyone can publish spam under any keyword.
   */
  async search (q: string, opts: { network?: boolean } = {}): Promise<NameHit[]> {
    const words = tokenize(q)
    if (words.length === 0) return []
    if (opts.network !== false) {
      const signal = AbortSignal.timeout(6000)
      await Promise.all(words.map(async (w) => {
        let asked = 0
        try {
          for await (const prov of this.node.contentRouting.findProviders(keywordCid(w), { signal })) {
            if (prov.id.equals(this.node.peerId)) continue
            if (++asked > PROVIDERS_PER_LOOKUP) break
            const list = await this.ask(prov, { k: 'kw', word: w }, signal)
            if (!Array.isArray(list)) continue
            for (const x of list.slice(0, KW_RESULTS)) {
              const rec = await validateRecord(x)
              this.report(prov.id.toString(), rec?.keywords.includes(w) ? 'valid-record' : 'bad-record', 'keyword search')
              if (rec?.keywords.includes(w) && this.allowed(rec)) this.store.putName(rec, false)
            }
          }
        } catch { /* partial results are fine */ }
      }))
    }
    const hay = (r: NameRecord): string => `${r.name} ${r.title.toLowerCase()} ${r.keywords.join(' ')}`
    return this.store.listNames()
      .filter((r) => this.allowed(r.record) && words.every((w) => hay(r.record).includes(w)))
      .sort((a, b) => Number(b.own) - Number(a.own) || b.record.ts - a.record.ts)
      .slice(0, 50)
      .map((r) => ({ ...r.record, link: nameLink(r.record.name, r.record.pub), own: r.own }))
  }

  list (): NameHit[] {
    return this.store.listNames().filter((r) => this.allowed(r.record)).map((r) => ({ ...r.record, link: nameLink(r.record.name, r.record.pub), own: r.own }))
  }
}
