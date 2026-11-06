import { createHash } from 'node:crypto'
import type { Libp2p } from '@libp2p/interface'
import { CID } from 'multiformats/cid'
import * as raw from 'multiformats/codecs/raw'
import { create as createDigest } from 'multiformats/hashes/digest'
import { RateLimiter } from './messaging.js'
import type { Moderation } from './moderation.js'
import type { ReputationEvent } from './reputation.js'
import type { Store } from './store.js'

export const BLOCK_PROTOCOL = '/frenet/block/1.0.0'
export const MAX_BLOCK_BYTES = 1024 * 1024
const SHA256 = 0x12

export const DAY_MS = 86_400_000
const HOUR_MS = 3_600_000
/** Concurrent DHT announcements during a re-announce run. */
const REANNOUNCE_CONCURRENCY = 8
/** When a run could not announce anything (no peers yet), try again after this long instead of waiting a full interval. */
const REANNOUNCE_RETRY_MS = 5 * 60_000

export interface RetentionOptions {
  /** Max bytes of block data held locally (own + replicas). */
  quotaBytes: number
  /** How long replicas fetched from other peers are kept before the sweeper removes them. */
  replicaTtlMs: number
  /**
   * How often every block held locally is announced again on the DHT; 0 turns it off. DHT peers drop a provider record
   * after 48 h, and the DHT's own re-provider only knows what this process announced (it keeps that in memory, so it
   * forgets everything on restart). Re-announcing from the local store is what keeps content findable across
   * restarts and while the publisher is offline, as long as some node still holds it.
   */
  reannounceMs: number
  /** Wait this long after start before the first re-announce, so the node has found some peers. */
  reannounceDelayMs: number
}
export const DEFAULT_RETENTION: RetentionOptions = { quotaBytes: 1024 ** 3, replicaTtlMs: 7 * DAY_MS, reannounceMs: 12 * HOUR_MS, reannounceDelayMs: 30_000 }

/** Thrown instead of storing, fetching or serving something the operator has blocked. */
export class ContentBlocked extends Error {
  constructor (what = 'content') { super(`${what} is blocked by the operator of this node`); this.name = 'ContentBlocked' }
}

export function cidFor (data: Uint8Array): CID {
  return CID.createV1(raw.code, createDigest(SHA256, createHash('sha256').update(data).digest()))
}

function verify (cid: CID, data: Uint8Array): boolean {
  return cid.multihash.code === SHA256 && Buffer.from(cid.multihash.digest).equals(createHash('sha256').update(data).digest())
}

/**
 * Content-addressed blocks: stored locally, announced as DHT provider records,
 * fetched from providers and verified against the CID (hash) before use.
 * Raw blocks are readable by anyone with the CID. Use FileStore for encrypted files.
 *
 * Retention: own blocks are kept until deleted (or until their ttl, if given);
 * replicas fetched from peers expire after `replicaTtlMs`; a byte quota bounds local storage.
 */
export class Blocks {
  private limiter = new RateLimiter(60, 10)
  readonly retention: RetentionOptions
  /** Set by the node: told which provider served a verified or a corrupt block. */
  report: (peer: string, event: ReputationEvent, detail?: string) => void = () => {}
  /** Outcome of the most recent complete re-announce run (null until one has finished). */
  lastReannounce: { at: number, total: number, ok: number } | null = null
  private timer: NodeJS.Timeout | null = null
  private stopped = true
  private running: Promise<{ total: number, ok: number }> | null = null

  constructor (private node: Libp2p, private store: Store, private moderation: Moderation, retention: Partial<RetentionOptions> = {}) {
    this.retention = { ...DEFAULT_RETENTION, ...retention }
  }

  async start (): Promise<void> {
    await this.node.handle(BLOCK_PROTOCOL, async (stream, connection) => {
      try {
        if (!this.limiter.allow(connection.remotePeer.toString())) { stream.abort(new Error('rate limited')); return }
        const chunks: Uint8Array[] = []
        let n = 0
        for await (const c of stream) { n += c.byteLength; if (n > 256) { stream.abort(new Error('too large')); return }; chunks.push(c.subarray()) }
        const cid = CID.parse(Buffer.concat(chunks).toString('utf8'))
        // Blocked content is never served, even if a copy somehow survived: answer with nothing.
        const data = this.moderation.isBlocked('cid', cid.toString()) ? null : this.store.getBlock(cid.toString())
        if (data) stream.send(data)
        await stream.close()
      } catch { stream.abort(new Error('bad request')) }
    }, { maxInboundStreams: 32, maxOutboundStreams: 32, runOnLimitedConnection: true })
    this.stopped = false
    if (this.retention.reannounceMs > 0) this.schedule(this.retention.reannounceDelayMs)
  }

  async stop (): Promise<void> {
    this.stopped = true
    if (this.timer) clearTimeout(this.timer)
    await this.node.unhandle(BLOCK_PROTOCOL)
  }

  private schedule (ms: number): void {
    if (this.stopped) return
    this.timer = setTimeout(() => {
      void this.reannounce().then((r) => this.schedule(r.total > 0 && r.ok === 0 ? REANNOUNCE_RETRY_MS : this.retention.reannounceMs))
    }, ms)
    this.timer.unref()
  }

  /**
   * Announce every block this node still holds (own files and sites first, then replicas) as a DHT provider record.
   * Runs at start-up and every `reannounceMs`; can also be triggered by hand. Blocked content is skipped, expired
   * blocks are not listed. Never rejects: failures just lower `ok`.
   */
  reannounce (): Promise<{ total: number, ok: number }> {
    if (this.running) return this.running
    const run = (async () => {
      const cids = this.store.listBlockCids().filter((c) => !this.moderation.isBlocked('cid', c))
      let ok = 0
      let next = 0
      await Promise.all(Array.from({ length: Math.min(REANNOUNCE_CONCURRENCY, cids.length) }, async () => {
        while (next < cids.length && !this.stopped) { if (await this.announce(CID.parse(cids[next++]!))) ok++ }
      }))
      const result = { total: cids.length, ok }
      if (!this.stopped) this.lastReannounce = { at: Date.now(), ...result }
      return result
    })().catch(() => ({ total: 0, ok: 0 })).finally(() => { this.running = null })
    this.running = run
    return run
  }

  /** True if `bytes` more fit under the quota (expired blocks are swept first if needed). */
  private room (bytes: number): boolean {
    if (this.store.blockStats().bytes + bytes <= this.retention.quotaBytes) return true
    this.store.sweep()
    return this.store.blockStats().bytes + bytes <= this.retention.quotaBytes
  }

  /** Store locally without announcing. ttlMs undefined = keep until deleted. Throws if over quota. */
  putLocal (data: Uint8Array, ttlMs?: number): CID {
    if (data.byteLength === 0 || data.byteLength > MAX_BLOCK_BYTES) throw new Error(`block must be 1..${MAX_BLOCK_BYTES} bytes`)
    const cid = cidFor(data)
    if (this.moderation.isBlocked('cid', cid.toString())) throw new ContentBlocked()
    if (!this.store.getBlock(cid.toString()) && !this.room(data.byteLength)) throw new Error('storage quota exceeded')
    this.store.putBlock(cid.toString(), data, ttlMs === undefined ? null : Date.now() + ttlMs)
    return cid
  }

  async put (data: Uint8Array, ttlMs?: number): Promise<{ cid: string, announced: boolean }> {
    const cid = this.putLocal(data, ttlMs)
    return { cid: cid.toString(), announced: await this.announce(cid) }
  }

  async announce (cid: CID): Promise<boolean> {
    if (this.moderation.isBlocked('cid', cid.toString())) return false
    if (this.node.getPeers().length === 0) return false   // nobody to tell: fail now instead of waiting out the timeout per block (the re-announce run retries later)
    try { await this.node.contentRouting.provide(cid, { signal: AbortSignal.timeout(5000) }); return true } catch { return false }
  }

  /** Announce many blocks with bounded concurrency. Returns true only if every announcement succeeded. */
  async announceAll (cids: CID[], concurrency = 8): Promise<boolean> {
    let ok = true
    let i = 0
    await Promise.all(Array.from({ length: Math.min(concurrency, cids.length) }, async () => {
      while (i < cids.length) { if (!await this.announce(cids[i++])) ok = false }
    }))
    return ok
  }

  /** Local hit, else find providers via the DHT, fetch, verify hash, cache as an expiring replica. */
  async get (cidStr: string): Promise<Uint8Array | null> {
    const cid = CID.parse(cidStr)
    if (this.moderation.isBlocked('cid', cid.toString())) throw new ContentBlocked()
    const local = this.store.getBlock(cid.toString())
    if (local) return local
    const data = await this.fromProviders(cid, MAX_BLOCK_BYTES)
    if (data && this.room(data.length)) {
      try {
        this.store.putBlock(cid.toString(), data, Date.now() + this.retention.replicaTtlMs)
        void this.announce(cid) // replicate: become a provider while the replica lives
      } catch { /* served but not cached */ }
    }
    return data
  }

  /**
   * Read a block for the operator's moderation tools: the local copy, else one fetched from a provider and verified
   * against its CID. Unlike `get` it ignores the blocklist (the operator may need to read what they are blocking, or
   * have already blocked) and it never stores or announces anything. `maxBytes` stops a download early, so asking for
   * a manifest cannot pull a whole chunk; a provider that sends more than that is skipped without a penalty.
   */
  async peek (cidStr: string, maxBytes = MAX_BLOCK_BYTES): Promise<Uint8Array | null> {
    const cid = CID.parse(cidStr)
    return this.store.getBlock(cid.toString()) ?? await this.fromProviders(cid, Math.min(maxBytes, MAX_BLOCK_BYTES))
  }

  /** Find providers via the DHT and return the first copy that hashes to `cid`, or null. Stores nothing. */
  private async fromProviders (cid: CID, maxBytes: number): Promise<Buffer | null> {
    const signal = AbortSignal.timeout(10_000)
    try {
      for await (const prov of this.node.contentRouting.findProviders(cid, { signal })) {
        if (prov.id.equals(this.node.peerId)) continue
        try {
          if (prov.multiaddrs.length) await this.node.peerStore.merge(prov.id, { multiaddrs: prov.multiaddrs })
          const stream = await this.node.dialProtocol(prov.id, BLOCK_PROTOCOL, { signal, runOnLimitedConnection: true })
          stream.send(Buffer.from(cid.toString()))
          await stream.close()
          const chunks: Uint8Array[] = []
          let n = 0
          for await (const c of stream) {
            n += c.byteLength
            if (n > maxBytes) { if (maxBytes >= MAX_BLOCK_BYTES) this.report(prov.id.toString(), 'oversize', 'block response'); throw new Error('oversize') }
            chunks.push(c.subarray())
          }
          const data = Buffer.concat(chunks)
          if (data.length && !verify(cid, data)) this.report(prov.id.toString(), 'bad-block', 'data does not match CID')
          if (data.length && verify(cid, data)) { this.report(prov.id.toString(), 'valid-block'); return data }
        } catch { /* try next provider */ }
      }
    } catch { /* no providers / timeout */ }
    return null
  }
}
