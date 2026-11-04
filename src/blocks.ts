import { createHash } from 'node:crypto'
import type { Libp2p } from '@libp2p/interface'
import { CID } from 'multiformats/cid'
import * as raw from 'multiformats/codecs/raw'
import { create as createDigest } from 'multiformats/hashes/digest'
import { RateLimiter } from './messaging.js'
import type { Store } from './store.js'

export const BLOCK_PROTOCOL = '/frenet/block/1.0.0'
export const MAX_BLOCK_BYTES = 1024 * 1024
const SHA256 = 0x12

export const DAY_MS = 86_400_000
export interface RetentionOptions {
  /** Max bytes of block data held locally (own + replicas). */
  quotaBytes: number
  /** How long replicas fetched from other peers are kept before the sweeper removes them. */
  replicaTtlMs: number
}
export const DEFAULT_RETENTION: RetentionOptions = { quotaBytes: 1024 ** 3, replicaTtlMs: 7 * DAY_MS }

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

  constructor (private node: Libp2p, private store: Store, retention: Partial<RetentionOptions> = {}) {
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
        const data = this.store.getBlock(cid.toString())
        if (data) stream.send(data)
        await stream.close()
      } catch { stream.abort(new Error('bad request')) }
    }, { maxInboundStreams: 32, maxOutboundStreams: 32 })
  }

  async stop (): Promise<void> { await this.node.unhandle(BLOCK_PROTOCOL) }

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
    if (!this.store.getBlock(cid.toString()) && !this.room(data.byteLength)) throw new Error('storage quota exceeded')
    this.store.putBlock(cid.toString(), data, ttlMs === undefined ? null : Date.now() + ttlMs)
    return cid
  }

  async put (data: Uint8Array, ttlMs?: number): Promise<{ cid: string, announced: boolean }> {
    const cid = this.putLocal(data, ttlMs)
    return { cid: cid.toString(), announced: await this.announce(cid) }
  }

  async announce (cid: CID): Promise<boolean> {
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
    const local = this.store.getBlock(cid.toString())
    if (local) return local
    const signal = AbortSignal.timeout(10_000)
    try {
      for await (const prov of this.node.contentRouting.findProviders(cid, { signal })) {
        if (prov.id.equals(this.node.peerId)) continue
        try {
          if (prov.multiaddrs.length) await this.node.peerStore.merge(prov.id, { multiaddrs: prov.multiaddrs })
          const stream = await this.node.dialProtocol(prov.id, BLOCK_PROTOCOL, { signal })
          stream.send(Buffer.from(cid.toString()))
          await stream.close()
          const chunks: Uint8Array[] = []
          let n = 0
          for await (const c of stream) { n += c.byteLength; if (n > MAX_BLOCK_BYTES) throw new Error('oversize'); chunks.push(c.subarray()) }
          const data = Buffer.concat(chunks)
          if (data.length && verify(cid, data)) {
            if (this.room(data.length)) {
              this.store.putBlock(cid.toString(), data, Date.now() + this.retention.replicaTtlMs)
              void this.announce(cid) // replicate: become a provider while the replica lives
            }
            return data
          }
        } catch { /* try next provider */ }
      }
    } catch { /* no providers / timeout */ }
    return null
  }
}
