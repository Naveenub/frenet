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

export function cidFor (data: Uint8Array): CID {
  return CID.createV1(raw.code, createDigest(SHA256, createHash('sha256').update(data).digest()))
}

function verify (cid: CID, data: Uint8Array): boolean {
  return cid.multihash.code === SHA256 && Buffer.from(cid.multihash.digest).equals(createHash('sha256').update(data).digest())
}

/**
 * Content-addressed blocks: stored locally, announced as DHT provider records,
 * fetched from providers and verified against the CID (hash) before use.
 * Blocks are NOT encrypted at rest or per-CID: anyone with the CID can fetch them.
 * Encrypt client-side before put() for private data.
 */
export class Blocks {
  private limiter = new RateLimiter(60, 10)
  constructor (private node: Libp2p, private store: Store) {}

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

  /** Store a block locally and announce it. Provider announcement failure is non-fatal (e.g. no peers yet). */
  async put (data: Uint8Array): Promise<{ cid: string, announced: boolean }> {
    if (data.byteLength === 0 || data.byteLength > MAX_BLOCK_BYTES) throw new Error(`block must be 1..${MAX_BLOCK_BYTES} bytes`)
    const cid = cidFor(data)
    this.store.putBlock(cid.toString(), data)
    return { cid: cid.toString(), announced: await this.announce(cid) }
  }

  async announce (cid: CID): Promise<boolean> {
    try { await this.node.contentRouting.provide(cid, { signal: AbortSignal.timeout(5000) }); return true } catch { return false }
  }

  /** Local hit, else find providers via the DHT, fetch, verify hash, cache. */
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
            this.store.putBlock(cid.toString(), data)
            void this.announce(cid) // become a provider too (replication)
            return data
          }
        } catch { /* try next provider */ }
      }
    } catch { /* no providers / timeout */ }
    return null
  }
}
