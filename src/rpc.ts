import type { Libp2p, PeerId } from '@libp2p/interface'

/** Small shared helpers for the one-request-per-stream JSON protocols (names, identity logs, revocations). */

/** Read a whole stream as JSON, refusing more than `max` bytes. Throws on oversize or bad JSON. */
export async function readJson (stream: AsyncIterable<{ byteLength: number, subarray: () => Uint8Array }>, max: number): Promise<any> {
  const chunks: Uint8Array[] = []
  let n = 0
  for await (const c of stream) {
    n += c.byteLength
    if (n > max) throw new Error('too large')
    chunks.push(c.subarray())
  }
  return JSON.parse(Buffer.concat(chunks).toString('utf8'))
}

/** Send one JSON request to a provider and read one JSON response (<= maxResponse bytes). Null on any failure. */
export async function ask (node: Libp2p, prov: { id: PeerId, multiaddrs: any[] }, protocol: string, req: object, signal: AbortSignal, maxResponse: number): Promise<unknown> {
  try {
    if (prov.multiaddrs.length) await node.peerStore.merge(prov.id, { multiaddrs: prov.multiaddrs })
    const stream = await node.dialProtocol(prov.id, protocol, { signal, runOnLimitedConnection: true })
    stream.send(Buffer.from(JSON.stringify(req)))
    await stream.close()
    return await readJson(stream as any, maxResponse)
  } catch { return null }
}
