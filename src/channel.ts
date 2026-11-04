import { peerIdFromString } from '@libp2p/peer-id'
import type { PrivateKey, Stream } from '@libp2p/interface'

export const MAX_FRAME_BYTES = 32 * 1024
export const MAX_SKEW_MS = 5 * 60 * 1000
/** Header fields are signed newline-joined, so each must match a newline-free pattern before it is verified. */
export const ID_RE = /^[A-Za-z0-9-]{1,64}$/

/** Domain-separated canonical bytes. `body` is last, so only it may contain newlines. */
export function canon (domain: string, head: string[], body: string): Uint8Array {
  return Buffer.from(`${domain}\n${head.join('\n')}\n${body}`, 'utf8')
}

export async function signBytes (key: PrivateKey, bytes: Uint8Array): Promise<string> {
  return Buffer.from(await key.sign(bytes)).toString('base64')
}

/** Verify under the key embedded in an Ed25519 peer ID, so any third party can re-check. */
export async function verifyBytes (signer: string, bytes: Uint8Array, sig: string): Promise<boolean> {
  try {
    const pub = peerIdFromString(signer).publicKey
    return !!pub && await pub.verify(bytes, Buffer.from(sig, 'base64'))
  } catch { return false }
}

/** Read one frame; aborts the stream and returns null when it exceeds `max`. */
export async function readFrame (stream: Stream, max = MAX_FRAME_BYTES): Promise<Buffer | null> {
  const chunks: Uint8Array[] = []
  let size = 0
  for await (const c of stream) {
    const b = c.subarray()
    size += b.length
    if (size > max) { stream.abort(new Error('too large')); return null }
    chunks.push(b)
  }
  return Buffer.concat(chunks)
}

export function isPeerId (s: unknown): s is string {
  if (typeof s !== 'string' || s.length > 128) return false
  try { peerIdFromString(s); return true } catch { return false }
}
