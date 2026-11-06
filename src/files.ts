import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto'
import { cidFor, type Blocks } from './blocks.js'
import type { Store } from './store.js'

export const CHUNK_BYTES = 256 * 1024
export const MAX_FILE_BYTES = 16 * 1024 * 1024

interface Manifest { v: 1, name: string, size: number, chunks: string[] }

export interface AddedFile { cid: string, key: string | null, link: string, chunks: number, size: number, announced: boolean }

const b64u = (b: Uint8Array): string => Buffer.from(b).toString('base64url')

/** AES-256-GCM (Node crypto). Output: nonce(12) | ciphertext | tag(16). `aad` binds the block's role/position. */
function seal (key: Buffer, plain: Uint8Array, aad: string): Buffer {
  const nonce = randomBytes(12)
  const c = createCipheriv('aes-256-gcm', key, nonce)
  c.setAAD(Buffer.from(aad))
  return Buffer.concat([nonce, c.update(plain), c.final(), c.getAuthTag()])
}

function open (key: Buffer, blob: Uint8Array, aad: string): Buffer {
  if (blob.length < 28) throw new Error('corrupt block')
  const b = Buffer.from(blob)
  const d = createDecipheriv('aes-256-gcm', key, b.subarray(0, 12))
  d.setAAD(Buffer.from(aad))
  d.setAuthTag(b.subarray(b.length - 16))
  try { return Buffer.concat([d.update(b.subarray(12, b.length - 16)), d.final()]) } catch { throw new Error('wrong key or corrupted data') }
}

const KEY_RE = /^[A-Za-z0-9_-]{43}$/
/** A file key as it appears after `#` in a `frenet://` link: 32 bytes, base64url, no padding. */
export const validFileKey = (k: unknown): k is string => typeof k === 'string' && KEY_RE.test(k)

/**
 * Chunk CIDs listed by an encrypted file's manifest block, given the key from its link. The key is used for this
 * call only and is not kept. Throws if the key does not open the block or the block is not a file manifest.
 */
export function sealedManifestChunks (blob: Uint8Array, keyB64u: string): string[] {
  if (!validFileKey(keyB64u)) throw new Error('invalid file key')
  const m = JSON.parse(open(Buffer.from(keyB64u, 'base64url'), blob, 'm').toString('utf8'))
  if (m?.v !== 1 || !Array.isArray(m.chunks)) throw new Error('not a file manifest')
  return m.chunks.filter((c: unknown): c is string => typeof c === 'string')
}

/**
 * Files = chunked, client-side-encrypted blocks plus an (also encrypted) manifest.
 * The key never touches the network or disk on this node: it exists only in the returned link
 * `frenet://<manifestCid>#<key>`. Whoever holds the link can read the file; providers see ciphertext only.
 * Pass { encrypt: false } for deliberately public files.
 */
export class FileStore {
  chunkBytes = CHUNK_BYTES
  constructor (private blocks: Blocks, private store: Store) {}

  async add (name: string, data: Uint8Array, opts: { encrypt?: boolean, ttlMs?: number, remember?: boolean } = {}): Promise<AddedFile> {
    if (data.byteLength === 0) throw new Error('empty file')
    if (data.byteLength > MAX_FILE_BYTES) throw new Error(`file exceeds ${MAX_FILE_BYTES} bytes`)
    const encrypt = opts.encrypt !== false
    const key = encrypt ? randomBytes(32) : null
    const cids = []
    try {
      const chunks: string[] = []
      for (let i = 0, off = 0; off < data.byteLength; i++, off += this.chunkBytes) {
        const part = data.subarray(off, off + this.chunkBytes)
        const cid = this.blocks.putLocal(key ? seal(key, part, `c${i}`) : part, opts.ttlMs)
        cids.push(cid); chunks.push(cid.toString())
      }
      const m = Buffer.from(JSON.stringify({ v: 1, name: name.slice(0, 255), size: data.byteLength, chunks } satisfies Manifest))
      const mcid = this.blocks.putLocal(key ? seal(key, m, 'm') : m, opts.ttlMs)
      cids.push(mcid)
      this.store.addFile({ cid: mcid.toString(), name: name.slice(0, 255), size: data.byteLength, chunks, encrypted: encrypt, created: Date.now(), expires: opts.ttlMs === undefined ? null : Date.now() + opts.ttlMs })
      const link = `frenet://${mcid}${key ? '#' + b64u(key) : ''}`
      // opt-in only: by default the key exists nowhere on this node but in the returned link
      if (opts.remember && key) this.store.putFileLink(mcid.toString(), link)
      const announced = await this.blocks.announceAll(cids)
      return { cid: mcid.toString(), key: key ? b64u(key) : null, link, chunks: chunks.length, size: data.byteLength, announced }
    } catch (e) {
      for (const c of cids) this.store.deleteBlock(c.toString())  // roll back partial writes (e.g. quota)
      throw e
    }
  }

  async get (cid: string, keyB64u?: string | null): Promise<{ name: string, data: Buffer }> {
    const mb = await this.blocks.get(cid)
    if (!mb) throw new Error('manifest not found on any reachable provider')
    const key = keyB64u ? Buffer.from(keyB64u, 'base64url') : null
    if (key && key.length !== 32) throw new Error('invalid key')
    const mj = key ? open(key, mb, 'm') : Buffer.from(mb)
    let m: Manifest
    try { m = JSON.parse(mj.toString('utf8')) } catch { throw new Error('this file is encrypted: a key is required') }
    if (m?.v !== 1 || !Array.isArray(m.chunks) || m.chunks.length > Math.ceil(MAX_FILE_BYTES / 1024) + 1) throw new Error('bad manifest')
    const parts: Buffer[] = []
    for (let i = 0; i < m.chunks.length; i++) {
      const cb = await this.blocks.get(m.chunks[i])
      if (!cb) throw new Error(`chunk ${i + 1}/${m.chunks.length} not found on any reachable provider`)
      parts.push(key ? open(key, cb, `c${i}`) : Buffer.from(cb))
    }
    const data = Buffer.concat(parts)
    if (data.length !== m.size) throw new Error('size mismatch')
    return { name: m.name, data }
  }

  list () { return this.store.listFiles() }

  /** The full `frenet://cid#key` link, only for files added with `remember`; null otherwise (the key is not stored by default). */
  rememberedLink (cid: string): string | null { return this.store.getFileLink(cid) }

  /** Delete the local copies of a file (manifest + chunks not shared with another local file). */
  remove (cid: string): boolean {
    const f = this.store.getFile(cid)
    if (!f) return false
    this.store.deleteFileRow(cid)
    const shared = this.store.referencedChunks()
    for (const c of f.chunks) if (!shared.has(c)) this.store.deleteBlock(c, false)
    this.store.deleteBlock(cid, false)
    this.store.compact()
    return true
  }
}

export { cidFor }
