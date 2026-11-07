import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto'
import type { CID } from 'multiformats/cid'
import { cidFor, type Blocks } from './blocks.js'
import type { Store } from './store.js'

export const CHUNK_BYTES = 256 * 1024
/** Per-file cap. Files stream through in 256 KB chunks, so memory use does not grow with file size; the manifest (a list of chunk CIDs) must stay under one block, which this cap keeps at ~250 KB. */
export const MAX_FILE_BYTES = 1024 * 1024 * 1024

interface Manifest { v: 1, name: string, size: number, chunks: string[] }

export interface AddOptions { encrypt?: boolean, ttlMs?: number, remember?: boolean }

/** `announced`: every block is findable on the DHT. `announcing`: the file was too big to wait for, so announcing continues in the background (the periodic re-announce also covers it). */
export interface AddedFile { cid: string, key: string | null, link: string, chunks: number, size: number, announced: boolean, announcing?: boolean }

/** Files with more blocks than this are announced in the background so `add` returns promptly. */
export const SYNC_ANNOUNCE_MAX_BLOCKS = 64

const b64u = (b: Uint8Array): string => Buffer.from(b).toString('base64url')

/** AES-256-GCM (Node crypto). Output: nonce(12) | ciphertext | tag(16). `aad` binds the block's role/position. */
export function seal (key: Buffer, plain: Uint8Array, aad: string): Buffer {
  const nonce = randomBytes(12)
  const c = createCipheriv('aes-256-gcm', key, nonce)
  c.setAAD(Buffer.from(aad))
  return Buffer.concat([nonce, c.update(plain), c.final(), c.getAuthTag()])
}

export function open (key: Buffer, blob: Uint8Array, aad: string): Buffer {
  if (blob.length < 28) throw new Error('corrupt block')
  const b = Buffer.from(blob)
  const d = createDecipheriv('aes-256-gcm', key, b.subarray(0, 12))
  d.setAAD(Buffer.from(aad))
  d.setAuthTag(b.subarray(b.length - 16))
  try { return Buffer.concat([d.update(b.subarray(12, b.length - 16)), d.final()]) } catch { throw new Error('wrong key or corrupted data') }
}

/** Encrypt one standalone block (AES-256-GCM, AAD `b`) with a fresh random key. The key is returned, never stored. */
export function sealBlock (plain: Uint8Array): { blob: Buffer, key: string } {
  const key = randomBytes(32)
  return { blob: seal(key, plain, 'b'), key: b64u(key) }
}

/** Decrypt a block made by `sealBlock`. Throws 'wrong key or corrupted data' if the key or block is wrong. */
export function openBlock (blob: Uint8Array, keyB64u: string): Buffer {
  if (!validFileKey(keyB64u)) throw new Error('invalid key')
  return open(Buffer.from(keyB64u, 'base64url'), blob, 'b')
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

  /** Add a whole in-memory file. For anything large use `addStream`, which never holds more than one chunk. */
  async add (name: string, data: Uint8Array, opts: AddOptions = {}): Promise<AddedFile> {
    if (data.byteLength === 0) throw new Error('empty file')
    if (data.byteLength > MAX_FILE_BYTES) throw new Error(`file exceeds ${MAX_FILE_BYTES} bytes`)
    return this.addStream(name, [data], opts)
  }

  /**
   * Add a file from a stream: bytes are re-cut into `chunkBytes` pieces, each sealed and stored as it arrives, so memory
   * stays at about one chunk whatever the file size. Aborts (and removes everything written so far) if the stream
   * errors, is empty, goes over MAX_FILE_BYTES or the quota is hit.
   */
  async addStream (name: string, source: AsyncIterable<Uint8Array> | Iterable<Uint8Array>, opts: AddOptions = {}): Promise<AddedFile> {
    const encrypt = opts.encrypt !== false
    const key = encrypt ? randomBytes(32) : null
    const cids: CID[] = []
    try {
      const chunks: string[] = []
      let size = 0
      const putChunk = (part: Uint8Array): void => {
        const i = chunks.length
        const cid = this.blocks.putLocal(key ? seal(key, part, `c${i}`) : part, opts.ttlMs)
        cids.push(cid); chunks.push(cid.toString())
      }
      let pending: Buffer[] = []
      let pendingLen = 0
      for await (const piece of source) {
        size += piece.byteLength
        if (size > MAX_FILE_BYTES) throw new Error(`file exceeds ${MAX_FILE_BYTES} bytes`)
        if (piece.byteLength === 0) continue
        pending.push(Buffer.from(piece.buffer, piece.byteOffset, piece.byteLength)); pendingLen += piece.byteLength
        if (pendingLen >= this.chunkBytes) {
          const all = pending.length === 1 ? pending[0]! : Buffer.concat(pending, pendingLen)
          let off = 0
          while (all.length - off >= this.chunkBytes) { putChunk(all.subarray(off, off + this.chunkBytes)); off += this.chunkBytes }
          const rest = all.subarray(off)
          pending = rest.length ? [Buffer.from(rest)] : []   // copy so the big source buffer can be released
          pendingLen = rest.length
        }
      }
      if (pendingLen) putChunk(Buffer.concat(pending, pendingLen))
      if (size === 0) throw new Error('empty file')
      const m = Buffer.from(JSON.stringify({ v: 1, name: name.slice(0, 255), size, chunks } satisfies Manifest))
      const mcid = this.blocks.putLocal(key ? seal(key, m, 'm') : m, opts.ttlMs)
      cids.push(mcid)
      this.store.addFile({ cid: mcid.toString(), name: name.slice(0, 255), size, chunks, encrypted: encrypt, created: Date.now(), expires: opts.ttlMs === undefined ? null : Date.now() + opts.ttlMs })
      const link = `frenet://${mcid}${key ? '#' + b64u(key) : ''}`
      // opt-in only: by default the key exists nowhere on this node but in the returned link
      if (opts.remember && key) this.store.putFileLink(mcid.toString(), link)
      const base = { cid: mcid.toString(), key: key ? b64u(key) : null, link, chunks: chunks.length, size }
      if (cids.length > SYNC_ANNOUNCE_MAX_BLOCKS) {
        void this.blocks.announceAll([mcid, ...cids.slice(0, -1)]).catch(() => {})   // manifest first, so the file is resolvable early
        return { ...base, announced: false, announcing: true }
      }
      return { ...base, announced: await this.blocks.announceAll(cids) }
    } catch (e) {
      for (const c of cids) this.store.deleteBlock(c.toString())  // roll back partial writes (e.g. quota, broken upload)
      throw e
    }
  }

  /**
   * Fetch and decrypt the manifest, then return a reader that yields the file one verified chunk at a time (each chunk
   * is hash-checked on fetch and GCM-authenticated, with its position bound as AAD, so chunks cannot be swapped or
   * reordered). Manifest errors (not found, wrong key, blocked) throw here, before any data flows; a failure while
   * reading throws from the iterator, and the total length is checked at the end.
   */
  async open (cid: string, keyB64u?: string | null): Promise<{ name: string, size: number, chunks: AsyncGenerator<Buffer, void, void> }> {
    const mb = await this.blocks.get(cid)
    if (!mb) throw new Error('manifest not found on any reachable provider')
    const key = keyB64u ? Buffer.from(keyB64u, 'base64url') : null
    if (key && key.length !== 32) throw new Error('invalid key')
    const mj = key ? open(key, mb, 'm') : Buffer.from(mb)
    let m: Manifest
    try { m = JSON.parse(mj.toString('utf8')) } catch { throw new Error('this file is encrypted: a key is required') }
    if (m?.v !== 1 || !Array.isArray(m.chunks) || m.chunks.length > Math.ceil(MAX_FILE_BYTES / 1024) + 1 || !m.chunks.every((c) => typeof c === 'string') ||
        typeof m.name !== 'string' || !Number.isSafeInteger(m.size) || m.size < 0 || m.size > MAX_FILE_BYTES) throw new Error('bad manifest')
    const blocks = this.blocks
    const gen = async function * (): AsyncGenerator<Buffer, void, void> {
      let total = 0
      for (let i = 0; i < m.chunks.length; i++) {
        const cb = await blocks.get(m.chunks[i]!)
        if (!cb) throw new Error(`chunk ${i + 1}/${m.chunks.length} not found on any reachable provider`)
        const part = key ? open(key, cb, `c${i}`) : Buffer.from(cb)
        total += part.length
        if (total > m.size) throw new Error('size mismatch')
        yield part
      }
      if (total !== m.size) throw new Error('size mismatch')
    }
    return { name: m.name, size: m.size, chunks: gen() }
  }

  /** Whole file in memory. Use `open` to stream large files. */
  async get (cid: string, keyB64u?: string | null): Promise<{ name: string, data: Buffer }> {
    const f = await this.open(cid, keyB64u)
    const parts: Buffer[] = []
    for await (const p of f.chunks) parts.push(p)
    return { name: f.name, data: Buffer.concat(parts) }
  }

  list () { return this.store.listFiles() }

  /** Local record of a file this node added (size, encrypted flag, chunks), or null. */
  info (cid: string) { return this.store.getFile(cid) }

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
