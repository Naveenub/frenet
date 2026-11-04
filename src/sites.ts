import { CID } from 'multiformats/cid'
import type { Blocks } from './blocks.js'
import { MAX_FILE_BYTES, type FileStore } from './files.js'

export const MAX_SITE_FILES = 64
export const MAX_SITE_BYTES = 32 * 1024 * 1024
const MAX_MANIFEST_BYTES = 64 * 1024
const MAX_PATH_LEN = 200
const SEGMENT_RE = /^[A-Za-z0-9._-]{1,100}$/

/** path -> manifest CID of a public file (see FileStore). The site ID is the CID of this JSON block. */
interface SiteManifest { v: 1, type: 'site', index: string, files: Record<string, string> }

export interface PublishedSite { cid: string, link: string, files: number, bytes: number, announced: boolean }

/** Relative, slash-separated, no empty / "." / ".." segments, conservative charset. */
export function validSitePath (p: unknown): p is string {
  if (typeof p !== 'string' || p.length === 0 || p.length > MAX_PATH_LEN) return false
  return p.split('/').every((s) => SEGMENT_RE.test(s) && s !== '.' && s !== '..')
}

export function validCid (c: unknown): c is string {
  if (typeof c !== 'string' || c.length > 100) return false
  try { return CID.parse(c).toString() === c } catch { return false }
}

/**
 * Sites = a set of deliberately public files under relative paths, tied together by a manifest block.
 * Everything is content-addressed, so a site ID pins the exact bytes: a provider cannot swap content.
 * Sites are public by design (no encryption); use encrypted files for private data.
 */
export class Sites {
  constructor (private blocks: Blocks, private files: FileStore) {}

  async publish (entries: Array<{ path: string, data: Uint8Array }>, opts: { index?: string, ttlMs?: number } = {}): Promise<PublishedSite> {
    if (entries.length === 0) throw new Error('no files')
    if (entries.length > MAX_SITE_FILES) throw new Error(`too many files (max ${MAX_SITE_FILES})`)
    const index = opts.index ?? 'index.html'
    const seen = new Set<string>()
    let bytes = 0
    for (const e of entries) {
      if (!validSitePath(e.path)) throw new Error(`invalid path: ${String(e.path).slice(0, 80)}`)
      if (seen.has(e.path)) throw new Error(`duplicate path: ${e.path}`)
      seen.add(e.path)
      if (e.data.byteLength === 0) throw new Error(`empty file: ${e.path}`)
      if (e.data.byteLength > MAX_FILE_BYTES) throw new Error(`file too large: ${e.path}`)
      bytes += e.data.byteLength
    }
    if (bytes > MAX_SITE_BYTES) throw new Error(`site exceeds ${MAX_SITE_BYTES} bytes`)
    if (!validSitePath(index) || !seen.has(index)) throw new Error(`index file "${index}" is not part of the site`)

    const added: string[] = []
    try {
      const files: Record<string, string> = {}
      for (const e of entries) {
        const f = await this.files.add(e.path, e.data, { encrypt: false, ...(opts.ttlMs !== undefined ? { ttlMs: opts.ttlMs } : {}) })
        added.push(f.cid)
        files[e.path] = f.cid
      }
      const m: SiteManifest = { v: 1, type: 'site', index, files }
      const r = await this.blocks.put(Buffer.from(JSON.stringify(m)), opts.ttlMs)
      return { cid: r.cid, link: `frenet-site://${r.cid}`, files: entries.length, bytes, announced: r.announced }
    } catch (e) {
      for (const c of added) this.files.remove(c)   // roll back partial publishes (e.g. quota)
      throw e
    }
  }

  /** Fetch + validate the manifest. The publisher is untrusted: every field is checked. */
  async manifest (siteCid: string): Promise<SiteManifest> {
    if (!validCid(siteCid)) throw new Error('invalid site id')
    const b = await this.blocks.get(siteCid)
    if (!b) throw new Error('site not found on any reachable provider')
    if (b.byteLength > MAX_MANIFEST_BYTES) throw new Error('bad site manifest')
    let m: any
    try { m = JSON.parse(Buffer.from(b).toString('utf8')) } catch { throw new Error('not a site') }
    if (m?.v !== 1 || m.type !== 'site' || !validSitePath(m.index) || typeof m.files !== 'object' || m.files === null || Array.isArray(m.files)) throw new Error('not a site')
    const entries = Object.entries(m.files)
    if (entries.length === 0 || entries.length > MAX_SITE_FILES) throw new Error('bad site manifest')
    for (const [p, c] of entries) if (!validSitePath(p) || !validCid(c)) throw new Error('bad site manifest')
    if (!(m.index in m.files)) throw new Error('bad site manifest')
    return m as SiteManifest
  }

  /** Resolve a request path ("" or trailing "/" means directory index) to file bytes. null = no such path. */
  async resolve (siteCid: string, reqPath: string): Promise<{ path: string, data: Buffer } | null> {
    const m = await this.manifest(siteCid)
    let p = reqPath.replace(/^\/+/, '')
    if (p === '') p = m.index
    else if (p.endsWith('/')) p += 'index.html'
    if (!validSitePath(p)) return null
    const fileCid = Object.hasOwn(m.files, p) ? m.files[p] : undefined
    if (!fileCid) return null
    const f = await this.files.get(fileCid, null)
    return { path: p, data: f.data }
  }
}
