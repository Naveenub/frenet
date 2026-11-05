import { randomUUID } from 'node:crypto'
import type { Libp2p, PrivateKey } from '@libp2p/interface'
import { CID } from 'multiformats/cid'
import { canon, ID_RE, signBytes, verifyBytes } from './channel.js'
import { NAME_RE, pubToB32, validPub } from './names.js'
import { validCid } from './sites.js'
import type { ReportRow, Store } from './store.js'

/**
 * Content safety for a node that stores and serves other people's data.
 *
 * FRENET has no central operator who can take content down, so each node operator needs their own tools:
 *  - **Reports**: record what was found and why. Reports hold identifiers and a short note, never content bytes
 *    and never a file's decryption key, and are signed by the node identity so they can be handed to a hotline,
 *    a publisher or another operator and still be verified (`verifyReport`).
 *  - **Blocklist**: refuse a content ID, a name or a publisher key. Blocking purges the local copies, withdraws the
 *    DHT advertisement, and then refuses to store, fetch, serve, announce or render the content again.
 *
 * Everything is local to this node. Nothing is transmitted, shared or scanned automatically, and matching is by
 * exact hash: a copy with one changed byte is a different CID and needs its own entry.
 */

export const TARGET_KINDS = ['cid', 'name', 'publisher'] as const
export type TargetKind = (typeof TARGET_KINDS)[number]
export const REPORT_CATEGORIES = ['illegal', 'child-safety', 'malware', 'phishing', 'harassment', 'spam', 'other'] as const
export type ReportCategory = (typeof REPORT_CATEGORIES)[number]

export const REPORT_DOMAIN = 'frenet-report/v1'
export const MAX_NOTE = 500
export const MAX_REASON = 200
export const MAX_REPORTS = 1000
/** Upper bounds on what one block operation pulls in, because manifests held locally are untrusted. */
const MAX_MANIFEST_BYTES = 64 * 1024
const MAX_LIST = 1100
const MAX_DERIVED = 5000
// eslint-disable-next-line no-control-regex
const HAS_CONTROL = /[\u0000-\u001f\u007f]/
// eslint-disable-next-line no-control-regex
const STRIP_CONTROL = /[\u0000-\u001f\u007f]/g

export interface BlockEntry { kind: TargetKind, target: string, reason: string, ts: number, /** how many other entries this one pulled in (a site's files and chunks, a name's site, ...) */ derived: number }

export function parseKind (k: unknown): TargetKind {
  if (typeof k === 'string' && (TARGET_KINDS as readonly string[]).includes(k)) return k as TargetKind
  throw new Error(`kind must be one of: ${TARGET_KINDS.join(', ')}`)
}

export function parseCategory (c: unknown): ReportCategory {
  if (typeof c === 'string' && (REPORT_CATEGORIES as readonly string[]).includes(c)) return c as ReportCategory
  throw new Error(`category must be one of: ${REPORT_CATEGORIES.join(', ')}`)
}

const cleanText = (v: unknown, max: number): string => String(v ?? '').replace(STRIP_CONTROL, ' ').trim().slice(0, max)

/**
 * Canonical form of a target. Accepts the links FRENET hands out; a file link's `#key` is dropped on purpose so a
 * decryption key is never written into a report, the blocklist or an exported report.
 */
export function normalizeTarget (kind: TargetKind, input: unknown): string {
  if (typeof input !== 'string') throw new Error('target must be a string')
  const t = input.trim().replace(/#[\s\S]*$/, '')
  if (t.length === 0 || t.length > 300) throw new Error('invalid target')
  if (kind === 'cid') {
    const cid = t.replace(/^frenet(?:-site)?:\/\//, '').replace(/\/[\s\S]*$/, '')
    if (!validCid(cid)) throw new Error('invalid content ID (use a frenet:// or frenet-site:// link, or a CID)')
    return cid
  }
  const bare = t.replace(/^frenet-name:\/\//, '').replace(/\/[\s\S]*$/, '')
  const m = /^([a-z0-9-]{1,63})\.([a-z2-7]{52})$/.exec(bare)
  if (kind === 'name') {
    if (!m || !NAME_RE.test(m[1]!) || !validPub(m[2])) throw new Error('invalid name (use frenet-name://<name>.<publisher-key>)')
    return bare
  }
  // publisher: a bare key, or any name link by that publisher
  const pub = m ? m[2]! : bare
  if (!validPub(pub)) throw new Error('invalid publisher key (52 characters, a-z and 2-7), or use a frenet-name:// link')
  return pub
}

const reportBytes = (r: Pick<ReportRow, 'id' | 'kind' | 'target' | 'category' | 'ts' | 'reporter'>, note: string): Uint8Array =>
  canon(REPORT_DOMAIN, [r.reporter, r.id, r.kind, r.target, r.category, String(r.ts)], note)

/**
 * Check an exported report: well-formed fields, and a signature that verifies under the key inside `reporter`
 * (a peer ID), so any third party can confirm which node filed it and that it was not altered. `status` is not signed.
 */
export async function verifyReport (x: unknown): Promise<boolean> {
  try {
    const r = x as any
    if (typeof r !== 'object' || r === null) return false
    if (typeof r.id !== 'string' || !ID_RE.test(r.id)) return false
    const kind = parseKind(r.kind); parseCategory(r.category)
    if (normalizeTarget(kind, r.target) !== r.target) return false
    if (typeof r.note !== 'string' || r.note.length > MAX_NOTE || HAS_CONTROL.test(r.note)) return false
    if (!Number.isSafeInteger(r.ts) || r.ts <= 0) return false
    if (typeof r.reporter !== 'string' || typeof r.sig !== 'string') return false
    return await verifyBytes(r.reporter, reportBytes(r, r.note), r.sig)
  } catch { return false }
}

export class Moderation {
  /** In-memory copy of the blocklist so the hot paths (block serving, gateway) never touch SQLite. */
  private sets: Record<TargetKind, Set<string>> = { cid: new Set(), name: new Set(), publisher: new Set() }
  private ownPub: string

  constructor (private store: Store, private node: Libp2p, private key: PrivateKey) {
    this.ownPub = pubToB32(key.publicKey.raw)
    this.reload()
  }

  private reload (): void {
    for (const s of Object.values(this.sets)) s.clear()
    for (const r of this.store.listContentBlocks()) this.sets[r.kind as TargetKind]?.add(r.target)
  }

  isBlocked (kind: TargetKind, target: string): boolean { return this.sets[kind].has(target) }

  /** A name is blocked directly, through its publisher, or because the site it points at is blocked. */
  nameBlocked (name: string, pub: string, target?: string): boolean {
    return this.sets.name.has(`${name}.${pub}`) || this.sets.publisher.has(pub) || (target !== undefined && this.sets.cid.has(target))
  }

  /** Operator-added entries, newest first. */
  list (): BlockEntry[] {
    const rows = this.store.listContentBlocks()
    const derived = new Map<string, number>()
    for (const r of rows) if (r.parent) derived.set(r.parent, (derived.get(r.parent) ?? 0) + 1)
    return rows.filter((r) => r.parent === '').map((r) => ({ kind: r.kind as TargetKind, target: r.target, reason: r.reason, ts: r.ts, derived: derived.get(`${r.kind}:${r.target}`) ?? 0 }))
  }

  /**
   * Block a content ID (a file, a site, or any block), a name, or a publisher key.
   * Whatever the target pulled in that this node holds is blocked with it: a site's file manifests and chunks, the
   * site a name points at, every name of a publisher and their sites. Local copies are deleted and no longer advertised.
   */
  block (kindIn: unknown, targetIn: unknown, reasonIn: unknown = ''): { entry: BlockEntry, purged: number } {
    const kind = parseKind(kindIn)
    const target = normalizeTarget(kind, targetIn)
    const reason = cleanText(reasonIn, MAX_REASON)
    if (kind === 'publisher' && target === this.ownPub) throw new Error("cannot block this node's own publisher key")
    const parent = `${kind}:${target}`

    // Work out what the target covers before anything is deleted.
    const roots: string[] = []
    if (kind === 'cid') roots.push(target)
    else if (kind === 'name') {
      const [name, pub] = target.split('.') as [string, string]
      const rec = this.store.getName(name, pub)?.record
      if (rec) roots.push(rec.target)
      this.store.deleteName(name, pub)
    } else {
      for (const r of this.store.listNames()) {
        if (r.record.pub !== target) continue
        roots.push(r.record.target)
        this.store.deleteName(r.record.name, target)
      }
    }
    const covered = new Set<string>()
    for (const root of roots) for (const c of this.closure(root)) { if (covered.size < MAX_DERIVED) covered.add(c) }

    this.store.addContentBlock(kind, target, '', reason)
    for (const c of covered) if (!(kind === 'cid' && c === target)) this.store.addContentBlock('cid', c, parent, reason)
    this.reload()
    this.store.closeOpenReports(kind, target, 'blocked')
    return { entry: this.list().find((e) => e.kind === kind && e.target === target)!, purged: this.purge(covered) }
  }

  /** Lift an entry and everything it pulled in. Deleted data is not restored; it can be fetched again from peers. */
  unblock (kindIn: unknown, targetIn: unknown): boolean {
    const kind = parseKind(kindIn)
    const removed = this.store.removeContentBlock(kind, normalizeTarget(kind, targetIn))
    this.reload()
    return removed
  }

  /**
   * Local-only walk of what a block refers to, never touching the network: a site manifest lists file manifests,
   * a file manifest lists chunks. Encrypted manifests cannot be read without the key, so for a file this node
   * holds only as someone else's replica the chunks are not enumerable (they expire with the replica TTL).
   */
  private closure (root: string): Set<string> {
    const out = new Set<string>([root])
    const kids = (cid: string): { type: 'site' | 'file' | null, cids: string[] } => {
      const f = this.store.getFile(cid)
      if (f) return { type: 'file', cids: f.chunks.filter(validCid).slice(0, MAX_LIST) }
      const data = this.store.getBlock(cid)
      if (!data || data.byteLength > MAX_MANIFEST_BYTES) return { type: null, cids: [] }
      let m: any
      try { m = JSON.parse(Buffer.from(data).toString('utf8')) } catch { return { type: null, cids: [] } }
      if (typeof m !== 'object' || m === null || m.v !== 1) return { type: null, cids: [] }
      if (m.type === 'site' && typeof m.files === 'object' && m.files !== null && !Array.isArray(m.files)) return { type: 'site', cids: (Object.values(m.files) as unknown[]).filter(validCid).slice(0, MAX_LIST) }
      if (Array.isArray(m.chunks)) return { type: 'file', cids: (m.chunks as unknown[]).filter(validCid).slice(0, MAX_LIST) }
      return { type: null, cids: [] }
    }
    const top = kids(root)
    for (const c of top.cids) out.add(c)
    if (top.type === 'site') for (const f of top.cids) for (const c of kids(f).cids) out.add(c)
    return out
  }

  /** Delete local data for these CIDs, drop names that point at them, and stop advertising them. Returns blocks removed. */
  private purge (cids: Set<string>): number {
    if (cids.size === 0) return 0
    let removed = 0
    for (const c of cids) {
      if (this.store.hasBlock(c)) removed++
      if (this.store.getFile(c)) this.store.deleteFileRow(c)
      this.store.deleteBlock(c, false)
    }
    for (const r of this.store.listNames()) if (cids.has(r.record.target)) this.store.deleteName(r.record.name, r.record.pub)
    this.store.compact()
    // The DHT keeps re-providing everything it was told to provide until told otherwise.
    for (const c of cids) void this.node.contentRouting.cancelReprovide(CID.parse(c)).catch(() => {})
    return removed
  }

  /** File a report. It is stored locally and signed by this node's identity; it does not block anything by itself. */
  async report (input: Record<string, unknown>): Promise<ReportRow> {
    const kind = parseKind(input.kind)
    const target = normalizeTarget(kind, input.target)
    const category = parseCategory(input.category)
    const note = cleanText(input.note, MAX_NOTE)
    if (this.store.countReports() >= MAX_REPORTS) {
      this.store.deleteOldestResolvedReports(100)
      if (this.store.countReports() >= MAX_REPORTS) throw new Error(`report log is full (${MAX_REPORTS} open reports): resolve some first`)
    }
    const head = { id: randomUUID(), kind, target, category, ts: Date.now(), reporter: this.node.peerId.toString() }
    const row: ReportRow = { ...head, note, sig: await signBytes(this.key, reportBytes(head, note)), status: 'open' }
    this.store.addReport(row)
    return row
  }

  listReports (): ReportRow[] { return this.store.listReports() }

  /** Close a report: `block` blocks its target (and closes every open report about it), `dismiss` just closes it. */
  resolve (idIn: unknown, action: unknown, reasonIn: unknown = ''): { report: ReportRow, purged: number } {
    const r = this.store.getReport(String(idIn))
    if (!r) throw new Error('no such report')
    if (action === 'dismiss') {
      this.store.setReportStatus(r.id, 'dismissed')
      return { report: { ...r, status: 'dismissed' }, purged: 0 }
    }
    if (action !== 'block') throw new Error('action must be "block" or "dismiss"')
    const { purged } = this.block(r.kind, r.target, cleanText(reasonIn, MAX_REASON) || `report: ${r.category}`)
    this.store.setReportStatus(r.id, 'blocked')   // block() closed the open ones; this also covers a report that was dismissed earlier
    return { report: { ...r, status: 'blocked' }, purged }
  }

  counts (): { blocklist: number, openReports: number } {
    return { blocklist: this.list().length, openReports: this.store.listReports(MAX_REPORTS).filter((r) => r.status === 'open').length }
  }
}
