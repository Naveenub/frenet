import { DatabaseSync } from 'node:sqlite'
import { join } from 'node:path'
import type { NameRecord } from './names.js'
import type { PeerReputation } from './reputation.js'
import type { IdentityEvent } from './identity-log.js'

const MAX_FOREIGN_REVOCATIONS = 10_000
const MAX_FOREIGN_IDENTITY_LOGS = 5_000
const MAX_ZK_TAGS = 100_000

interface Col { name: string, type: 'text' | 'int', nullable?: boolean }
const T = (name: string, nullable = false): Col => ({ name, type: 'text', nullable })
const I = (name: string, nullable = false): Col => ({ name, type: 'int', nullable })
/** Tables an archive carries, with the columns validated on import. Replicas and cached foreign records are left out on purpose. */
const ARCHIVE_TABLES: Record<string, { cols: Col[], where?: string }> = {
  messages: { cols: [T('id'), T('peer'), T('direction'), I('ts'), T('body'), T('sig', true), T('sender', true), T('recipient', true)] },
  files: { cols: [T('cid'), T('name'), I('size'), T('chunks'), I('encrypted'), I('created'), I('expires', true)] },
  file_links: { cols: [T('cid'), T('link')] },
  names: { cols: [T('name'), T('pub'), I('seq'), I('own'), I('seen'), T('record')], where: 'own = 1' },
  communities: { cols: [T('id'), T('owner'), T('name'), I('seq'), T('members'), T('state'), I('updated')] },
  group_events: { cols: [T('community'), T('id'), T('kind'), T('author'), I('ts'), T('body'), T('sig'), T('meta', true)] },
  credentials: { cols: [T('id'), T('role'), T('issuer'), T('subject'), T('type'), I('issued'), I('expires', true), T('jwt')] },
  revocations: { cols: [T('issuer'), T('id'), I('ts'), T('jwt'), I('own')], where: 'own = 1' },
  bans: { cols: [T('peer'), T('reason'), I('ts')] },
  site_permissions: { cols: [T('origin'), T('feature'), I('ts')] },
  tracker_rules: { cols: [T('host'), T('action'), I('ts')] }
}

export interface StoredMessage {
  id: string
  peer: string
  direction: 'in' | 'out'
  ts: number
  body: string
  /** Ed25519 signature (base64) over sender|recipient|id|ts|body; verifiable by anyone via verifyMessage(). */
  sig?: string | null
  sender?: string | null
  recipient?: string | null
}

export type CommunityState = 'invited' | 'joined' | 'removed' | 'left'
export interface CommunityRow { id: string, owner: string, name: string, seq: number, members: string[], state: CommunityState, updated: number }
export interface GroupEventRow { community: string, id: string, kind: string, author: string, ts: number, body: string, sig: string, meta: string | null }

export interface CredentialRow { id: string, role: 'issued' | 'held', issuer: string, subject: string, type: string, issued: number, expires: number | null, jwt: string }

export interface FileRow { cid: string, name: string, size: number, chunks: string[], encrypted: boolean, created: number, expires: number | null }

/** `parent` is '' for an entry the operator added, else `<kind>:<target>` of the entry whose blocking pulled this one in. */
export interface ContentBlockRow { kind: string, target: string, parent: string, reason: string, ts: number }
export type ReportStatus = 'open' | 'blocked' | 'dismissed'
/** A locally filed content report. The signature covers everything except `status`, which is local workflow state. */
export interface ReportRow { id: string, kind: string, target: string, category: string, note: string, ts: number, reporter: string, sig: string, status: ReportStatus }

/** Local-first message store (SQLite). Nothing here is ever uploaded. */
export class Store {
  private db: DatabaseSync

  constructor (dataDir: string | ':memory:') {
    this.db = new DatabaseSync(dataDir === ':memory:' ? ':memory:' : join(dataDir, 'frenet.db'))
    this.db.exec(`
      PRAGMA journal_mode = WAL;
      CREATE TABLE IF NOT EXISTS messages (
        id TEXT NOT NULL,
        peer TEXT NOT NULL,
        direction TEXT NOT NULL CHECK (direction IN ('in','out')),
        ts INTEGER NOT NULL,
        body TEXT NOT NULL,
        PRIMARY KEY (id, direction)
      );
      CREATE INDEX IF NOT EXISTS messages_peer_ts ON messages (peer, ts);
      CREATE TABLE IF NOT EXISTS blocks (cid TEXT PRIMARY KEY, data BLOB NOT NULL, ts INTEGER NOT NULL, expires INTEGER);
      CREATE TABLE IF NOT EXISTS names (name TEXT NOT NULL, pub TEXT NOT NULL, seq INTEGER NOT NULL, own INTEGER NOT NULL DEFAULT 0, seen INTEGER NOT NULL, record TEXT NOT NULL, PRIMARY KEY (name, pub));
      CREATE TABLE IF NOT EXISTS files (cid TEXT PRIMARY KEY, name TEXT NOT NULL, size INTEGER NOT NULL, chunks TEXT NOT NULL, encrypted INTEGER NOT NULL, created INTEGER NOT NULL, expires INTEGER);
      CREATE TABLE IF NOT EXISTS admin_log (id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, peer TEXT NOT NULL, cmd TEXT NOT NULL, ok INTEGER NOT NULL, detail TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS bans (peer TEXT PRIMARY KEY, reason TEXT NOT NULL, ts INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS communities (id TEXT PRIMARY KEY, owner TEXT NOT NULL, name TEXT NOT NULL, seq INTEGER NOT NULL, members TEXT NOT NULL, state TEXT NOT NULL CHECK (state IN ('invited','joined','removed','left')), updated INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS group_events (community TEXT NOT NULL, id TEXT NOT NULL, kind TEXT NOT NULL, author TEXT NOT NULL, ts INTEGER NOT NULL, body TEXT NOT NULL, sig TEXT NOT NULL, meta TEXT, PRIMARY KEY (community, id));
      CREATE INDEX IF NOT EXISTS group_events_ts ON group_events (community, kind, ts);
      CREATE TABLE IF NOT EXISTS credentials (id TEXT NOT NULL, role TEXT NOT NULL CHECK (role IN ('issued','held')), issuer TEXT NOT NULL, subject TEXT NOT NULL, type TEXT NOT NULL, issued INTEGER NOT NULL, expires INTEGER, jwt TEXT NOT NULL, PRIMARY KEY (id, role));
      CREATE TABLE IF NOT EXISTS reputation (peer TEXT PRIMARY KEY, score REAL NOT NULL, good INTEGER NOT NULL, bad INTEGER NOT NULL, strikes INTEGER NOT NULL, blocked_until INTEGER, last_reason TEXT NOT NULL, updated INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS update_state (channel TEXT PRIMARY KEY, seq INTEGER NOT NULL, version TEXT NOT NULL, ts INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS revocations (issuer TEXT NOT NULL, id TEXT NOT NULL, ts INTEGER NOT NULL, jwt TEXT NOT NULL, own INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (issuer, id));
      CREATE TABLE IF NOT EXISTS identity_logs (id TEXT PRIMARY KEY, seq INTEGER NOT NULL, events TEXT NOT NULL, own INTEGER NOT NULL DEFAULT 0, seen INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS zk_tags (scope TEXT NOT NULL, tag TEXT NOT NULL, ts INTEGER NOT NULL, PRIMARY KEY (scope, tag));
      CREATE TABLE IF NOT EXISTS file_links (cid TEXT PRIMARY KEY, link TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS content_blocks (kind TEXT NOT NULL CHECK (kind IN ('cid','name','publisher')), target TEXT NOT NULL, parent TEXT NOT NULL DEFAULT '', reason TEXT NOT NULL, ts INTEGER NOT NULL, PRIMARY KEY (kind, target, parent));
      CREATE INDEX IF NOT EXISTS content_blocks_parent ON content_blocks (parent);
      CREATE TABLE IF NOT EXISTS reports (id TEXT PRIMARY KEY, kind TEXT NOT NULL, target TEXT NOT NULL, category TEXT NOT NULL, note TEXT NOT NULL, ts INTEGER NOT NULL, reporter TEXT NOT NULL, sig TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','blocked','dismissed')));
      CREATE INDEX IF NOT EXISTS reports_ts ON reports (ts);
      CREATE TABLE IF NOT EXISTS outbox (kind TEXT NOT NULL CHECK (kind IN ('msg','group')), id TEXT NOT NULL, peer TEXT NOT NULL, ts INTEGER NOT NULL, payload TEXT NOT NULL, tries INTEGER NOT NULL DEFAULT 0, next INTEGER NOT NULL, PRIMARY KEY (kind, id, peer));
      CREATE TABLE IF NOT EXISTS site_permissions (origin TEXT NOT NULL, feature TEXT NOT NULL, ts INTEGER NOT NULL, PRIMARY KEY (origin, feature));
      CREATE TABLE IF NOT EXISTS tracker_rules (host TEXT PRIMARY KEY, action TEXT NOT NULL CHECK (action IN ('block','allow')), ts INTEGER NOT NULL);
    `)
    try { this.db.exec('ALTER TABLE blocks ADD COLUMN expires INTEGER') } catch { /* column already present */ }
    try { this.db.exec('ALTER TABLE revocations ADD COLUMN own INTEGER NOT NULL DEFAULT 0') } catch { /* column already present */ }
    for (const c of ['sig', 'sender', 'recipient']) {
      try { this.db.exec(`ALTER TABLE messages ADD COLUMN ${c} TEXT`) } catch { /* column already present */ }
    }
  }

  add (m: StoredMessage): boolean {
    const r = this.db.prepare('INSERT OR IGNORE INTO messages (id, peer, direction, ts, body, sig, sender, recipient) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
      .run(m.id, m.peer, m.direction, m.ts, m.body, m.sig ?? null, m.sender ?? null, m.recipient ?? null)
    return Number(r.changes) > 0
  }

  list (peer?: string, limit = 200): StoredMessage[] {
    const rows = peer
      ? this.db.prepare('SELECT * FROM messages WHERE peer = ? ORDER BY ts DESC LIMIT ?').all(peer, limit)
      : this.db.prepare('SELECT * FROM messages ORDER BY ts DESC LIMIT ?').all(limit)
    return (rows as unknown as StoredMessage[]).reverse()
  }

  count (): { in: number, out: number } {
    const rows = this.db.prepare('SELECT direction, COUNT(*) AS n FROM messages GROUP BY direction').all() as Array<{ direction: string, n: number }>
    const out = { in: 0, out: 0 }
    for (const r of rows) out[r.direction as 'in' | 'out'] = Number(r.n)
    return out
  }

  /** expires = null pins the block (kept until deleted). A pin is never downgraded to an expiring copy. */
  putBlock (cid: string, data: Uint8Array, expires: number | null = null): void {
    this.db.prepare(`INSERT INTO blocks (cid, data, ts, expires) VALUES (?, ?, ?, ?)
      ON CONFLICT(cid) DO UPDATE SET expires = CASE
        WHEN excluded.expires IS NULL OR blocks.expires IS NULL THEN NULL
        ELSE MAX(blocks.expires, excluded.expires) END`).run(cid, data, Date.now(), expires)
  }

  getBlock (cid: string): Uint8Array | null {
    const r = this.db.prepare('SELECT data FROM blocks WHERE cid = ? AND (expires IS NULL OR expires > ?)').get(cid, Date.now()) as { data: Uint8Array } | undefined
    return r ? new Uint8Array(r.data) : null
  }

  hasBlock (cid: string): boolean { return !!this.db.prepare('SELECT 1 FROM blocks WHERE cid = ?').get(cid) }

  /**
   * CIDs of every block still held (not expired), pinned blocks first, for re-announcing on the DHT.
   * Ids only: the data is not read.
   */
  listBlockCids (now = Date.now()): string[] {
    return (this.db.prepare('SELECT cid FROM blocks WHERE expires IS NULL OR expires > ? ORDER BY (expires IS NULL) DESC, ts ASC').all(now) as Array<{ cid: string }>).map((r) => r.cid)
  }

  blockStats (): { count: number, bytes: number } {
    const r = this.db.prepare('SELECT COUNT(*) AS n, COALESCE(SUM(LENGTH(data)),0) AS b FROM blocks').get() as { n: number, b: number }
    return { count: Number(r.n), bytes: Number(r.b) }
  }

  deleteBlock (cid: string, compact = true): void {
    this.db.prepare('DELETE FROM blocks WHERE cid = ?').run(cid)
    if (compact) this.compact()
  }

  /** Retention sweeper: remove expired blocks and expired file records. Returns blocks removed. */
  sweep (now = Date.now()): number {
    const r = this.db.prepare('DELETE FROM blocks WHERE expires IS NOT NULL AND expires <= ?').run(now)
    this.db.prepare('DELETE FROM files WHERE expires IS NOT NULL AND expires <= ?').run(now)
    if (Number(r.changes) > 0) this.compact()
    return Number(r.changes)
  }

  compact (): void { this.db.exec('PRAGMA wal_checkpoint(TRUNCATE); VACUUM;') }

  addFile (f: FileRow): void {
    this.db.prepare('INSERT OR REPLACE INTO files (cid, name, size, chunks, encrypted, created, expires) VALUES (?, ?, ?, ?, ?, ?, ?)')
      .run(f.cid, f.name, f.size, JSON.stringify(f.chunks), f.encrypted ? 1 : 0, f.created, f.expires)
  }

  private row (r: any): FileRow { return { cid: r.cid, name: r.name, size: Number(r.size), chunks: JSON.parse(r.chunks), encrypted: !!r.encrypted, created: Number(r.created), expires: r.expires == null ? null : Number(r.expires) } }
  listFiles (): FileRow[] { return (this.db.prepare('SELECT * FROM files ORDER BY created DESC').all() as any[]).map((r) => this.row(r)) }
  getFile (cid: string): FileRow | null { const r = this.db.prepare('SELECT * FROM files WHERE cid = ?').get(cid); return r ? this.row(r) : null }
  deleteFileRow (cid: string): void {
    this.db.prepare('DELETE FROM files WHERE cid = ?').run(cid)
    this.db.prepare('DELETE FROM file_links WHERE cid = ?').run(cid)
  }
  /** Opt-in: remember the full `frenet://cid#key` link of a file so an archive can carry its key. Never done by default. */
  putFileLink (cid: string, link: string): void { this.db.prepare('INSERT OR REPLACE INTO file_links (cid, link) VALUES (?, ?)').run(cid, link) }
  getFileLink (cid: string): string | null { const r = this.db.prepare('SELECT link FROM file_links WHERE cid = ?').get(cid) as { link: string } | undefined; return r ? r.link : null }
  referencedChunks (): Set<string> {
    const out = new Set<string>()
    for (const f of this.listFiles()) { out.add(f.cid); for (const c of f.chunks) out.add(c) }
    return out
  }


  /**
   * Keep only the highest-seq record per (name, pub): a stale or replayed record never replaces a newer one.
   * `own` is sticky. Foreign records are capped so a flood of valid-but-junk records cannot grow the DB forever.
   */
  putName (r: NameRecord, own: boolean): boolean {
    const res = this.db.prepare(`INSERT INTO names (name, pub, seq, own, seen, record) VALUES (?, ?, ?, ?, ?, ?)
      ON CONFLICT(name, pub) DO UPDATE SET seq = excluded.seq, record = excluded.record, seen = excluded.seen, own = MAX(names.own, excluded.own)
      WHERE excluded.seq > names.seq`).run(r.name, r.pub, r.seq, own ? 1 : 0, Date.now(), JSON.stringify(r))
    if (!own) {
      this.db.prepare('DELETE FROM names WHERE own = 0 AND rowid NOT IN (SELECT rowid FROM names WHERE own = 0 ORDER BY seen DESC LIMIT 5000)').run()
    }
    return Number(res.changes) > 0
  }

  getName (name: string, pub: string): { record: NameRecord, seq: number, own: boolean } | null {
    const r = this.db.prepare('SELECT * FROM names WHERE name = ? AND pub = ?').get(name, pub) as any
    return r ? { record: JSON.parse(r.record), seq: Number(r.seq), own: !!r.own } : null
  }

  listNames (ownOnly = false): Array<{ record: NameRecord, seq: number, own: boolean }> {
    const rows = this.db.prepare(`SELECT * FROM names ${ownOnly ? 'WHERE own = 1' : ''} ORDER BY seen DESC`).all() as any[]
    return rows.map((r) => ({ record: JSON.parse(r.record), seq: Number(r.seq), own: !!r.own }))
  }

  deleteName (name: string, pub: string): void { this.db.prepare('DELETE FROM names WHERE name = ? AND pub = ?').run(name, pub) }

  /** Operator content blocklist (see Moderation). Idempotent per (kind, target, parent). */
  addContentBlock (kind: string, target: string, parent: string, reason: string): void {
    this.db.prepare('INSERT OR IGNORE INTO content_blocks (kind, target, parent, reason, ts) VALUES (?, ?, ?, ?, ?)').run(kind, target, parent, reason, Date.now())
  }
  listContentBlocks (): ContentBlockRow[] {
    return (this.db.prepare('SELECT * FROM content_blocks ORDER BY ts DESC').all() as any[]).map((r) => ({ kind: r.kind, target: r.target, parent: r.parent, reason: r.reason, ts: Number(r.ts) }))
  }
  /** Remove an entry the operator added together with everything it pulled in. True if the entry itself existed. */
  removeContentBlock (kind: string, target: string): boolean {
    const own = Number(this.db.prepare("DELETE FROM content_blocks WHERE kind = ? AND target = ? AND parent = ''").run(kind, target).changes) > 0
    this.db.prepare('DELETE FROM content_blocks WHERE parent = ?').run(`${kind}:${target}`)
    return own
  }

  addReport (r: ReportRow): void {
    this.db.prepare('INSERT INTO reports (id, kind, target, category, note, ts, reporter, sig, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)')
      .run(r.id, r.kind, r.target, r.category, r.note, r.ts, r.reporter, r.sig, r.status)
  }
  private report (r: any): ReportRow { return { id: r.id, kind: r.kind, target: r.target, category: r.category, note: r.note, ts: Number(r.ts), reporter: r.reporter, sig: r.sig, status: r.status } }
  getReport (id: string): ReportRow | null { const r = this.db.prepare('SELECT * FROM reports WHERE id = ?').get(id); return r ? this.report(r) : null }
  listReports (limit = 500): ReportRow[] { return (this.db.prepare('SELECT * FROM reports ORDER BY ts DESC LIMIT ?').all(limit) as any[]).map((r) => this.report(r)) }
  countReports (): number { return Number((this.db.prepare('SELECT COUNT(*) AS n FROM reports').get() as any).n) }
  setReportStatus (id: string, status: ReportStatus): boolean { return Number(this.db.prepare('UPDATE reports SET status = ? WHERE id = ?').run(status, id).changes) > 0 }
  /** Close every open report about this target (used when the target gets blocked). */
  closeOpenReports (kind: string, target: string, status: ReportStatus): void { this.db.prepare("UPDATE reports SET status = ? WHERE kind = ? AND target = ? AND status = 'open'").run(status, kind, target) }
  deleteOldestResolvedReports (n: number): void {
    this.db.prepare("DELETE FROM reports WHERE id IN (SELECT id FROM reports WHERE status != 'open' ORDER BY ts ASC LIMIT ?)").run(n)
  }

  /** Browser permission grants per site origin (see SitePermissions). Absence of a row means denied. */
  grantPermission (origin: string, feature: string): void { this.db.prepare('INSERT OR IGNORE INTO site_permissions (origin, feature, ts) VALUES (?, ?, ?)').run(origin, feature, Date.now()) }
  revokePermission (origin: string, feature: string): boolean { return Number(this.db.prepare('DELETE FROM site_permissions WHERE origin = ? AND feature = ?').run(origin, feature).changes) > 0 }
  revokeAllPermissions (origin: string): number { return Number(this.db.prepare('DELETE FROM site_permissions WHERE origin = ?').run(origin).changes) }
  listPermissions (origin?: string): Array<{ origin: string, feature: string, ts: number }> {
    const rows = (origin ? this.db.prepare('SELECT * FROM site_permissions WHERE origin = ? ORDER BY feature').all(origin) : this.db.prepare('SELECT * FROM site_permissions ORDER BY origin, feature').all()) as any[]
    return rows.map((r) => ({ origin: r.origin, feature: r.feature, ts: Number(r.ts) }))
  }

  /** The user's own tracker-blocking rules (see TrackerBlocker). */
  setTrackerRule (host: string, action: 'block' | 'allow'): void { this.db.prepare('INSERT OR REPLACE INTO tracker_rules (host, action, ts) VALUES (?, ?, ?)').run(host, action, Date.now()) }
  /** Many rules in one transaction (list import). Existing rules for a host are replaced. */
  setTrackerRules (hosts: string[], action: 'block' | 'allow'): void {
    const stmt = this.db.prepare('INSERT OR REPLACE INTO tracker_rules (host, action, ts) VALUES (?, ?, ?)'); const ts = Date.now()
    this.db.exec('BEGIN')
    try { for (const h of hosts) stmt.run(h, action, ts); this.db.exec('COMMIT') } catch (e) { try { this.db.exec('ROLLBACK') } catch { /* already rolled back */ } throw e }
  }
  clearTrackerRules (action: 'block' | 'allow'): number { return Number(this.db.prepare('DELETE FROM tracker_rules WHERE action = ?').run(action).changes) }
  removeTrackerRule (host: string): boolean { return Number(this.db.prepare('DELETE FROM tracker_rules WHERE host = ?').run(host).changes) > 0 }
  listTrackerRules (): Array<{ host: string, action: 'block' | 'allow', ts: number }> { return (this.db.prepare('SELECT * FROM tracker_rules ORDER BY host').all() as any[]).map((r) => ({ host: r.host, action: r.action, ts: Number(r.ts) })) }
  countTrackerRules (): number { return Number((this.db.prepare('SELECT COUNT(*) AS n FROM tracker_rules').get() as any).n) }
  countPermissionOrigins (): number { return Number((this.db.prepare('SELECT COUNT(DISTINCT origin) AS n FROM site_permissions').get() as any).n) }

  addBan (peer: string, reason: string): void { this.db.prepare('INSERT OR REPLACE INTO bans (peer, reason, ts) VALUES (?, ?, ?)').run(peer, reason, Date.now()) }
  removeBan (peer: string): boolean { return Number(this.db.prepare('DELETE FROM bans WHERE peer = ?').run(peer).changes) > 0 }
  listBans (): Array<{ peer: string, reason: string, ts: number }> { return (this.db.prepare('SELECT * FROM bans ORDER BY ts DESC').all() as any[]).map((r) => ({ peer: r.peer, reason: r.reason, ts: Number(r.ts) })) }

  private community (r: any): CommunityRow { return { id: r.id, owner: r.owner, name: r.name, seq: Number(r.seq), members: JSON.parse(r.members), state: r.state, updated: Number(r.updated) } }
  putCommunity (c: CommunityRow): void {
    this.db.prepare('INSERT OR REPLACE INTO communities (id, owner, name, seq, members, state, updated) VALUES (?, ?, ?, ?, ?, ?, ?)')
      .run(c.id, c.owner, c.name, c.seq, JSON.stringify(c.members), c.state, c.updated)
  }
  getCommunity (id: string): CommunityRow | null { const r = this.db.prepare('SELECT * FROM communities WHERE id = ?').get(id); return r ? this.community(r) : null }
  listCommunities (): CommunityRow[] { return (this.db.prepare('SELECT * FROM communities ORDER BY updated DESC').all() as any[]).map((r) => this.community(r)) }
  countCommunities (state: CommunityState): number { return Number((this.db.prepare('SELECT COUNT(*) AS n FROM communities WHERE state = ?').get(state) as any).n) }

  addGroupEvent (e: GroupEventRow): boolean {
    const r = this.db.prepare('INSERT OR IGNORE INTO group_events (community, id, kind, author, ts, body, sig, meta) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
      .run(e.community, e.id, e.kind, e.author, e.ts, e.body, e.sig, e.meta)
    return Number(r.changes) > 0
  }
  getGroupEvent (community: string, id: string): GroupEventRow | null { return (this.db.prepare('SELECT * FROM group_events WHERE community = ? AND id = ?').get(community, id) as unknown as GroupEventRow) ?? null }
  listGroupEvents (community: string, kind: string, limit = 200): GroupEventRow[] {
    return (this.db.prepare('SELECT * FROM group_events WHERE community = ? AND kind = ? ORDER BY ts DESC LIMIT ?').all(community, kind, limit) as unknown as GroupEventRow[]).reverse()
  }

  addCredential (c: CredentialRow): void {
    this.db.prepare('INSERT OR REPLACE INTO credentials (id, role, issuer, subject, type, issued, expires, jwt) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
      .run(c.id, c.role, c.issuer, c.subject, c.type, c.issued, c.expires, c.jwt)
  }
  getCredential (id: string, role: 'issued' | 'held'): CredentialRow | null {
    const r = this.db.prepare('SELECT * FROM credentials WHERE id = ? AND role = ?').get(id, role) as any
    return r ? this.credential(r) : null
  }
  listCredentials (role?: 'issued' | 'held'): CredentialRow[] {
    const rows = role ? this.db.prepare('SELECT * FROM credentials WHERE role = ? ORDER BY issued DESC').all(role) : this.db.prepare('SELECT * FROM credentials ORDER BY issued DESC').all()
    return (rows as any[]).map((r) => this.credential(r))
  }
  deleteCredential (id: string, role: 'issued' | 'held'): boolean { return Number(this.db.prepare('DELETE FROM credentials WHERE id = ? AND role = ?').run(id, role).changes) > 0 }
  private credential (r: any): CredentialRow { return { id: r.id, role: r.role, issuer: r.issuer, subject: r.subject, type: r.type, issued: Number(r.issued), expires: r.expires == null ? null : Number(r.expires), jwt: r.jwt } }

  /**
   * Store a verified revocation statement. Returns false if it was already known. Foreign statements are capped
   * (oldest evicted first) so junk cannot grow the DB forever; our own are never evicted.
   */
  addRevocation (issuer: string, id: string, jwt: string, own = false): boolean {
    const fresh = Number(this.db.prepare('INSERT OR IGNORE INTO revocations (issuer, id, ts, jwt, own) VALUES (?, ?, ?, ?, ?)').run(issuer, id, Date.now(), jwt, own ? 1 : 0).changes) > 0
    if (own && !fresh) this.db.prepare('UPDATE revocations SET own = 1 WHERE issuer = ? AND id = ?').run(issuer, id)
    if (fresh && !own) {
      this.db.prepare(`DELETE FROM revocations WHERE own = 0 AND rowid IN (
        SELECT rowid FROM revocations WHERE own = 0 ORDER BY ts DESC, rowid DESC LIMIT -1 OFFSET ?)`).run(MAX_FOREIGN_REVOCATIONS)
    }
    return fresh
  }
  isRevoked (issuer: string, id: string): boolean { return !!this.db.prepare('SELECT 1 FROM revocations WHERE issuer = ? AND id = ?').get(issuer, id) }
  /** The stored statement (a JWT) for a revocation, or null. */
  getRevocation (issuer: string, id: string): string | null {
    const r = this.db.prepare('SELECT jwt FROM revocations WHERE issuer = ? AND id = ?').get(issuer, id) as { jwt: string } | undefined
    return r ? r.jwt : null
  }
  listRevocations (): Array<{ issuer: string, id: string, ts: number, jwt: string }> {
    return (this.db.prepare('SELECT * FROM revocations ORDER BY ts DESC').all() as any[]).map((r) => ({ issuer: r.issuer, id: r.id, ts: Number(r.ts), jwt: r.jwt }))
  }

  /** Key logs (did:frenet) we hold, ours and others'. Foreign logs are capped; ours are never evicted. */
  putIdentityLog (id: string, seq: number, eventsJson: string, own = false): void {
    this.db.prepare(`INSERT INTO identity_logs (id, seq, events, own, seen) VALUES (?, ?, ?, ?, ?)
      ON CONFLICT(id) DO UPDATE SET seq = excluded.seq, events = excluded.events, own = MAX(identity_logs.own, excluded.own), seen = excluded.seen
      WHERE excluded.seq >= identity_logs.seq`).run(id, seq, eventsJson, own ? 1 : 0, Date.now())
    this.db.prepare(`DELETE FROM identity_logs WHERE own = 0 AND rowid IN (
      SELECT rowid FROM identity_logs WHERE own = 0 ORDER BY seen DESC, rowid DESC LIMIT -1 OFFSET ?)`).run(MAX_FOREIGN_IDENTITY_LOGS)
  }
  getIdentityLog (id: string): { id: string, seq: number, events: IdentityEvent[], own: boolean } | null {
    const r = this.db.prepare('SELECT * FROM identity_logs WHERE id = ?').get(id) as any
    if (!r) return null
    try { return { id: r.id, seq: Number(r.seq), events: JSON.parse(r.events) as IdentityEvent[], own: !!r.own } } catch { return null }
  }
  listIdentityLogs (ownOnly = false): Array<{ id: string, seq: number, own: boolean }> {
    const sql = `SELECT id, seq, own FROM identity_logs ${ownOnly ? 'WHERE own = 1 ' : ''}ORDER BY seen DESC`
    return (this.db.prepare(sql).all() as any[]).map((r) => ({ id: r.id, seq: Number(r.seq), own: !!r.own }))
  }

  putReputation (r: PeerReputation): void {
    this.db.prepare('INSERT OR REPLACE INTO reputation (peer, score, good, bad, strikes, blocked_until, last_reason, updated) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
      .run(r.peer, r.score, r.good, r.bad, r.strikes, r.blockedUntil, r.lastReason, r.updated)
  }
  deleteReputation (peer: string): void { this.db.prepare('DELETE FROM reputation WHERE peer = ?').run(peer) }
  listReputation (): PeerReputation[] {
    return (this.db.prepare('SELECT * FROM reputation').all() as any[]).map((r) => ({ peer: r.peer, score: Number(r.score), good: Number(r.good), bad: Number(r.bad), strikes: Number(r.strikes), blockedUntil: r.blocked_until == null ? null : Number(r.blocked_until), lastReason: r.last_reason, updated: Number(r.updated) }))
  }

  /** Audit trail of remote administration commands that passed authentication (newest 1000 kept). */
  addAdminLog (peer: string, cmd: string, ok: boolean, detail: string): void {
    this.db.prepare('INSERT INTO admin_log (ts, peer, cmd, ok, detail) VALUES (?, ?, ?, ?, ?)').run(Date.now(), peer, cmd, ok ? 1 : 0, detail)
    this.db.prepare('DELETE FROM admin_log WHERE id <= (SELECT MAX(id) FROM admin_log) - 1000').run()
  }
  listAdminLog (limit = 100): Array<{ ts: number, peer: string, cmd: string, ok: boolean, detail: string }> {
    return (this.db.prepare('SELECT * FROM admin_log ORDER BY id DESC LIMIT ?').all(Math.min(Math.max(1, limit), 1000)) as any[]).map((r) => ({ ts: Number(r.ts), peer: r.peer, cmd: r.cmd, ok: Number(r.ok) === 1, detail: r.detail }))
  }

  /** Highest update manifest sequence accepted per channel (rollback protection). */
  getUpdateState (channel: string): { seq: number, version: string, ts: number } | null {
    const r = this.db.prepare('SELECT * FROM update_state WHERE channel = ?').get(channel) as any
    return r ? { seq: Number(r.seq), version: r.version, ts: Number(r.ts) } : null
  }
  putUpdateState (channel: string, seq: number, version: string): void {
    this.db.prepare('INSERT INTO update_state (channel, seq, version, ts) VALUES (?, ?, ?, ?) ON CONFLICT(channel) DO UPDATE SET seq = excluded.seq, version = excluded.version, ts = excluded.ts WHERE excluded.seq > update_state.seq')
      .run(channel, seq, version, Date.now())
  }

  hasMessage (id: string, direction: 'in' | 'out'): boolean {
    return !!this.db.prepare('SELECT 1 FROM messages WHERE id = ? AND direction = ?').get(id, direction)
  }

  outboxAdd (r: { kind: string, id: string, peer: string, ts: number, payload: string, tries: number, next: number }): void {
    this.db.prepare('INSERT OR IGNORE INTO outbox (kind, id, peer, ts, payload, tries, next) VALUES (?, ?, ?, ?, ?, ?, ?)').run(r.kind, r.id, r.peer, r.ts, r.payload, r.tries, r.next)
  }
  outboxCount (peer?: string): number {
    const r = (peer ? this.db.prepare('SELECT COUNT(*) AS n FROM outbox WHERE peer = ?').get(peer) : this.db.prepare('SELECT COUNT(*) AS n FROM outbox').get()) as { n: number }
    return Number(r.n)
  }
  outboxDue (now: number, peer: string | undefined, force: boolean, limit: number): Array<{ kind: 'msg' | 'group', id: string, peer: string, ts: number, payload: string, tries: number, next: number }> {
    const rows = peer
      ? this.db.prepare(`SELECT * FROM outbox WHERE peer = ? ${force ? '' : 'AND next <= ?'} ORDER BY ts LIMIT ?`).all(...(force ? [peer, limit] : [peer, now, limit]))
      : this.db.prepare('SELECT * FROM outbox WHERE next <= ? ORDER BY ts LIMIT ?').all(now, limit)
    return rows as never
  }
  outboxDone (kind: string, id: string, peer: string): void { this.db.prepare('DELETE FROM outbox WHERE kind = ? AND id = ? AND peer = ?').run(kind, id, peer) }
  outboxRetry (kind: string, id: string, peer: string, next: number): void { this.db.prepare('UPDATE outbox SET tries = tries + 1, next = ? WHERE kind = ? AND id = ? AND peer = ?').run(next, kind, id, peer) }
  outboxExpire (before: number): number { return Number(this.db.prepare('DELETE FROM outbox WHERE ts < ?').run(before).changes) }
  outboxDropPeer (peer: string): void { this.db.prepare('DELETE FROM outbox WHERE peer = ?').run(peer) }

  /** Secure-ish local deletion: remove rows, checkpoint WAL, vacuum. */
  deletePeer (peer: string): void {
    this.db.prepare('DELETE FROM messages WHERE peer = ?').run(peer)
    this.db.prepare("DELETE FROM outbox WHERE peer = ? AND kind = 'msg'").run(peer)
    this.db.exec('PRAGMA wal_checkpoint(TRUNCATE); VACUUM;')
  }

  /** Blocks this node holds as its own (pinned: no expiry). Replicas of other people's data carry an expiry and are not included. */
  ownBlocks (): Array<{ cid: string, data: Uint8Array, expires: number | null }> {
    return (this.db.prepare('SELECT cid, data, expires FROM blocks WHERE expires IS NULL ORDER BY ts ASC').all() as any[])
      .map((r) => ({ cid: r.cid, data: new Uint8Array(r.data), expires: null }))
  }

  /** Everything this node holds that the network cannot give back, as plain rows (see archive.ts for what is left out). */
  exportTables (): Record<string, unknown[]> {
    const out: Record<string, unknown[]> = {}
    for (const [t, spec] of Object.entries(ARCHIVE_TABLES)) {
      out[t] = this.db.prepare(`SELECT ${spec.cols.map((c) => c.name).join(', ')} FROM ${t}${spec.where ? ' WHERE ' + spec.where : ''}`).all()
        .map((r: any) => Object.fromEntries(spec.cols.map((c) => [c.name, r[c.name] ?? null])))
    }
    return out
  }

  /**
   * Merge exported rows in one transaction: existing rows win, so re-running is safe, and one bad row rolls everything
   * back. Rows are type-checked column by column (the archive is authenticated but may still be malformed).
   * Returns how many rows were newly added per table. Unknown tables are ignored.
   */
  importTables (tables: unknown): Record<string, number> {
    if (typeof tables !== 'object' || tables === null || Array.isArray(tables)) throw new Error('corrupt archive')
    const added: Record<string, number> = {}
    this.db.exec('BEGIN')
    try {
      for (const [t, spec] of Object.entries(ARCHIVE_TABLES)) {
        const rows = (tables as Record<string, unknown>)[t]
        if (rows === undefined) continue
        if (!Array.isArray(rows)) throw new Error('corrupt archive')
        // ON CONFLICT DO NOTHING (not OR IGNORE): duplicates are skipped, but CHECK violations still throw
        const stmt = this.db.prepare(`INSERT INTO ${t} (${spec.cols.map((c) => c.name).join(', ')}) VALUES (${spec.cols.map(() => '?').join(', ')}) ON CONFLICT DO NOTHING`)
        let n = 0
        for (const row of rows) {
          if (typeof row !== 'object' || row === null || Array.isArray(row)) throw new Error('corrupt archive')
          const vals = spec.cols.map((c) => {
            const v = (row as Record<string, unknown>)[c.name]
            if (v === undefined || v === null) {
              if (c.nullable) return null
              throw new Error(`corrupt archive: ${t}.${c.name} missing`)
            }
            if (c.type === 'int' ? !Number.isSafeInteger(v) : typeof v !== 'string') throw new Error(`corrupt archive: ${t}.${c.name} has the wrong type`)
            return v as string | number
          })
          n += Number(stmt.run(...vals).changes)
        }
        added[t] = n
      }
      this.db.exec('COMMIT')
    } catch (e) {
      try { this.db.exec('ROLLBACK') } catch { /* already rolled back */ }
      throw e
    }
    return added
  }

  /**
   * Zero-knowledge auth (zkauth.ts): remember that an anonymous member of a scope has already acted. Returns false if this
   * (scope, tag) was seen before. A tag is unlinkable across scopes and says nothing about who holds it; only the newest
   * MAX_ZK_TAGS are kept, so a scope that must never accept a repeat should not be flooded with others.
   */
  claimZkTag (scope: string, tag: string): boolean {
    const fresh = Number(this.db.prepare('INSERT OR IGNORE INTO zk_tags (scope, tag, ts) VALUES (?, ?, ?)').run(scope, tag, Date.now()).changes) > 0
    if (fresh) this.db.prepare('DELETE FROM zk_tags WHERE rowid IN (SELECT rowid FROM zk_tags ORDER BY ts DESC, rowid DESC LIMIT -1 OFFSET ?)').run(MAX_ZK_TAGS)
    return fresh
  }
  zkTagCount (scope: string): number { return Number((this.db.prepare('SELECT COUNT(*) AS n FROM zk_tags WHERE scope = ?').get(scope) as { n: number }).n) }
  forgetZkScope (scope: string): number { return Number(this.db.prepare('DELETE FROM zk_tags WHERE scope = ?').run(scope).changes) }

  close (): void { this.db.close() }
}
