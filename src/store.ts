import { DatabaseSync } from 'node:sqlite'
import { join } from 'node:path'

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

export interface FileRow { cid: string, name: string, size: number, chunks: string[], encrypted: boolean, created: number, expires: number | null }

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
      CREATE TABLE IF NOT EXISTS files (cid TEXT PRIMARY KEY, name TEXT NOT NULL, size INTEGER NOT NULL, chunks TEXT NOT NULL, encrypted INTEGER NOT NULL, created INTEGER NOT NULL, expires INTEGER);
    `)
    try { this.db.exec('ALTER TABLE blocks ADD COLUMN expires INTEGER') } catch { /* column already present */ }
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
  deleteFileRow (cid: string): void { this.db.prepare('DELETE FROM files WHERE cid = ?').run(cid) }
  referencedChunks (): Set<string> {
    const out = new Set<string>()
    for (const f of this.listFiles()) { out.add(f.cid); for (const c of f.chunks) out.add(c) }
    return out
  }

  /** Secure-ish local deletion: remove rows, checkpoint WAL, vacuum. */
  deletePeer (peer: string): void {
    this.db.prepare('DELETE FROM messages WHERE peer = ?').run(peer)
    this.db.exec('PRAGMA wal_checkpoint(TRUNCATE); VACUUM;')
  }

  close (): void { this.db.close() }
}
