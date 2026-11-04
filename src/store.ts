import { DatabaseSync } from 'node:sqlite'
import { join } from 'node:path'

export interface StoredMessage {
  id: string
  peer: string
  direction: 'in' | 'out'
  ts: number
  body: string
}

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
      CREATE TABLE IF NOT EXISTS blocks (cid TEXT PRIMARY KEY, data BLOB NOT NULL, ts INTEGER NOT NULL);
    `)
  }

  add (m: StoredMessage): boolean {
    const r = this.db.prepare('INSERT OR IGNORE INTO messages (id, peer, direction, ts, body) VALUES (?, ?, ?, ?, ?)')
      .run(m.id, m.peer, m.direction, m.ts, m.body)
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

  putBlock (cid: string, data: Uint8Array): void {
    this.db.prepare('INSERT OR IGNORE INTO blocks (cid, data, ts) VALUES (?, ?, ?)').run(cid, data, Date.now())
  }

  getBlock (cid: string): Uint8Array | null {
    const r = this.db.prepare('SELECT data FROM blocks WHERE cid = ?').get(cid) as { data: Uint8Array } | undefined
    return r ? new Uint8Array(r.data) : null
  }

  blockStats (): { count: number, bytes: number } {
    const r = this.db.prepare('SELECT COUNT(*) AS n, COALESCE(SUM(LENGTH(data)),0) AS b FROM blocks').get() as { n: number, b: number }
    return { count: Number(r.n), bytes: Number(r.b) }
  }

  deleteBlock (cid: string): void {
    this.db.prepare('DELETE FROM blocks WHERE cid = ?').run(cid)
    this.db.exec('PRAGMA wal_checkpoint(TRUNCATE); VACUUM;')
  }

  /** Secure-ish local deletion: remove rows, checkpoint WAL, vacuum. */
  deletePeer (peer: string): void {
    this.db.prepare('DELETE FROM messages WHERE peer = ?').run(peer)
    this.db.exec('PRAGMA wal_checkpoint(TRUNCATE); VACUUM;')
  }

  close (): void { this.db.close() }
}
