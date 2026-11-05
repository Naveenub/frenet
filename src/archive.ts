import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto'
import { gunzipSync, gzipSync } from 'node:zlib'
import { privateKeyFromProtobuf } from '@libp2p/crypto/keys'
import { base32 } from 'multiformats/bases/base32'
import { cidFor, MAX_BLOCK_BYTES } from './blocks.js'
import { extendsLog, verifyLog } from './identity-log.js'
import { validateRecord } from './names.js'
import { checkPassphrase, derive, describeKey, installKey, readIdentityLog, readKeyFile, SCRYPT_MAX_N, SCRYPT_N, SCRYPT_P, SCRYPT_R, writeIdentityLog } from './recovery.js'
import { Store } from './store.js'

/**
 * Full archive: the identity key (and its key log) plus everything this node holds that the network cannot give back:
 * message history, files and remembered file links, own names, communities, credentials (issued and held), revocations,
 * bans, and optionally the node's own blocks. One file, one passphrase (scrypt -> AES-256-GCM over gzipped JSON, the
 * whole header authenticated). It supersedes `frenet backup` (which carries the key only) and restores into a data
 * directory with the node stopped.
 *
 * Not included on purpose: replicas of other people's blocks and cached foreign names (refetchable), and file keys of
 * files whose link was not remembered (`remember` at upload time: the node never stores a key unless you opt in).
 * The archive holds your private key AND your private data: treat the file and the passphrase like the key itself.
 */
const MAGIC = Buffer.from('FRENET-ARCHIVE\n', 'utf8')
const MAX_PLAIN_BYTES = 256 * 1024 * 1024
const MAX_BLOCK_TOTAL = 128 * 1024 * 1024
const MAX_FILE_BYTES = 320 * 1024 * 1024
const MAX_HEADER = 1024

interface Snapshot {
  v: 1
  created: number
  peer: string
  key: string
  identityLog: unknown[] | null
  tables: Record<string, unknown[]>
  blocks: Array<{ cid: string, data: string, expires: number | null }>
}

export const isArchive = (bytes: Uint8Array): boolean => bytes.length > MAGIC.length && Buffer.from(bytes.subarray(0, MAGIC.length)).equals(MAGIC)

function seal (plain: Buffer, passphrase: string, peer: string, N: number): Promise<Buffer> {
  return (async () => {
    const pw = checkPassphrase(passphrase)
    const salt = randomBytes(16); const nonce = randomBytes(12)
    const header = Buffer.from(JSON.stringify({ v: 1, kdf: 'scrypt', N, r: SCRYPT_R, p: SCRYPT_P, salt: salt.toString('base64'), nonce: nonce.toString('base64'), peer }), 'utf8')
    const len = Buffer.alloc(4); len.writeUInt32BE(header.length)
    const aad = Buffer.concat([MAGIC, len, header])
    const c = createCipheriv('aes-256-gcm', await derive(pw, salt, N, SCRYPT_R, SCRYPT_P), nonce)
    c.setAAD(aad)
    return Buffer.concat([aad, c.update(plain), c.final(), c.getAuthTag()])
  })()
}

async function unseal (bytes: Uint8Array, passphrase: string): Promise<Buffer> {
  const b = Buffer.from(bytes)
  if (b.length > MAX_FILE_BYTES || !isArchive(b) || b.length < MAGIC.length + 4 + 17) throw new Error('not a FRENET archive')
  const hl = b.readUInt32BE(MAGIC.length)
  if (hl === 0 || hl > MAX_HEADER || b.length < MAGIC.length + 4 + hl + 17) throw new Error('unsupported or corrupted archive')
  const aad = b.subarray(0, MAGIC.length + 4 + hl)
  let h: any
  try { h = JSON.parse(aad.subarray(MAGIC.length + 4).toString('utf8')) } catch { throw new Error('unsupported or corrupted archive') }
  const ok = h && h.v === 1 && h.kdf === 'scrypt' && Number.isInteger(h.N) && h.N >= 2 ** 10 && h.N <= SCRYPT_MAX_N && Number.isInteger(Math.log2(h.N)) &&
    h.r === SCRYPT_R && h.p === SCRYPT_P && typeof h.salt === 'string' && typeof h.nonce === 'string' && typeof h.peer === 'string'
  if (!ok) throw new Error('unsupported or corrupted archive')
  const salt = Buffer.from(h.salt, 'base64'); const nonce = Buffer.from(h.nonce, 'base64')
  if (salt.length !== 16 || nonce.length !== 12) throw new Error('unsupported or corrupted archive')
  const d = createDecipheriv('aes-256-gcm', await derive(checkPassphrase(passphrase), salt, h.N, h.r, h.p), nonce)
  d.setAAD(aad)
  d.setAuthTag(b.subarray(b.length - 16))
  try { return Buffer.concat([d.update(b.subarray(aad.length, b.length - 16)), d.final()]) } catch { throw new Error('wrong passphrase or corrupted archive') }
}

/** Snapshot `dataDir` (node stopped) into one encrypted archive. `blocks` adds the node's own blocks (<= 128 MiB). */
export async function createArchive (dataDir: string, passphrase: string, opts: { blocks?: boolean, N?: number } = {}): Promise<{ bytes: Buffer, peerId: string, counts: Record<string, number>, blocks: number }> {
  const N = opts.N ?? SCRYPT_N
  if (!Number.isInteger(Math.log2(N)) || N < 2 ** 10 || N > SCRYPT_MAX_N) throw new Error('invalid scrypt cost')
  checkPassphrase(passphrase)
  const key = readKeyFile(dataDir)
  const info = describeKey(key)
  const log = readIdentityLog(dataDir)
  if (log) {
    const st = await verifyLog(log)
    if (st.key !== base32.baseEncode(privateKeyFromProtobuf(key).publicKey.raw)) throw new Error('identity-log.json does not end in this identity key; fix that before archiving')
  }
  const store = new Store(dataDir)
  try {
    const tables = store.exportTables()
    const blocks: Snapshot['blocks'] = []
    if (opts.blocks) {
      let total = 0
      for (const b of store.ownBlocks()) {
        total += b.data.byteLength
        if (total > MAX_BLOCK_TOTAL) throw new Error(`own blocks exceed the archive limit (${MAX_BLOCK_TOTAL >> 20} MiB); archive without blocks (peers that replicated them can serve them again) or delete files you no longer need`)
        blocks.push({ cid: b.cid, data: Buffer.from(b.data).toString('base64'), expires: b.expires })
      }
    }
    const snap: Snapshot = { v: 1, created: Date.now(), peer: info.peerId, key: Buffer.from(key).toString('base64'), identityLog: log, tables, blocks }
    const plain = gzipSync(Buffer.from(JSON.stringify(snap), 'utf8'))
    if (plain.length > MAX_PLAIN_BYTES) throw new Error('archive too large')
    return { bytes: await seal(plain, passphrase, info.peerId, N), peerId: info.peerId, counts: Object.fromEntries(Object.entries(tables).map(([t, r]) => [t, r.length])), blocks: blocks.length }
  } finally { store.close() }
}

/** Decrypt and fully validate an archive without touching anything on disk. */
export async function openArchive (bytes: Uint8Array, passphrase: string): Promise<Snapshot & { peerId: string, did: string, keyBytes: Uint8Array }> {
  const plain = await unseal(bytes, passphrase)
  let snap: Snapshot
  try { snap = JSON.parse(gunzipSync(plain, { maxOutputLength: MAX_PLAIN_BYTES }).toString('utf8')) } catch { throw new Error('corrupted archive') }
  if (!snap || snap.v !== 1 || typeof snap.key !== 'string' || typeof snap.tables !== 'object' || snap.tables === null || !Array.isArray(snap.blocks)) throw new Error('corrupted archive')
  const keyBytes = new Uint8Array(Buffer.from(snap.key, 'base64'))
  const info = describeKey(keyBytes)
  if (info.peerId !== snap.peer) throw new Error('archive does not match its recorded identity')
  if (snap.identityLog !== null) await verifyLog(snap.identityLog)
  for (const b of snap.blocks) {
    const data = Buffer.from(String(b?.data), 'base64')
    if (typeof b?.cid !== 'string' || data.length === 0 || data.length > MAX_BLOCK_BYTES || cidFor(data).toString() !== b.cid) throw new Error('archive contains a block that does not match its hash')
  }
  for (const r of (snap.tables.names ?? []) as any[]) {
    let rec: unknown
    try { rec = JSON.parse(r.record) } catch { throw new Error('archive contains an invalid name record') }
    if (!(await validateRecord(rec))) throw new Error('archive contains an invalid name record')
  }
  return { ...snap, ...info, keyBytes }
}

export interface RestoreResult { peerId: string, did: string, replaced: string | null, unchanged: boolean, added: Record<string, number>, blocks: number, identityLog: 'written' | 'kept' | 'none' }

/**
 * Restore into `dataDir` (node stopped). Order matters: the key is installed first (it refuses to replace a different
 * identity without `force`), then rows are merged in one transaction (existing rows win), then blocks. Re-running is safe.
 */
export async function restoreArchive (dataDir: string, bytes: Uint8Array, passphrase: string, opts: { force?: boolean } = {}): Promise<RestoreResult> {
  const snap = await openArchive(bytes, passphrase)
  const k = installKey(dataDir, snap.keyBytes, opts.force ? { force: true } : {})
  let identityLog: RestoreResult['identityLog'] = 'none'
  if (snap.identityLog) {
    const have = readIdentityLog(dataDir)
    let keep = false
    if (have) { try { const h = await verifyLog(have); const s = await verifyLog(snap.identityLog); keep = !(extendsLog(h.events, s.events) && s.seq > h.seq) } catch { keep = false } }
    if (!keep) { writeIdentityLog(dataDir, snap.identityLog); identityLog = 'written' } else identityLog = 'kept'
  }
  const store = new Store(dataDir)
  try {
    const added = store.importTables(snap.tables)
    for (const b of snap.blocks) store.putBlock(b.cid, Buffer.from(b.data, 'base64'), b.expires)
    return { peerId: k.peerId, did: k.did, replaced: k.replaced, unchanged: k.unchanged, added, blocks: snap.blocks.length, identityLog }
  } finally { store.close() }
}
