import { createCipheriv, createDecipheriv, createHash, randomBytes, scrypt, timingSafeEqual, type BinaryLike, type ScryptOptions } from 'node:crypto'
import { chmodSync, existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { promisify } from 'node:util'
import { privateKeyFromProtobuf } from '@libp2p/crypto/keys'
import { peerIdFromPrivateKey } from '@libp2p/peer-id'
import { didFromPublicKeyRaw } from './did.js'

/**
 * Account recovery. A FRENET account *is* its Ed25519 key: the peer ID, the did:key, every `<name>.<pub>` address and
 * every credential issued by or to you are derived from it. Recovery therefore means getting the same key back, not
 * minting a new one (a new key would be a different person to everyone who knows you). Two independent ways:
 *
 *  1. Encrypted backup: the key file sealed with a passphrase (scrypt -> AES-256-GCM). One file, one secret.
 *  2. Social recovery: the key split with Shamir secret sharing (GF(2^8)) into n shares, any k of which rebuild it
 *     and any k-1 of which reveal nothing. Hand them to people or places you trust, not to the network.
 *
 * What recovery cannot do: it does not help if the key is *stolen* (whoever holds it is you; a did:key cannot be
 * revoked or rotated), and it does not restore file links/keys, which are never stored (see ARCHITECTURE: files).
 */

const scryptAsync = promisify(scrypt) as (pw: BinaryLike, salt: BinaryLike, len: number, o: ScryptOptions) => Promise<Buffer>

// ---------------------------------------------------------------------------------------------------------------
// Key file helpers
// ---------------------------------------------------------------------------------------------------------------

export const KEY_FILE = 'identity.key'

/** Parse protobuf key bytes and require Ed25519. Returns the peer ID and DID they correspond to. */
export function describeKey (protobuf: Uint8Array): { peerId: string, did: string } {
  let key
  try { key = privateKeyFromProtobuf(protobuf) } catch { throw new Error('not a valid identity key') }
  if (key.type !== 'Ed25519') throw new Error('identity key must be Ed25519')
  return { peerId: peerIdFromPrivateKey(key).toString(), did: didFromPublicKeyRaw(key.publicKey.raw) }
}

/** Read `<dataDir>/identity.key` without creating anything. */
export function readKeyFile (dataDir: string): Uint8Array {
  const file = join(dataDir, KEY_FILE)
  if (!existsSync(file)) throw new Error(`no identity in ${dataDir} (start the node once to create one)`)
  const bytes = new Uint8Array(readFileSync(file))
  describeKey(bytes)
  return bytes
}

export const LOG_FILE = 'identity-log.json'

/** The identity's public key event log (rotatable did:frenet), if one was set up. Unverified: callers verifyLog(). */
export function readIdentityLog (dataDir: string): unknown[] | null {
  const file = join(dataDir, LOG_FILE)
  if (!existsSync(file)) return null
  const x = JSON.parse(readFileSync(file, 'utf8'))
  if (!Array.isArray(x)) throw new Error(`${file} is not an identity log`)
  return x
}

/** Atomic write (the log is public, but a torn file would lock the identity out). */
export function writeIdentityLog (dataDir: string, events: unknown[]): void {
  mkdirSync(dataDir, { recursive: true, mode: 0o700 })
  const file = join(dataDir, LOG_FILE)
  const tmp = `${file}.tmp-${randomBytes(4).toString('hex')}`
  writeFileSync(tmp, JSON.stringify(events, null, 1) + '\n', { mode: 0o600, flag: 'wx' })
  renameSync(tmp, file)
}

/**
 * Install a recovered key as `<dataDir>/identity.key` (0600). An existing, different key is never overwritten silently:
 * it needs `force` and is kept next to the new one as `identity.key.replaced-<time>`. Stop the node before restoring.
 */
export function installKey (dataDir: string, protobuf: Uint8Array, opts: { force?: boolean } = {}): { peerId: string, did: string, replaced: string | null, unchanged: boolean } {
  const info = describeKey(protobuf)
  mkdirSync(dataDir, { recursive: true, mode: 0o700 })
  const file = join(dataDir, KEY_FILE)
  let replaced: string | null = null
  if (existsSync(file)) {
    const current = new Uint8Array(readFileSync(file))
    let same = false
    try { same = describeKey(current).peerId === info.peerId } catch { /* unreadable current key: treat as different */ }
    if (same) return { ...info, replaced: null, unchanged: true }
    if (!opts.force) throw new Error(`${file} already holds a different identity; pass force to replace it (the old key is kept as a .replaced-* file)`)
    replaced = `${file}.replaced-${Date.now()}`
    renameSync(file, replaced)
    chmodSync(replaced, 0o600)
  }
  const tmp = `${file}.tmp-${randomBytes(4).toString('hex')}`
  writeFileSync(tmp, protobuf, { mode: 0o600, flag: 'wx' })
  chmodSync(tmp, 0o600)
  renameSync(tmp, file)
  return { ...info, replaced, unchanged: false }
}

// ---------------------------------------------------------------------------------------------------------------
// 1. Passphrase-encrypted backup
// ---------------------------------------------------------------------------------------------------------------

const BACKUP_PREFIX = 'frenet-backup:v1:'
export const MIN_PASSPHRASE = 12
export const SCRYPT_N = 2 ** 17
export const SCRYPT_MAX_N = 2 ** 18   // a backup file is untrusted input: cap the work it can ask for
export const SCRYPT_R = 8
export const SCRYPT_P = 1

interface BackupDoc { v: 1, kdf: 'scrypt', N: number, r: number, p: number, salt: string, nonce: string, ct: string, peer: string }

const aad = (d: Pick<BackupDoc, 'peer' | 'N' | 'r' | 'p' | 'salt'>): Buffer => Buffer.from(`frenet-backup/v1\n${d.peer}\n${d.N}\n${d.r}\n${d.p}\n${d.salt}`, 'utf8')

export function checkPassphrase (pw: unknown): string {
  if (typeof pw !== 'string' || [...pw].length < MIN_PASSPHRASE) throw new Error(`passphrase must be at least ${MIN_PASSPHRASE} characters`)
  return pw.normalize('NFKC')
}

export const derive = (pw: string, salt: Buffer, N: number, r: number, p: number): Promise<Buffer> =>
  scryptAsync(pw, salt, 32, { N, r, p, maxmem: 256 * N * r + 1024 * 1024 })

/** Seal the key bytes under a passphrase. The result is one printable line, safe to store anywhere you keep backups. */
export async function createBackup (protobuf: Uint8Array, passphrase: string, opts: { N?: number } = {}): Promise<string> {
  const { peerId } = describeKey(protobuf)
  const pw = checkPassphrase(passphrase)
  const N = opts.N ?? SCRYPT_N
  if (!Number.isInteger(Math.log2(N)) || N < 2 ** 10 || N > SCRYPT_MAX_N) throw new Error('invalid scrypt cost')
  const salt = randomBytes(16)
  const nonce = randomBytes(12)
  const meta = { peer: peerId, N, r: SCRYPT_R, p: SCRYPT_P, salt: salt.toString('base64') }
  const cipher = createCipheriv('aes-256-gcm', await derive(pw, salt, N, SCRYPT_R, SCRYPT_P), nonce)
  cipher.setAAD(aad(meta))
  const ct = Buffer.concat([cipher.update(protobuf), cipher.final(), cipher.getAuthTag()])
  const doc: BackupDoc = { v: 1, kdf: 'scrypt', ...meta, nonce: nonce.toString('base64'), ct: ct.toString('base64') }
  return BACKUP_PREFIX + Buffer.from(JSON.stringify(doc)).toString('base64url')
}

/** Decrypt a backup. A wrong passphrase and a tampered file are indistinguishable by design. */
export async function openBackup (text: string, passphrase: string): Promise<{ protobuf: Uint8Array, peerId: string, did: string }> {
  const t = String(text).trim()
  if (!t.startsWith(BACKUP_PREFIX) || t.length > 4096) throw new Error('not a FRENET backup')
  let doc: any
  try { doc = JSON.parse(Buffer.from(t.slice(BACKUP_PREFIX.length), 'base64url').toString('utf8')) } catch { throw new Error('not a FRENET backup') }
  const ok = doc && doc.v === 1 && doc.kdf === 'scrypt' && typeof doc.peer === 'string' && doc.peer.length <= 128 &&
    typeof doc.salt === 'string' && typeof doc.nonce === 'string' && typeof doc.ct === 'string' &&
    Number.isInteger(doc.N) && doc.N >= 2 ** 10 && doc.N <= SCRYPT_MAX_N && Number.isInteger(Math.log2(doc.N)) && doc.r === SCRYPT_R && doc.p === SCRYPT_P
  if (!ok) throw new Error('unsupported or corrupted backup')
  const salt = Buffer.from(doc.salt, 'base64')
  const nonce = Buffer.from(doc.nonce, 'base64')
  const ct = Buffer.from(doc.ct, 'base64')
  if (salt.length !== 16 || nonce.length !== 12 || ct.length < 17 || ct.length > 1024) throw new Error('unsupported or corrupted backup')
  const key = await derive(checkPassphrase(passphrase), salt, doc.N, doc.r, doc.p)
  const decipher = createDecipheriv('aes-256-gcm', key, nonce)
  decipher.setAAD(aad(doc))
  decipher.setAuthTag(ct.subarray(ct.length - 16))
  let plain: Buffer
  try { plain = Buffer.concat([decipher.update(ct.subarray(0, ct.length - 16)), decipher.final()]) } catch { throw new Error('wrong passphrase or corrupted backup') }
  const info = describeKey(plain)
  if (info.peerId !== doc.peer) throw new Error('backup does not match its recorded identity')
  return { protobuf: new Uint8Array(plain), ...info }
}

// ---------------------------------------------------------------------------------------------------------------
// 2. Shamir secret sharing over GF(2^8)
// ---------------------------------------------------------------------------------------------------------------

// GF(256) with the AES polynomial x^8+x^4+x^3+x+1 (0x11b). Secret bytes flow through these functions, so they use no
// lookup tables and no data-dependent branches: every call does the same fixed sequence of shifts, ANDs and XORs.
// (JavaScript gives no hard constant-time guarantee, since the JIT may rewrite code, but nothing here indexes memory or
// branches on a secret value, which removes the cache- and branch-timing channels of the earlier log/exp tables.)
export const gfMul = (a: number, b: number): number => {
  let r = 0
  a &= 0xff; b &= 0xff
  for (let i = 0; i < 8; i++) {
    r ^= a & -(b & 1)                          // add a if the low bit of b is set (mask is 0 or -1)
    a = ((a << 1) & 0xff) ^ (0x1b & -(a >> 7)) // a *= x, reduce when the top bit was set
    b >>= 1
  }
  return r
}
/** a^-1 = a^254 by a fixed square-and-multiply chain (0 maps to 0). */
const gfInv = (a: number): number => {
  const a2 = gfMul(a, a); const a3 = gfMul(a2, a); const a6 = gfMul(a3, a3); const a12 = gfMul(a6, a6)
  const a14 = gfMul(a12, a2); const a15 = gfMul(a12, a3)
  const a30 = gfMul(a15, a15); const a60 = gfMul(a30, a30); const a120 = gfMul(a60, a60); const a240 = gfMul(a120, a120)
  return gfMul(a240, a14)   // 240 + 14 = 254
}
/** Division. `b` must be a public value (a share position); a zero divisor is a caller bug, not secret-dependent. */
export const gfDiv = (a: number, b: number): number => {
  if (b === 0) throw new Error('division by zero')
  return gfMul(a, gfInv(b))
}

const SHARE_PREFIX = 'frenet-share:1:'
export const MAX_SHARES = 32
const CHECK_LEN = 4

const checksum = (s: string): string => createHash('sha256').update(s).digest('hex').slice(0, 8)

export interface ParsedShare { k: number, set: string, x: number, data: Buffer }

/**
 * Split `secret` into `n` shares, any `k` (2 <= k <= n <= 32) of which recover it. Each share is one printable line that
 * carries its own checksum (typos are caught), a random set id (shares of different splits are never mixed) and the
 * threshold. The secret gets a 4-byte hash appended before splitting so a wrong combination is detected, not returned.
 */
export function splitSecret (secret: Uint8Array, k: number, n: number): string[] {
  if (!Number.isInteger(k) || !Number.isInteger(n) || k < 2 || n < k || n > MAX_SHARES) throw new Error(`need 2 <= k <= n <= ${MAX_SHARES}`)
  if (secret.length === 0 || secret.length > 512) throw new Error('secret size out of range')
  const framed = Buffer.concat([secret, createHash('sha256').update(secret).digest().subarray(0, CHECK_LEN)])
  const set = randomBytes(4).toString('hex')
  const ys = Array.from({ length: n }, () => Buffer.alloc(framed.length))
  for (let i = 0; i < framed.length; i++) {
    const coef = randomBytes(k - 1)   // uniformly random higher-order coefficients: any k-1 shares are independent of the secret
    for (let s = 0; s < n; s++) {
      const x = s + 1
      let y = 0
      for (let c = k - 2; c >= 0; c--) y = gfMul(y, x) ^ coef[c]!   // Horner over the random coefficients
      ys[s]![i] = gfMul(y, x) ^ framed[i]!
    }
  }
  return ys.map((data, s) => {
    const body = `${SHARE_PREFIX}${k}:${set}:${s + 1}:${data.toString('base64url')}`
    return `${body}:${checksum(body)}`
  })
}

export function parseShare (text: string): ParsedShare {
  if (typeof text !== 'string') throw new Error('not a FRENET recovery share')
  const t = text.trim()
  const parts = t.split(':')
  if (!t.startsWith(SHARE_PREFIX) || parts.length !== 7 || t.length > 2048) throw new Error('not a FRENET recovery share')
  const body = parts.slice(0, 6).join(':')
  if (checksum(body) !== parts[6]) throw new Error('share is damaged (checksum mismatch): re-check how it was copied')
  const k = Number(parts[2]); const x = Number(parts[4])
  const set = parts[3]!
  if (!Number.isInteger(k) || k < 2 || k > MAX_SHARES || !/^[0-9a-f]{8}$/.test(set) || !Number.isInteger(x) || x < 1 || x > MAX_SHARES) throw new Error('invalid share')
  const data = Buffer.from(parts[5]!, 'base64url')
  if (data.length <= CHECK_LEN || data.toString('base64url') !== parts[5]) throw new Error('invalid share')
  return { k, set, x, data }
}

/** Rebuild the secret from at least k shares of one split. Throws on too few, mixed, duplicate or inconsistent shares. */
export function combineShares (texts: string[]): Uint8Array {
  if (!Array.isArray(texts) || texts.length > MAX_SHARES) throw new Error(`give between 1 and ${MAX_SHARES} shares`)
  const shares = texts.map(parseShare)
  if (shares.length === 0) throw new Error('no shares given')
  const { k, set } = shares[0]!
  if (shares.some((s) => s.set !== set || s.k !== k)) throw new Error('shares come from different splits')
  const len = shares[0]!.data.length
  if (shares.some((s) => s.data.length !== len)) throw new Error('shares have different lengths')
  const unique = new Map<number, ParsedShare>()
  for (const s of shares) {
    const seen = unique.get(s.x)
    if (seen && !seen.data.equals(s.data)) throw new Error(`two different shares claim position ${s.x}`)
    unique.set(s.x, s)
  }
  if (unique.size < k) throw new Error(`need ${k} shares, got ${unique.size}`)
  const use = [...unique.values()].slice(0, k)
  const out = Buffer.alloc(len)
  for (let i = 0; i < len; i++) {
    let acc = 0
    for (const a of use) {
      // Lagrange basis at 0 in characteristic 2: prod_{b != a} x_b / (x_a ^ x_b)
      let l = 1
      for (const b of use) if (b !== a) l = gfMul(l, gfDiv(b.x, a.x ^ b.x))
      acc ^= gfMul(a.data[i]!, l)
    }
    out[i] = acc
  }
  const secret = out.subarray(0, len - CHECK_LEN)
  const check = createHash('sha256').update(secret).digest().subarray(0, CHECK_LEN)
  if (!timingSafeEqual(check, out.subarray(len - CHECK_LEN))) throw new Error('shares do not combine to a valid secret (wrong or corrupted share)')
  return new Uint8Array(secret)
}
