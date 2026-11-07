import { createCipheriv, createDecipheriv, createHash, hkdfSync, randomBytes } from 'node:crypto'
import { ed25519, x25519 } from '@noble/curves/ed25519.js'
import { peerIdFromString } from '@libp2p/peer-id'
import type { PrivateKey } from '@libp2p/interface'

/**
 * End-to-end encryption for community chat. Each message gets a random content key `K`; the text is sealed with
 * AES-256-GCM under `K`, and `K` is wrapped separately for every member: an ephemeral X25519 key agrees a secret with
 * the member's identity key (Ed25519 -> X25519), HKDF turns it into a wrapping key. Only the members named at send
 * time can open it: relays, removed members and members added later cannot. The envelope is what the author signs,
 * so the signature stays verifiable by anyone while the text stays private. There is no ratchet, so a stolen
 * identity key opens every message that was addressed to it (no forward secrecy).
 */
export const ENVELOPE_VERSION = 1
export const MAX_ENVELOPE_BYTES = 32 * 1024
const MAX_WRAPS = 100
const INFO = 'frenet-group-msg/v1'

export interface Envelope { e: 1, epk: string, n: string, c: string, k: Record<string, string> }

const b64 = (b: Uint8Array): string => Buffer.from(b).toString('base64')
const unb64 = (s: string): Buffer => Buffer.from(s, 'base64')

/** 8-character, non-reversible label that lets a member find their own wrapped key without listing peer IDs. */
export function tagOf (peer: string): string { return createHash('sha256').update(`${INFO}\n${peer}`).digest().subarray(0, 6).toString('base64url') }

const montPub = (peer: string): Uint8Array => {
  const pub = peerIdFromString(peer).publicKey
  if (!pub || pub.type !== 'Ed25519') throw new Error('not an Ed25519 peer')
  return ed25519.utils.toMontgomery(pub.raw)
}

const kek = (shared: Uint8Array, epk: Uint8Array, community: string, recipient: string): Buffer =>
  Buffer.from(hkdfSync('sha256', shared, epk, `${INFO}|${community}|${recipient}`, 32))

function gcm (key: Uint8Array, nonce: Uint8Array, aad: string, data: Uint8Array): Buffer {
  const c = createCipheriv('aes-256-gcm', key, nonce)
  c.setAAD(Buffer.from(aad))
  return Buffer.concat([c.update(data), c.final(), c.getAuthTag()])
}

function ungcm (key: Uint8Array, nonce: Uint8Array, aad: string, data: Uint8Array): Buffer {
  if (data.length < 16) throw new Error('short ciphertext')
  const d = createDecipheriv('aes-256-gcm', key, nonce)
  d.setAAD(Buffer.from(aad))
  d.setAuthTag(data.subarray(data.length - 16))
  return Buffer.concat([d.update(data.subarray(0, data.length - 16)), d.final()])
}

const aadOf = (community: string, author: string): string => `${INFO}\n${community}\n${author}`

export function seal (text: string, community: string, author: string, recipients: string[]): string {
  const set = [...new Set([...recipients, author])]
  if (set.length > MAX_WRAPS) throw new Error('too many recipients')
  const K = randomBytes(32)
  const n = randomBytes(12)
  const esk = x25519.utils.randomSecretKey()
  const epk = x25519.getPublicKey(esk)
  const k: Record<string, string> = {}
  for (const r of set) {
    const wn = randomBytes(12)
    const wrapped = gcm(kek(x25519.getSharedSecret(esk, montPub(r)), epk, community, r), wn, aadOf(community, author), K)
    k[tagOf(r)] = b64(Buffer.concat([wn, wrapped]))
  }
  const env: Envelope = { e: 1, epk: b64(epk), n: b64(n), c: b64(gcm(K, n, aadOf(community, author), Buffer.from(text, 'utf8'))), k }
  return JSON.stringify(env)
}

/** Structural check only (no keys needed). Returns the parsed envelope, or null if the body is not a well-formed envelope. */
export function parseEnvelope (body: string): Envelope | null {
  if (body.charCodeAt(0) !== 0x7b) return null
  try {
    const o = JSON.parse(body)
    if (o?.e !== 1 || typeof o.epk !== 'string' || typeof o.n !== 'string' || typeof o.c !== 'string' || !o.k || typeof o.k !== 'object' || Array.isArray(o.k)) return null
    if (unb64(o.epk).length !== 32 || unb64(o.n).length !== 12 || unb64(o.c).length < 17) return null
    const entries = Object.entries(o.k)
    if (entries.length < 1 || entries.length > MAX_WRAPS) return null
    for (const [t, v] of entries) if (!/^[A-Za-z0-9_-]{8}$/.test(t) || typeof v !== 'string' || unb64(v).length !== 12 + 32 + 16) return null
    return o as Envelope
  } catch { return null }
}

/** Plaintext length of an envelope, for the text size limit. */
export const sealedTextBytes = (env: Envelope): number => unb64(env.c).length - 16

/** Open an envelope addressed to `self`. Returns null if it was not addressed to us or fails authentication. */
export function open (env: Envelope, community: string, author: string, self: string, key: PrivateKey): string | null {
  const wrapped = env.k[tagOf(self)]
  if (!wrapped) return null
  try {
    const epk = unb64(env.epk)
    const shared = x25519.getSharedSecret(ed25519.utils.toMontgomerySecret(key.raw.subarray(0, 32)), epk)
    const w = unb64(wrapped)
    const K = ungcm(kek(shared, epk, community, self), w.subarray(0, 12), aadOf(community, author), w.subarray(12))
    return ungcm(K, unb64(env.n), aadOf(community, author), unb64(env.c)).toString('utf8')
  } catch { return null }
}
