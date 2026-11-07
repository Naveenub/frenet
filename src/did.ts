import { publicKeyFromRaw } from '@libp2p/crypto/keys'
import type { PublicKey } from '@libp2p/interface'
import { peerIdFromPublicKey, peerIdFromString } from '@libp2p/peer-id'
import { base32 } from 'multiformats/bases/base32'
import { base58btc } from 'multiformats/bases/base58'
import { isWebDid } from './webid.js'

/**
 * `did:key` for Ed25519 (https://w3c-ccg.github.io/did-method-key/). A FRENET identity already is an Ed25519 key,
 * so its DID is derived from the same key as its peer ID: `did:key:z` + base58btc(0xed 0x01 || 32-byte public key).
 * The DID is self-certifying (no registry, nothing to capture) and resolves offline.
 *
 * Limits: a did:key cannot be rotated or revoked; the DID *is* the key. For an identity that can survive a lost or
 * stolen key use `did:frenet` (src/identity-log.ts); losing the key without that is handled by restoring it
 * (src/recovery.ts, src/archive.ts), not by changing the DID.
 */
const ED25519_PREFIX = Uint8Array.of(0xed, 0x01)
const DID_RE = /^did:key:(z[1-9A-HJ-NP-Za-km-z]{40,60})$/
const MAX_DID_URL = 200

export interface VerificationMethod { id: string, type: 'Multikey', controller: string, publicKeyMultibase: string }
export interface DidDocument {
  '@context': string[]
  id: string
  verificationMethod: VerificationMethod[]
  authentication: string[]
  assertionMethod: string[]
  capabilityInvocation: string[]
  capabilityDelegation: string[]
  alsoKnownAs: string[]
}

/** `did:key:z6Mk…` for a raw 32-byte Ed25519 public key. */
export function didFromPublicKeyRaw (raw: Uint8Array): string {
  if (raw.length !== 32) throw new Error('Ed25519 public key must be 32 bytes')
  const buf = new Uint8Array(ED25519_PREFIX.length + raw.length)
  buf.set(ED25519_PREFIX)
  buf.set(raw, ED25519_PREFIX.length)
  return `did:key:${base58btc.encode(buf)}`
}

/** Ed25519 peers embed their public key in the peer ID, so any Ed25519 peer ID maps to a DID. */
export function didFromPeerId (peerId: string): string {
  const pub = peerIdFromString(peerId).publicKey
  if (!pub || pub.type !== 'Ed25519') throw new Error('peer ID does not carry an Ed25519 public key')
  return didFromPublicKeyRaw(pub.raw)
}

/** Strict parse of a bare DID (no path, query or fragment). Rejects other methods, key types and non-canonical encodings. */
export function parseDidKey (did: unknown): { did: string, raw: Uint8Array, publicKey: PublicKey, keyId: string } {
  if (typeof did !== 'string' || did.length > MAX_DID_URL) throw new Error('invalid DID')
  const m = DID_RE.exec(did)
  if (!m) throw new Error('unsupported DID (only did:key with an Ed25519 key)')
  const multibase = m[1]!
  let bytes: Uint8Array
  try { bytes = base58btc.decode(multibase) } catch { throw new Error('invalid DID encoding') }
  if (bytes.length !== 34 || bytes[0] !== ED25519_PREFIX[0] || bytes[1] !== ED25519_PREFIX[1]) throw new Error('unsupported DID key type (only Ed25519)')
  if (base58btc.encode(bytes) !== multibase) throw new Error('non-canonical DID encoding')
  const raw = bytes.slice(2)
  return { did, raw, publicKey: publicKeyFromRaw(raw), keyId: multibase }
}

const FRENET_DID_RE = /^did:frenet:([a-z2-7]{52})$/

/** 52-char base32 of exactly 32 bytes, round-trip checked so non-canonical encodings are rejected. */
export function validB32 (s: unknown): s is string {
  if (typeof s !== 'string' || !/^[a-z2-7]{52}$/.test(s)) return false
  try { const raw = base32.baseDecode(s); return raw.length === 32 && base32.baseEncode(raw) === s } catch { return false }
}

/** `did:frenet:<id>`: a rotatable identity whose id is the digest of its inception event (src/identity-log.ts). */
export const isFrenetDid = (s: unknown): boolean => typeof s === 'string' && FRENET_DID_RE.test(s) && validB32(s.slice('did:frenet:'.length))
export const frenetDid = (id: string): string => { if (!validB32(id)) throw new Error('invalid identity id'); return `did:frenet:${id}` }
export const frenetId = (did: string): string => { if (!isFrenetDid(did)) throw new Error('invalid did:frenet'); return did.slice('did:frenet:'.length) }

/** Accept a DID (did:key or did:frenet), a peer ID, or null-ish input and return the canonical DID. Anything else throws. */
export function toDid (subject: unknown): string {
  if (typeof subject !== 'string' || subject === '') throw new Error('missing DID or peer ID')
  if (isFrenetDid(subject)) return subject
  if (isWebDid(subject)) return subject
  if (subject.startsWith('did:')) return parseDidKey(subject).did
  return didFromPeerId(subject)
}

export function peerIdFromDid (did: string): string {
  return peerIdFromPublicKey(parseDidKey(did).publicKey).toString()
}

/** The DID document is derived entirely from the identifier. */
export function didDocument (did: string): DidDocument {
  const { keyId, publicKey } = parseDidKey(did)
  const vm = `${did}#${keyId}`
  return {
    '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/multikey/v1'],
    id: did,
    verificationMethod: [{ id: vm, type: 'Multikey', controller: did, publicKeyMultibase: keyId }],
    authentication: [vm],
    assertionMethod: [vm],
    capabilityInvocation: [vm],
    capabilityDelegation: [vm],
    alsoKnownAs: [`frenet-peer://${peerIdFromPublicKey(publicKey).toString()}`]
  }
}

/** Resolve a DID or DID URL. did:key needs no network; other methods are refused rather than guessed. */
export function resolveDid (didOrUrl: string): { document: DidDocument, fragment: string | null } {
  if (typeof didOrUrl !== 'string' || didOrUrl.length > MAX_DID_URL) throw new Error('invalid DID')
  const hash = didOrUrl.indexOf('#')
  const did = hash === -1 ? didOrUrl : didOrUrl.slice(0, hash)
  const fragment = hash === -1 ? null : didOrUrl.slice(hash + 1)
  const document = didDocument(did)
  if (fragment !== null && fragment !== parseDidKey(did).keyId) throw new Error('unknown verification method')
  return { document, fragment }
}

/** The signer's key for a JWT `kid` (a DID URL) that must belong to `did`. */
export function keyForKid (did: string, kid: unknown): PublicKey {
  const p = parseDidKey(did)
  if (kid !== undefined && kid !== `${did}#${p.keyId}`) throw new Error('kid does not match issuer')
  return p.publicKey
}
