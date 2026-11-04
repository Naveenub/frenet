import { createHash } from 'node:crypto'
import { generateKeyPair } from '@libp2p/crypto/keys'
import type { PrivateKey } from '@libp2p/interface'

/**
 * Sybil resistance. A peer ID costs nothing to create, so on its own it proves nothing about how many
 * machines are behind it. Two cheap, local defences are provided here (neither is a full solution, see
 * docs/ARCHITECTURE.md "Reputation, Sybil resistance and detection"):
 *
 *  1. Identity proof-of-work (S/Kademlia style). A key is "worth N bits" if sha256("frenet-pow/v1" || publicKey)
 *     starts with N zero bits. A node started with `minIdentityBits = N` refuses connections from peers whose
 *     key is cheaper. Minting k identities then costs about k * 2^N hashes, instead of nothing.
 *  2. Network-diversity limits. At most `maxPerSubnet` distinct peers per IPv4 /24 (IPv6 /48) at a time, so one
 *     host or hosting range cannot fill all of a node's connection slots with throw-away identities.
 */

const POW_DOMAIN = 'frenet-pow/v1\n'
export const MAX_IDENTITY_BITS = 32

/** Leading zero bits of sha256(domain || raw public key). */
export function identityWorkBits (publicKeyRaw: Uint8Array): number {
  const h = createHash('sha256').update(POW_DOMAIN).update(publicKeyRaw).digest()
  let bits = 0
  for (const byte of h) {
    if (byte === 0) { bits += 8; continue }
    bits += Math.clz32(byte) - 24
    break
  }
  return bits
}

export function meetsIdentityWork (publicKeyRaw: Uint8Array | undefined, minBits: number): boolean {
  if (minBits <= 0) return true
  if (!publicKeyRaw) return false   // no inline public key (not an Ed25519 peer ID): cannot be checked, so refused
  return identityWorkBits(publicKeyRaw) >= minBits
}

/** Generate Ed25519 keys until one carries at least `bits` of work. Expected tries: 2^bits. */
export async function mineIdentity (bits: number, opts: { maxTries?: number, onProgress?: (tries: number) => void } = {}): Promise<{ key: PrivateKey, bits: number, tries: number }> {
  if (!Number.isInteger(bits) || bits < 0 || bits > MAX_IDENTITY_BITS) throw new Error(`bits must be an integer 0..${MAX_IDENTITY_BITS}`)
  const maxTries = opts.maxTries ?? Number.MAX_SAFE_INTEGER
  for (let tries = 1; tries <= maxTries; tries++) {
    const key = await generateKeyPair('Ed25519')
    const got = identityWorkBits(key.publicKey.raw)
    if (got >= bits) return { key, bits: got, tries }
    if (tries % 5000 === 0) opts.onProgress?.(tries)
  }
  throw new Error(`no key with ${bits} bits found in ${maxTries} tries`)
}

/** Network group a connection counts against, or null for addresses that are exempt (loopback, LAN, link-local, relayed). */
export function subnetKey (addr: string, opts: { includePrivate?: boolean } = {}): string | null {
  if (addr.includes('/p2p-circuit')) return null   // the relay, not the peer, owns the address
  const v4 = /^\/ip4\/(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?:\/|$)/.exec(addr)
  if (v4) {
    const [a, b, c] = [Number(v4[1]), Number(v4[2]), Number(v4[3])]
    if (!opts.includePrivate && (a === 127 || a === 10 || a === 0 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254) || (a === 100 && b >= 64 && b <= 127))) return null
    return `v4:${a}.${b}.${c}`
  }
  const v6 = /^\/ip6\/([0-9a-fA-F:]+)(?:\/|$)/.exec(addr)
  if (v6) {
    const g = expandV6(v6[1]!)
    if (!g) return null
    if (!opts.includePrivate && (g.every((x) => x === 0) || (g.slice(0, 7).every((x) => x === 0) && g[7] === 1) || (g[0]! & 0xfe00) === 0xfc00 || (g[0]! & 0xffc0) === 0xfe80)) return null
    return `v6:${g.slice(0, 3).map((x) => x.toString(16)).join(':')}`
  }
  return null   // DNS names and other transports: not classified
}

function expandV6 (s: string): number[] | null {
  const halves = s.split('::')
  if (halves.length > 2) return null
  const head = halves[0] ? halves[0].split(':') : []
  const tail = halves.length === 2 && halves[1] ? halves[1].split(':') : []
  const fill = halves.length === 2 ? 8 - head.length - tail.length : 0
  if (fill < 0 || (halves.length === 1 && head.length !== 8)) return null
  const groups = [...head, ...Array(fill).fill('0'), ...tail]
  if (groups.length !== 8 || groups.some((x) => !/^[0-9a-fA-F]{1,4}$/.test(x))) return null
  return groups.map((x) => parseInt(x, 16))
}

/**
 * Remembers which peer IDs were seen from which network group. `admit` is the hard limit used by the
 * connection gater (distinct *currently connected* peers per group); `observe` keeps a sliding window of
 * distinct peers per group so that a burst of identities from one range can be flagged as a Sybil cluster.
 */
export class SybilGuard {
  private window = new Map<string, Map<string, number>>()
  private flagged = new Set<string>()

  constructor (readonly opts: { maxPerSubnet: number, clusterSize: number, windowMs: number, includePrivate?: boolean } = { maxPerSubnet: 8, clusterSize: 6, windowMs: 3_600_000 }) {}

  /** May `peer` (at `addr`) connect, given the peers currently connected from the same group? */
  admit (peer: string, addr: string, connectedPeersByAddr: Array<{ peer: string, addr: string }>): boolean {
    const k = subnetKey(addr, this.opts)
    if (!k) return true
    const others = new Set<string>()
    for (const c of connectedPeersByAddr) if (c.peer !== peer && subnetKey(c.addr, this.opts) === k) others.add(c.peer)
    return others.size < this.opts.maxPerSubnet
  }

  /** Record a sighting. Returns the peers newly implicated in a cluster (empty if none or already flagged). */
  observe (peer: string, addr: string, now = Date.now()): string[] {
    const k = subnetKey(addr, this.opts)
    if (!k) return []
    let m = this.window.get(k)
    if (!m) {
      if (this.window.size >= 4096) this.window.delete(this.window.keys().next().value as string)   // bounded memory
      m = new Map(); this.window.set(k, m)
    }
    m.set(peer, now)
    for (const [p, t] of m) if (now - t > this.opts.windowMs) { m.delete(p); this.flagged.delete(`${k}|${p}`) }
    if (m.size < this.opts.clusterSize) return []
    const fresh: string[] = []
    for (const p of m.keys()) if (!this.flagged.has(`${k}|${p}`)) { this.flagged.add(`${k}|${p}`); fresh.push(p) }
    return fresh
  }

  clusters (now = Date.now()): Array<{ subnet: string, peers: number }> {
    const out: Array<{ subnet: string, peers: number }> = []
    for (const [k, m] of this.window) {
      const live = [...m.values()].filter((t) => now - t <= this.opts.windowMs).length
      if (live >= this.opts.clusterSize) out.push({ subnet: k, peers: live })
    }
    return out
  }
}
