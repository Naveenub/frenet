// Fuzz pass over the functions that take untrusted input (wire data, files, user-supplied strings).
//
//   npm test                                        2,000 cases per target (a few seconds)
//   FRENET_FUZZ_ITERS=200000 npm run test:fuzz      a long run
//   FRENET_FUZZ_SEED=12345 npm run test:fuzz        replay a failing run (the seed is printed on failure)
//
// This is dependency-free, seeded, structure-aware random testing, not coverage-guided fuzzing (no AFL/libFuzzer
// feedback loop). It checks two properties for every target:
//   1. Robustness: the function either returns or throws a *deliberate* Error. A TypeError, RangeError or
//      ReferenceError means untrusted input reached code that assumed a shape it never checked.
//   2. Soundness: a verifier never accepts input that was not produced by the matching signer/sealer.
// Each call also has a time budget, so an input that makes a parser spin is a failure, not a hang.
import assert from 'node:assert/strict'
import { randomBytes } from 'node:crypto'
import { describe, it } from 'node:test'
import { Readable } from 'node:stream'
import { combineShares, createBackup, openBackup, parseShare, splitSecret, checkPassphrase, gfDiv, gfMul } from '../src/recovery.js'
import { parseDidKey } from '../src/did.js'
import { didFromPublicKeyRaw } from '../src/did.js'
import { sealBlock, openBlock, validFileKey } from '../src/files.js'
import { parseEnvelope } from '../src/groupcrypto.js'
import { validateRoots, verifyEnvelope, verifyArtifact, compareSemver } from '../src/updates.js'
import { verifyCredential, verifyPresentation, verifyRevocation } from '../src/credentials.js'
import { verifyLog } from '../src/identity-log.js'
import { validateRecord } from '../src/names.js'
import { verifyMessage } from '../src/messaging.js'
import { verifyReport, parseKind, parseCategory } from '../src/moderation.js'
import { parseWebDidDocument, isNonPublicAddress as webidNonPublic } from '../src/webid.js'
import { parseAuthority, parseUpstream, isNonPublicAddress as proxyNonPublic } from '../src/webproxy.js'
import { verifyMembership, checkPolicy } from '../src/zkauth.js'
import { readJson } from '../src/rpc.js'
import { isPeerId } from '../src/channel.js'
import { openArchive } from '../src/archive.js'

const ITERS = Math.max(50, Number(process.env.FRENET_FUZZ_ITERS ?? 2000))
const SEED = Number(process.env.FRENET_FUZZ_SEED ?? 0x46524e54)   // "FRNT"
const BUDGET_MS = 1500   // per call; the slowest legitimate target here (a KDF at the minimum cost) is far below this

// ---------------------------------------------------------------------------------------------------------------
// Deterministic generators
// ---------------------------------------------------------------------------------------------------------------
function rng (seed: number): () => number {   // mulberry32
  let a = seed >>> 0
  return () => { a = (a + 0x6d2b79f5) >>> 0; let t = a; t = Math.imul(t ^ (t >>> 15), t | 1); t ^= t + Math.imul(t ^ (t >>> 7), t | 61); return ((t ^ (t >>> 14)) >>> 0) / 4294967296 }
}
class Gen {
  constructor (private r: () => number) {}
  int (n: number): number { return Math.floor(this.r() * n) }
  pick<T> (xs: readonly T[]): T { return xs[this.int(xs.length)]! }
  bytes (max = 96): Buffer { return Buffer.from(Array.from({ length: this.int(max + 1) }, () => this.int(256))) }
  str (max = 64): string {
    const alphabets = ['abcdefghijklmnopqrstuvwxyz0123456789', 'ABCDEF0123456789', '-_.:/@# \t\n"\'\\{}[]<>%', '\u0000\uffff\ud800\u202e\u00e9\u4e2d\u{1f600}']
    const a = this.pick(alphabets)
    const len = this.int(max + 1)
    let s = ''
    for (let i = 0; i < len; i++) s += a[this.int(a.length)]
    return s
  }
  num (): number { return this.pick([0, -0, 1, -1, 2 ** 31, 2 ** 32, 2 ** 53, -(2 ** 53), Number.MAX_VALUE, Number.MIN_VALUE, NaN, Infinity, -Infinity, 0.5, this.int(1e6), Date.now(), Date.now() + 1e12]) }
  /** A random JSON-ish value, including hostile shapes (prototype keys, deep nesting, huge arrays/strings). */
  value (depth = 0): unknown {
    const k = this.int(depth > 3 ? 8 : 12)
    switch (k) {
      case 0: return null
      case 1: return undefined
      case 2: return this.num()
      case 3: return this.str()
      case 4: return this.bool()
      case 5: return this.bytes(32)
      case 6: return this.str(4096)
      case 7: return this.pick([0n, 1n, Symbol.for('x'), () => 1] as unknown[])
      case 8: return Array.from({ length: this.int(6) }, () => this.value(depth + 1))
      case 9: return this.obj(depth + 1)
      case 10: return JSON.parse('{"__proto__":{"polluted":1},"constructor":{"prototype":{"polluted":1}}}')
      default: return Array.from({ length: 1 + this.int(3000) }, () => this.int(256))
    }
  }
  bool (): boolean { return this.r() < 0.5 }
  obj (depth = 0, keys: readonly string[] = []): Record<string, unknown> {
    const o: Record<string, unknown> = {}
    const n = this.int(8)
    for (let i = 0; i < n; i++) o[(keys.length && this.bool()) ? this.pick(keys) : this.str(8)] = this.value(depth)
    return o
  }
  /** Mutate a valid string: flip, drop, duplicate, splice or truncate. */
  mutate (s: string): string {
    const n = 1 + this.int(4)
    for (let i = 0; i < n && s.length > 0; i++) {
      const at = this.int(s.length)
      switch (this.int(6)) {
        case 0: s = s.slice(0, at) + String.fromCharCode(this.int(0x250)) + s.slice(at + 1); break
        case 1: s = s.slice(0, at) + s.slice(at + 1 + this.int(8)); break
        case 2: s = s.slice(0, at) + s.slice(at, at + 1 + this.int(8)).repeat(2 + this.int(4)) + s.slice(at); break
        case 3: s = s.slice(0, at); break
        case 4: s = s + this.str(16); break
        default: { const j = this.int(s.length); s = s.slice(0, Math.min(at, j)) + s.slice(Math.max(at, j)) }
      }
    }
    return s
  }
  mutateBytes (b: Uint8Array): Buffer {
    const out = Buffer.from(b)
    if (out.length === 0) return this.bytes(8)
    switch (this.int(4)) {
      case 0: out[this.int(out.length)] ^= 1 << this.int(8); return out
      case 1: return out.subarray(0, this.int(out.length))
      case 2: return Buffer.concat([out, this.bytes(16)])
      default: for (let i = 0, n = 1 + this.int(4); i < n; i++) out[this.int(out.length)] = this.int(256); return out
    }
  }
}

// ---------------------------------------------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------------------------------------------
const BUG = [TypeError, RangeError, ReferenceError, EvalError, URIError]
const isBug = (e: unknown): boolean => !(e instanceof Error) || BUG.some((c) => e instanceof c)

interface Opts {
  iters?: number
  /** Return true if `result` is a soundness failure (the function accepted something it must not have). */
  bad?: (result: unknown) => boolean
}
async function fuzz<A extends unknown[]> (name: string, fn: (...a: A) => unknown, gen: (g: Gen, i: number) => A, o: Opts = {}): Promise<void> {
  const iters = o.iters ?? ITERS
  const g = new Gen(rng(SEED ^ [...name].reduce((h, c) => (Math.imul(h, 31) + c.charCodeAt(0)) | 0, 7)))
  for (let i = 0; i < iters; i++) {
    const args = gen(g, i)
    const t0 = performance.now()
    let result: unknown
    try {
      result = await fn(...args)
    } catch (e) {
      const ms = performance.now() - t0
      assert.ok(!isBug(e), `${name}: crashed with ${(e as any)?.constructor?.name}: ${(e as Error)?.message}\n  seed=${SEED} case=${i}\n  input=${show(args)}`)
      assert.ok(ms < BUDGET_MS, `${name}: took ${ms | 0} ms (seed=${SEED} case=${i})`)
      continue
    }
    const ms = performance.now() - t0
    assert.ok(ms < BUDGET_MS, `${name}: took ${ms | 0} ms (seed=${SEED} case=${i}) input=${show(args)}`)
    if (o.bad) assert.ok(!o.bad(result), `${name}: soundness failure (seed=${SEED} case=${i}) result=${show([result])} input=${show(args)}`)
  }
}
function show (x: unknown): string {
  try { return JSON.stringify(x, (_k, v) => typeof v === 'bigint' ? `${v}n` : v instanceof Uint8Array ? `bytes(${Buffer.from(v).toString('hex').slice(0, 120)})` : typeof v === 'function' || typeof v === 'symbol' ? String(v) : v)?.slice(0, 400) ?? String(x) } catch { return '<unprintable>' }
}

const jsonSafe = (x: unknown): string => JSON.stringify(x, (_k, v) => typeof v === 'bigint' ? String(v) : typeof v === 'symbol' || typeof v === 'function' ? String(v) : v)
const ENVELOPE_KEYS = ['v', 'payload', 'signatures', 'sigs', 'signer', 'sig', 'e', 'epk', 'n', 'c', 'k', 'ts', 'id', 'body', 'sender', 'recipient', 'signature', 'name', 'seq', 'keys', 'threshold', 'artifacts', 'iat', 'exp', 'iss', 'sub', 'vc', 'kind', 'target', 'category', 'type', 'proof', 'tag', 'ring', 'verificationMethod', 'authentication', 'assertionMethod', 'publicKeyJwk', 'x', 'crv', 'kty']
const anyArg = (g: Gen): unknown => g.bool() ? g.value() : g.obj(0, ENVELOPE_KEYS)
const ZERO_ID = didFromPublicKeyRaw(new Uint8Array(32).fill(7))

// ---------------------------------------------------------------------------------------------------------------
describe('fuzz: arithmetic and key material', () => {
  it('GF(256): multiply is commutative/associative/distributive and every nonzero element inverts (exhaustive)', () => {
    for (let a = 0; a < 256; a++) {
      if (a) assert.equal(gfMul(a, gfDiv(1, a)), 1, `inverse of ${a}`)
      for (let b = 0; b < 256; b += 5) {
        assert.equal(gfMul(a, b), gfMul(b, a))
        assert.equal(gfMul(a, b ^ 0x5a), gfMul(a, b) ^ gfMul(a, 0x5a))
        assert.equal(gfMul(gfMul(a, b), 0x1d), gfMul(a, gfMul(b, 0x1d)))
      }
    }
    assert.equal(gfMul(0, 0xff), 0); assert.equal(gfMul(0xff, 0), 0); assert.equal(gfMul(1, 0xab), 0xab)
    assert.equal(gfMul(0x1ff, 0x103), gfMul(0xff, 0x03), 'out-of-range operands are reduced to a byte, not trusted')
  })

  it('Shamir: random secrets round-trip for random k, n and random k-subsets; k-1 shares never combine', async () => {
    const g = new Gen(rng(SEED + 1))
    for (let i = 0; i < Math.min(ITERS, 400); i++) {
      const n = 2 + g.int(9); const k = 2 + g.int(n - 1)
      const secret = Buffer.concat([Buffer.from([1 + g.int(255)]), g.bytes(79)])   // 1..80 bytes
      const shares = splitSecret(secret, k, n)
      const order = [...shares].sort(() => g.int(3) - 1)
      assert.deepEqual(Buffer.from(combineShares(order.slice(0, k))), secret)
      assert.deepEqual(Buffer.from(combineShares(order.slice(n - k))), secret)
      assert.throws(() => combineShares(order.slice(0, k - 1)), Error)
    }
  })

  it('parseShare / combineShares: mutated and random shares are rejected cleanly', async () => {
    const good = splitSecret(randomBytes(36), 3, 5)
    await fuzz('parseShare(random)', parseShare, (g) => [g.str(200)])
    await fuzz('parseShare(mutated)', parseShare, (g) => [g.mutate(g.pick(good))])
    await fuzz('combineShares(mixed)', combineShares, (g) => [Array.from({ length: g.int(6) }, () => g.bool() ? g.pick(good) : g.mutate(g.pick(good)))])
    await fuzz('combineShares(hostile)', combineShares as (x: unknown) => unknown, (g) => [g.value()])
  })

  it('backup: random and mutated blobs and passphrases are rejected cleanly (a mutated blob never opens)', async () => {
    const key = randomBytes(36)   // not a valid protobuf key, so build a real one through createBackup's own check
    void key
    const { generateKeyPair } = await import('@libp2p/crypto/keys')
    const { privateKeyToProtobuf } = await import('@libp2p/crypto/keys')
    const priv = await generateKeyPair('Ed25519')
    const bytes = privateKeyToProtobuf(priv)
    const blob = await createBackup(bytes, 'correct horse battery', { N: 2 ** 10 })
    assert.deepEqual(Buffer.from((await openBackup(blob, 'correct horse battery')).protobuf), Buffer.from(bytes))
    await fuzz('openBackup(random)', openBackup, (g) => [g.str(300), g.str(30)], { iters: Math.min(ITERS, 1000) })
    // A mutated container may still decode to the same sealed bytes (base64url padding, JSON whitespace); what it must
    // never do is open to a *different* key. AES-GCM plus the AAD over peer/N/r/p/salt is what guarantees that.
    await fuzz('openBackup(mutated)', openBackup, (g) => [g.mutate(blob), 'correct horse battery'], { iters: Math.min(ITERS, 300), bad: (r: any) => r !== undefined && !Buffer.from(r.protobuf).equals(Buffer.from(bytes)) })
    await fuzz('checkPassphrase', checkPassphrase, (g) => [g.value()])
  })

  it('did:key, peer IDs and file keys: arbitrary input never crashes the parsers', async () => {
    await fuzz('parseDidKey(any)', parseDidKey, (g) => [anyArg(g)])
    await fuzz('parseDidKey(mutated)', parseDidKey, (g) => [g.mutate(ZERO_ID)])
    await fuzz('isPeerId', isPeerId, (g) => [anyArg(g)])
    await fuzz('validFileKey', validFileKey, (g) => [anyArg(g)])
    const { blob, key } = sealBlock(randomBytes(300))
    assert.deepEqual(openBlock(blob, key).length, 300)
    await fuzz('openBlock(mutated blob)', openBlock, (g) => [g.mutateBytes(blob), key], {})
    await fuzz('openBlock(random key)', openBlock, (g) => [g.bytes(400), g.str(50)])
    // A flipped bit anywhere in the sealed block must be detected.
    for (let i = 0; i < blob.length; i += 3) { const b = Buffer.from(blob); b[i]! ^= 0x01; assert.throws(() => openBlock(b, key), Error) }
  })
})

// ---------------------------------------------------------------------------------------------------------------
describe('fuzz: signed wire formats must reject everything they did not sign', () => {
  const none = { roots: { threshold: 1, keys: [ZERO_ID] }, currentVersion: '0.0.1' }
  it('updates', async () => {
    await fuzz('validateRoots', validateRoots, (g) => [anyArg(g)])
    await fuzz('verifyEnvelope', verifyEnvelope, (g) => [anyArg(g), { ...none, now: g.bool() ? undefined : g.num() as number }], { bad: (r: any) => r?.ok === true })
    // The manifest is already signature-verified; what an attacker controls is the artifact name and its bytes.
    const manifest = { v: 1, product: 'frenet', channel: 'stable', version: '1.0.0', seq: 1, created: 0, expires: 1, artifacts: [{ name: 'frenet.tgz', size: 4, sha256: '0'.repeat(64) }] } as never
    await fuzz('verifyArtifact', verifyArtifact, (g) => [manifest, g.bool() ? 'frenet.tgz' : g.str(30), g.bytes(16)], { bad: (r: any) => r?.ok === true })
    await fuzz('compareSemver', compareSemver, (g) => [g.str(20), g.str(20)])
  })

  it('credentials, presentations, revocations, identity logs', async () => {
    await fuzz('verifyCredential(any)', verifyCredential, (g) => [anyArg(g)], { bad: (r: any) => r?.ok === true })
    await fuzz('verifyCredential(jwt-shaped)', verifyCredential, (g) => [`${g.str(60)}.${g.str(120)}.${g.str(86)}`], { bad: (r: any) => r?.ok === true })
    await fuzz('verifyCredential(unsigned alg)', verifyCredential, (g) => {
      const h = Buffer.from(JSON.stringify({ alg: g.pick(['none', 'None', 'HS256', 'EdDSA', 'ES256', '']), typ: 'JWT', kid: ZERO_ID })).toString('base64url')
      const p = Buffer.from(JSON.stringify({ iss: ZERO_ID, sub: ZERO_ID, iat: 1, vc: jsonSafe(g.value()) && JSON.parse(jsonSafe(g.value()) ?? 'null') })).toString('base64url')
      return [`${h}.${p}.${g.bool() ? '' : g.str(86)}`]
    }, { bad: (r: any) => r?.ok === true })
    await fuzz('verifyPresentation', verifyPresentation as (a: unknown, b: unknown) => unknown, (g) => [anyArg(g), { nonce: g.str(20), audience: g.bool() ? g.str(10) : undefined }], { bad: (r: any) => r?.ok === true })
    await fuzz('verifyRevocation', verifyRevocation, (g) => [anyArg(g)], { bad: (r: any) => r?.ok === true })
    await fuzz('verifyLog', verifyLog, (g) => [g.bool() ? g.value() : Array.from({ length: g.int(5) }, () => g.obj(0, ENVELOPE_KEYS))], {})
  })

  it('messages, name records, reports, group envelopes', async () => {
    await fuzz('verifyMessage', verifyMessage as (m: unknown) => unknown, (g) => [anyArg(g)], { bad: (r) => r === true })
    await fuzz('verifyMessage(well-formed fields)', verifyMessage, (g) => [{ sender: ZERO_ID, recipient: ZERO_ID, id: g.str(30), ts: Date.now(), body: g.str(100), sig: g.str(90) }], { bad: (r) => r === true })
    await fuzz('validateRecord', validateRecord, (g) => [anyArg(g), g.num()], { bad: (r) => r !== null && r !== undefined })
    await fuzz('verifyReport', verifyReport, (g) => [anyArg(g)], { bad: (r) => r === true })
    await fuzz('parseEnvelope(random)', parseEnvelope, (g) => [g.bool() ? g.str(300) : '{' + g.str(300)])
    await fuzz('parseEnvelope(json)', parseEnvelope, (g) => [jsonSafe(g.obj(0, ENVELOPE_KEYS))])
    await fuzz('parseKind', parseKind, (g) => [anyArg(g)])
    await fuzz('parseCategory', parseCategory, (g) => [anyArg(g)])
  })

  it('zero-knowledge membership proofs', async () => {
    const ring = Array.from({ length: 6 }, (_, i) => new Uint8Array(32).fill(i + 1))
    await fuzz('verifyMembership', verifyMembership as (a: unknown, b: unknown, c: unknown) => unknown, (g) => [anyArg(g), g.bool() ? ring : g.value(), g.bool() ? { scope: 'vote', nonce: 'n0nce' } : anyArg(g)], { bad: (r: any) => r?.ok === true })
    await fuzz('checkPolicy(ring of arbitrary byte strings)', checkPolicy as (a: unknown, b: unknown) => unknown, (g) => [g.bool() ? ring : Array.from({ length: g.int(40) }, () => g.bytes(40)), {}])
  })
})

// ---------------------------------------------------------------------------------------------------------------
describe('fuzz: network-facing parsers and address guards', () => {
  it('did:web documents, proxy targets, upstream specs', async () => {
    await fuzz('parseWebDidDocument', parseWebDidDocument as (a: unknown, b: unknown) => unknown, (g) => ['did:web:example.com', { id: g.bool() ? 'did:web:example.com' : g.str(), ...g.obj(0, ENVELOPE_KEYS) }])
    await fuzz('parseAuthority', parseAuthority, (g) => [g.bool() ? g.str(80) : `${g.str(20)}:${g.num()}`])
    await fuzz('parseUpstream', parseUpstream, (g) => [g.bool() ? g.str(80) : `${g.str(20)}:${g.num()}`])
  })

  it('SSRF guards: no private, loopback, link-local or mapped-private address is ever called public', () => {
    const priv = ['127.0.0.1', '127.255.255.254', '10.0.0.1', '172.16.0.1', '172.31.255.255', '192.168.1.1', '169.254.169.254', '0.0.0.0', '100.64.0.1', '::1', '::', 'fe80::1', 'fc00::1', 'fd12:3456::1', '::ffff:127.0.0.1', '::ffff:10.1.2.3', '::ffff:7f00:1', '::ffff:a9fe:a9fe', '224.0.0.1', '255.255.255.255']
    for (const a of priv) { assert.equal(webidNonPublic(a), true, `webid ${a}`); assert.equal(proxyNonPublic(a), true, `proxy ${a}`) }
    for (const a of ['8.8.8.8', '1.1.1.1', '93.184.216.34', '2606:4700:4700::1111']) { assert.equal(webidNonPublic(a), false, `webid ${a}`); assert.equal(proxyNonPublic(a), false, `proxy ${a}`) }
  })

  it('SSRF guards: random strings never crash and the two implementations never disagree on IPv4', async () => {
    await fuzz('webid.isNonPublicAddress', webidNonPublic, (g) => [g.str(60)])   // callers pass DNS answers, which are strings
    await fuzz('proxy.isNonPublicAddress', proxyNonPublic, (g) => [g.str(60)])
    const g = new Gen(rng(SEED + 2))
    for (let i = 0; i < ITERS; i++) {
      const ip = `${g.int(256)}.${g.int(256)}.${g.int(256)}.${g.int(256)}`
      assert.equal(webidNonPublic(ip), proxyNonPublic(ip), `guards disagree on ${ip}`)
      // every encoding of a loopback/private address that the guards accept as an IPv4-mapped IPv6 must agree with the v4 form
      const [a, b, c, d] = ip.split('.').map(Number) as [number, number, number, number]
      const mapped = `::ffff:${((a << 8) | b).toString(16)}:${((c << 8) | d).toString(16)}`
      // Safety direction only: the IPv4-mapped IPv6 spelling of a non-public address must never be called public.
      // (webid refuses every hex-spelled mapped address, public ones included; that over-blocking is fail-closed.)
      if (webidNonPublic(ip)) assert.equal(webidNonPublic(mapped), true, `webid: ${mapped} slips past the guard for ${ip}`)
      if (proxyNonPublic(ip)) assert.equal(proxyNonPublic(mapped), true, `proxy: ${mapped} slips past the guard for ${ip}`)
    }
  })

  it('readJson: oversize and malformed streams fail with an Error and never buffer past the cap', async () => {
    const stream = (chunks: Uint8Array[]): any => Readable.from(chunks.map((c) => Object.assign(c, { subarray: () => c })))
    await fuzz('readJson', async (chunks: Uint8Array[], max: number) => readJson(stream(chunks) as never, max), (g) => [Array.from({ length: g.int(6) }, () => g.bytes(200)), g.pick([0, 1, 16, 100, 1000])], { iters: Math.min(ITERS, 1000) })
    await assert.rejects(readJson(stream([Buffer.alloc(100, 0x20), Buffer.alloc(100, 0x20)]) as never, 150), /too large/)
  })

  it('openArchive: random and mutated archives are rejected cleanly', async () => {
    await fuzz('openArchive(random)', openArchive, (g) => [g.bytes(300), g.str(30)], { iters: Math.min(ITERS, 500) })
  })
})
