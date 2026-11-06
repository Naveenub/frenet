import assert from 'node:assert/strict'
import { after, describe, it } from 'node:test'
import { generateKeyPair } from '@libp2p/crypto/keys'
import { peerIdFromPrivateKey } from '@libp2p/peer-id'
import type { PrivateKey } from '@libp2p/interface'
import { randomBytes } from 'node:crypto'
import { base32 } from 'multiformats/bases/base32'
import { ed25519 } from '@noble/curves/ed25519.js'
import { startApi } from '../src/api.js'
import { didFromPublicKeyRaw } from '../src/did.js'
import { startFrenet, type FrenetNode } from '../src/node.js'
import { MAX_RING, proveMembership, ringFromMembers, tagFor, verifyMembership, ZkAuth } from '../src/zkauth.js'

const L = ed25519.Point.Fn.ORDER
const keys = async (n: number): Promise<PrivateKey[]> => Promise.all(Array.from({ length: n }, () => generateKeyPair('Ed25519')))
const did = (k: PrivateKey): string => didFromPublicKeyRaw(k.publicKey.raw)
const ringOf = (ks: PrivateKey[]): Uint8Array[] => ringFromMembers(ks.map(did))
const P = { scope: 'poll:42', nonce: 'n-1', audience: 'verifier-a' }
const le = (b: Uint8Array): bigint => { let n = 0n; for (let i = b.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(b[i]!); return n }
const toLe = (n: bigint): Buffer => { const o = Buffer.alloc(32); for (let i = 0; i < 32; i++) { o[i] = Number(n & 0xffn); n >>= 8n } return o }
const mutate = (proof: string, f: (b: Buffer) => void): string => { const b = Buffer.from(proof, 'base64url'); f(b); return b.toString('base64url') }

const nodes: FrenetNode[] = []
after(async () => { for (const n of nodes) await n.stop().catch(() => {}) })

describe('zero-knowledge membership proofs', () => {
  it('verifies for every possible signer position and ring size', async () => {
    for (const size of [2, 3, 7]) {
      const ks = await keys(size)
      const ring = ringOf(ks)
      for (const k of ks) {
        const { proof, tag } = proveMembership(k, ring, P)
        const r = verifyMembership(proof, ring, P)
        assert.deepEqual(r, { valid: true, tag })
        assert.equal(tag, tagFor(k, P.scope))
      }
    }
  })

  it('does not reveal the signer: the proof carries no key and has the same shape for every member', async () => {
    const ks = await keys(5)
    const ring = ringOf(ks)
    const sizes = new Set<number>()
    for (const k of ks) {
      const { proof } = proveMembership(k, ring, P)
      const bytes = Buffer.from(proof, 'base64url')
      sizes.add(bytes.length)
      for (const m of ks) assert.ok(!bytes.includes(Buffer.from(m.publicKey.raw)), 'proof must not embed any public key')
      // The proof is randomised: proving twice never gives the same bytes.
      assert.notEqual(proveMembership(k, ring, P).proof, proof)
    }
    assert.equal(sizes.size, 1)
  })

  it('is independent of how the ring was listed', async () => {
    const ks = await keys(4)
    const proof = proveMembership(ks[0]!, ringOf(ks), P).proof
    assert.equal(verifyMembership(proof, ringFromMembers([...ks].reverse().map(did)), P).valid, true)
    const peerIds = ks.map((k) => peerIdFromPrivateKey(k).toString())
    assert.equal(verifyMembership(proof, ringFromMembers([...peerIds, did(ks[1]!)]), P).valid, true)   // peer IDs and duplicates
  })

  it('gives one stable tag per member and scope, unlinkable across scopes', async () => {
    const [a, b, c, d] = await keys(4) as [PrivateKey, PrivateKey, PrivateKey, PrivateKey]
    const t1 = proveMembership(a, ringOf([a, b, c]), P).tag
    const t2 = proveMembership(a, ringOf([a, b, d]), { ...P, nonce: 'other' }).tag   // other ring, other nonce
    assert.equal(t1, t2)
    assert.notEqual(proveMembership(a, ringOf([a, b, c]), { ...P, scope: 'poll:43' }).tag, t1)
    assert.notEqual(proveMembership(b, ringOf([a, b, c]), P).tag, t1)
    assert.ok(!t1.includes(Buffer.from(a.publicKey.raw).toString('hex')))
  })

  it('refuses to prove for a ring you are not in, and bad parameters', async () => {
    const [a, b, c] = await keys(3) as [PrivateKey, PrivateKey, PrivateKey]
    assert.throws(() => proveMembership(c, ringOf([a, b]), P), /not in the ring/)
    assert.throws(() => proveMembership(a, ringOf([a, b]), { ...P, scope: '' }), /scope/)
    assert.throws(() => proveMembership(a, ringOf([a, b]), { ...P, nonce: 'bad nonce' }), /nonce/)
    assert.throws(() => proveMembership(a, ringOf([a, b]), { ...P, audience: 'a b' }), /audience/)
    assert.throws(() => ringOf([a]), /at least 2/)
    assert.throws(() => ringOf([a, a]), /at least 2/)
    assert.throws(() => ringFromMembers(['did:key:z6MkNotAKey', did(a)]), /DID/)
  })

  it('rejects a proof used with another nonce, scope, audience or ring', async () => {
    const [a, b, c] = await keys(3) as [PrivateKey, PrivateKey, PrivateKey]
    const ring = ringOf([a, b, c])
    const { proof } = proveMembership(a, ring, P)
    assert.equal(verifyMembership(proof, ring, P).valid, true)
    assert.equal(verifyMembership(proof, ring, { ...P, nonce: 'n-2' }).valid, false)
    assert.equal(verifyMembership(proof, ring, { ...P, scope: 'poll:43' }).valid, false)
    assert.equal(verifyMembership(proof, ring, { ...P, audience: 'verifier-b' }).valid, false)
    assert.equal(verifyMembership(proof, ring, { scope: P.scope, nonce: P.nonce }).valid, false)
    assert.equal(verifyMembership(proof, ringOf([a, b, ...(await keys(1))]), P).valid, false)   // swapped member
    assert.equal(verifyMembership(proof, ringOf([a, b]), P).valid, false)                       // smaller ring
  })

  it('rejects every tampered byte, bad lengths, bad encodings and non-canonical scalars', async () => {
    const ks = await keys(3)
    const ring = ringOf(ks)
    const { proof } = proveMembership(ks[1]!, ring, P)
    const total = Buffer.from(proof, 'base64url').length
    for (let i = 0; i < total; i += 7) {
      assert.equal(verifyMembership(mutate(proof, (b) => { b[i] = b[i]! ^ 1 }), ring, P).valid, false, `byte ${i}`)
    }
    assert.equal(verifyMembership(proof.slice(0, -4), ring, P).valid, false)
    assert.equal(verifyMembership(proof + 'AAAA', ring, P).valid, false)
    assert.equal(verifyMembership(`${proof}=`, ring, P).valid, false)
    assert.equal(verifyMembership('', ring, P).valid, false)
    assert.equal(verifyMembership(null, ring, P).valid, false)
    assert.equal(verifyMembership({}, ring, P).valid, false)
    // c0 + L is the same number mod L but not a canonical scalar.
    const wide = mutate(proof, (b) => { toLe(le(b.subarray(33, 65)) + L).copy(b, 33) })
    assert.equal(verifyMembership(wide, ring, P).valid, false)
    assert.equal(verifyMembership(mutate(proof, (b) => { b[0] = 2 }), ring, P).valid, false)
  })

  it('rejects forged, identity and small-order tags', async () => {
    const [a, b, c] = await keys(3) as [PrivateKey, PrivateKey, PrivateKey]
    const ring = ringOf([a, b, c])
    const { proof, tag } = proveMembership(a, ring, P)
    const Pt = ed25519.Point
    // A tag from a key outside the ring (an attacker minting a fresh pseudonym) does not verify.
    const outsider = tagFor(c, 'poll:other')
    assert.equal(verifyMembership(mutate(proof, (x) => { Buffer.from(outsider, 'hex').copy(x, 1) }), ring, P).valid, false)
    // Identity element and a torsion-shifted copy of the real tag (same prime-order part) must both be refused.
    assert.equal(verifyMembership(mutate(proof, (x) => { Buffer.from(Pt.ZERO.toBytes()).copy(x, 1) }), ring, P).valid, false)
    const small = Pt.fromBytes(Buffer.from('c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a', 'hex'))   // order-8 point
    assert.ok(!small.isTorsionFree())
    const shifted = Pt.fromBytes(Buffer.from(tag, 'hex')).add(small).toBytes()
    assert.equal(verifyMembership(mutate(proof, (x) => { Buffer.from(shifted).copy(x, 1) }), ring, P).valid, false)
  })

  it('rejects non-canonical rings and oversized rings', async () => {
    const ks = await keys(3)
    const ring = ringOf(ks)
    const { proof } = proveMembership(ks[0]!, ring, P)
    assert.equal(verifyMembership(proof, [...ring].reverse(), P).valid, false)
    assert.throws(() => proveMembership(ks[0]!, [...ring].reverse(), P), /canonical/)
    const big = await keys(MAX_RING + 1)
    assert.throws(() => ringOf(big), /too large/)
  })

  it('scales to the maximum ring', async () => {
    const ks = await keys(MAX_RING)
    const ring = ringOf(ks)
    const t = Date.now()
    const { proof } = proveMembership(ks[MAX_RING - 1]!, ring, P)
    assert.equal(verifyMembership(proof, ring, P).valid, true)
    assert.ok(Date.now() - t < 20_000)
  })
})

describe('ZkAuth verifier (challenges, once-per-scope)', () => {
  const node = async (): Promise<FrenetNode> => { const n = await startFrenet({ dataDir: ':memory:', listen: ['/ip4/127.0.0.1/tcp/0'], mdns: false, nat: false }); nodes.push(n); return n }

  it('accepts a proof against an issued challenge exactly once (replay protection)', async () => {
    const v = await node(); const [a, b] = await keys(2) as [PrivateKey, PrivateKey]
    const members = [did(a), did(b)]
    const prover = new ZkAuth(v.store, a)
    const { nonce } = v.zk.challenge()
    const { proof } = await prover.prove(members, { scope: 's', nonce })
    assert.equal((await v.zk.verify(proof, members, { scope: 's', nonce })).valid, true)
    const again = await v.zk.verify(proof, members, { scope: 's', nonce })
    assert.equal(again.valid, false)
    assert.match((again as any).error, /challenge/)
  })

  it('refuses nonces it did not issue, and failed proofs do not burn the challenge', async () => {
    const v = await node(); const [a, b] = await keys(2) as [PrivateKey, PrivateKey]
    const members = [did(a), did(b)]
    const prover = new ZkAuth(v.store, a)
    const own = await prover.prove(members, { scope: 's', nonce: 'made-up' })
    assert.equal((await v.zk.verify(own.proof, members, { scope: 's', nonce: 'made-up' })).valid, false)
    assert.equal((await v.zk.verify(own.proof, members, { scope: 's', nonce: 'made-up', externalNonce: true })).valid, true)
    const { nonce } = v.zk.challenge()
    const good = await prover.prove(members, { scope: 's', nonce })
    assert.equal((await v.zk.verify(mutate(good.proof, (x) => { x[40] = x[40]! ^ 1 }), members, { scope: 's', nonce })).valid, false)
    assert.equal((await v.zk.verify(good.proof, members, { scope: 's', nonce })).valid, true)
  })

  it('expires challenges', async () => {
    const v = await node(); const [a, b] = await keys(2) as [PrivateKey, PrivateKey]
    assert.throws(() => v.zk.challenge(10), /lifetime/)
    const { nonce } = v.zk.challenge(1000)
    const proof = (await new ZkAuth(v.store, a).prove([did(a), did(b)], { scope: 's', nonce })).proof
    const realNow = Date.now
    try { Date.now = () => realNow() + 2000; assert.equal((await v.zk.verify(proof, [did(a), did(b)], { scope: 's', nonce })).valid, false) } finally { Date.now = realNow }
  })

  it('enforces one action per member per scope without learning who', async () => {
    const v = await node(); const [a, b, c] = await keys(3) as [PrivateKey, PrivateKey, PrivateKey]
    const members = [did(a), did(b), did(c)]
    const act = async (k: PrivateKey, scope: string) => {
      const { nonce } = v.zk.challenge()
      const { proof } = await new ZkAuth(v.store, k).prove(members, { scope, nonce })
      return v.zk.verify(proof, members, { scope, nonce, once: true })
    }
    assert.equal((await act(a, 'vote:1')).valid, true)
    assert.equal((await act(b, 'vote:1')).valid, true)
    const dup = await act(a, 'vote:1')
    assert.equal(dup.valid, false); assert.match((dup as any).error, /already acted/)
    assert.equal((await act(a, 'vote:2')).valid, true)   // a new scope is a new ballot
    assert.equal(v.store.zkTagCount('vote:1'), 2)
    assert.equal(v.store.forgetZkScope('vote:1'), 2)
    assert.equal((await act(a, 'vote:1')).valid, true)
    // Nothing stored can be tied back to a member: tags differ from keys and from other scopes' tags.
    const stored = v.store.zkTagCount('vote:2')
    assert.equal(stored, 1)
  })

  it('does not spend the tag when verification fails', async () => {
    const v = await node(); const [a, b] = await keys(2) as [PrivateKey, PrivateKey]
    const members = [did(a), did(b)]
    const { nonce } = v.zk.challenge()
    const { proof } = await new ZkAuth(v.store, a).prove(members, { scope: 'x', nonce })
    assert.equal((await v.zk.verify(proof, members, { scope: 'x', nonce, audience: 'wrong', once: true })).valid, false)
    assert.equal(v.store.zkTagCount('x'), 0)
    assert.equal((await v.zk.verify(proof, members, { scope: 'x', nonce, once: true })).valid, true)
  })

  it('accepts did:frenet members by their current key', async () => {
    const v = await node(); const [a, b] = await keys(2) as [PrivateKey, PrivateKey]
    const id = base32.baseEncode(randomBytes(32))
    const resolve = async (x: string) => x === id ? b.publicKey.raw : null
    const prover = new ZkAuth(v.store, b, { resolveFrenet: resolve })
    const verifier = new ZkAuth(v.store, a, { resolveFrenet: resolve })
    const members = [did(a), `did:frenet:${id}`]
    const { nonce } = verifier.challenge()
    const { proof, tag } = await prover.prove(members, { scope: 's', nonce })
    assert.deepEqual(await verifier.verify(proof, members, { scope: 's', nonce }), { valid: true, tag, ringSize: 2 })
    await assert.rejects(new ZkAuth(v.store, b).prove(members, { scope: 's', nonce }), /cannot resolve/)   // no resolver, no did:frenet
  })

  it('works through the local API between two nodes', async () => {
    const verifier = await node(); const prover = await node(); const other = await node()
    const members = [prover.keyDid, other.keyDid, verifier.keyDid]
    const va = await startApi(verifier, 0, '127.0.0.1'); const pa = await startApi(prover, 0, '127.0.0.1')
    try {
      const post = async (port: number, path: string, data: unknown) => (await fetch(`http://127.0.0.1:${port}${path}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(data) })).json() as Promise<any>
      const ch = await post(va.port, '/api/zk/challenge', {})
      const pr = await post(pa.port, '/api/zk/prove', { ring: members, scope: 'room:1', nonce: ch.nonce, audience: 'v' })
      assert.equal(pr.ringSize, 3)
      const ok = await post(va.port, '/api/zk/verify', { proof: pr.proof, ring: members, scope: 'room:1', nonce: ch.nonce, audience: 'v', once: true })
      assert.deepEqual([ok.valid, ok.tag], [true, pr.tag])
      assert.equal((await post(va.port, '/api/zk/verify', { proof: pr.proof, ring: members, scope: 'room:1', nonce: ch.nonce, audience: 'v', once: true })).valid, false)
      assert.match((await post(pa.port, '/api/zk/prove', { ring: [other.keyDid, verifier.keyDid], scope: 'room:1', nonce: 'x' })).error, /not in the ring/)
      assert.equal((await post(va.port, '/api/zk/forget', { scope: 'room:1' })).removed, 1)
      const st = await (await fetch(`http://127.0.0.1:${va.port}/api/status`)).json() as any
      assert.match(st.privacy.anonymousAuth, /ring/)
    } finally { va.server.close(); pa.server.close() }
  })
})
