import assert from 'node:assert/strict'
import { after, describe, it } from 'node:test'
import { generateKeyPair } from '@libp2p/crypto/keys'
import { startFrenet, type FrenetNode } from '../src/node.js'
import { Reputation } from '../src/reputation.js'
import { Store } from '../src/store.js'
import { identityWorkBits, meetsIdentityWork, mineIdentity, subnetKey, SybilGuard } from '../src/sybil.js'
import { compareSemver, generateReleaseKey, sha256Hex, signManifest, Updates, validateRoots, verifyArtifact, verifyEnvelope, type UpdateManifest } from '../src/updates.js'

const TCP = ['/ip4/127.0.0.1/tcp/0']
const nodes: FrenetNode[] = []
const track = async (o: Partial<Parameters<typeof startFrenet>[0]> = {}) => { const n = await startFrenet({ dataDir: ':memory:', listen: TCP, mdns: false, nat: false, ...o }); nodes.push(n); return n }
after(async () => { for (const n of nodes) await n.stop().catch(() => {}) })
const waitFor = async (fn: () => boolean, ms = 8000) => {
  const t = Date.now()
  while (!fn()) { if (Date.now() - t > ms) throw new Error('timeout'); await new Promise((r) => setTimeout(r, 25)) }
}
const id = (n: FrenetNode) => n.libp2p.peerId.toString()
/** A refused inbound connection is closed by the remote after the handshake, so the dial may resolve and then drop. */
const connectsAndStays = async (from: FrenetNode, to: FrenetNode): Promise<boolean> => {
  try { await from.libp2p.dial(to.libp2p.getMultiaddrs()[0]!) } catch { return false }
  await new Promise((r) => setTimeout(r, 400))
  return from.libp2p.getConnections(to.libp2p.peerId).length > 0 && to.libp2p.getConnections(from.libp2p.peerId).length > 0
}
const weakKey = async (bits: number) => { for (;;) { const k = await generateKeyPair('Ed25519'); if (identityWorkBits(k.publicKey.raw) < bits) return k } }

describe('QUIC transport', () => {
  it('connects over QUIC and carries signed messages', async () => {
    const a = await track({ listen: ['/ip4/127.0.0.1/udp/0/quic-v1'] })
    const b = await track({ listen: ['/ip4/127.0.0.1/udp/0/quic-v1'] })
    const addr = a.libp2p.getMultiaddrs().find((m) => m.toString().includes('/quic-v1'))
    assert.ok(addr, 'node listens on a quic-v1 address')
    const conn = await b.libp2p.dial(addr)
    assert.ok(conn.remoteAddr.toString().includes('/quic-v1'))
    const got: string[] = []
    a.messaging.on('message', (m) => got.push(m.body))
    await b.messaging.send(a.libp2p.peerId, 'over quic')
    await waitFor(() => got.length === 1)
    assert.equal(got[0], 'over quic')
  })

  it('listens on TCP and QUIC by default and can be switched off', async () => {
    const on = await startFrenet({ dataDir: ':memory:', mdns: false, nat: false }); nodes.push(on)
    const s = on.libp2p.getMultiaddrs().map(String)
    assert.ok(s.some((x) => x.includes('/tcp/')) && s.some((x) => x.includes('/quic-v1')))
    const off = await startFrenet({ dataDir: ':memory:', mdns: false, nat: false, quic: false }); nodes.push(off)
    assert.ok(!off.libp2p.getMultiaddrs().some((m) => m.toString().includes('/quic-v1')))
  })

  it('enforces the ban list on QUIC connections too', async () => {
    const a = await track({ listen: ['/ip4/127.0.0.1/udp/0/quic-v1'] })
    const b = await track({ listen: ['/ip4/127.0.0.1/udp/0/quic-v1'] })
    await a.operator.ban(id(b), 'test')
    assert.equal(await connectsAndStays(b, a), false)
    assert.equal(a.libp2p.getConnections(b.libp2p.peerId).length, 0)
  })
})

describe('Sybil resistance: identity proof-of-work', () => {
  it('counts leading zero bits and mines a key of the requested weight', async () => {
    const m = await mineIdentity(8)
    assert.ok(m.bits >= 8)
    assert.ok(meetsIdentityWork(m.key.publicKey.raw, 8))
    assert.ok(identityWorkBits(m.key.publicKey.raw) === m.bits)
    assert.ok(!meetsIdentityWork(undefined, 8), 'a key that cannot be inspected does not pass')
    assert.ok(meetsIdentityWork(undefined, 0), 'rule is off at 0')
    await assert.rejects(mineIdentity(99))
    await assert.rejects(mineIdentity(40, { maxTries: 3 }))
  })

  it('a node with minIdentityBits refuses cheap identities and accepts worked ones', async () => {
    const strict = await track({ minIdentityBits: 8 })
    const cheap = await track({ privateKey: await weakKey(8) })
    const worked = await track({ privateKey: (await mineIdentity(8)).key })
    assert.equal(await connectsAndStays(cheap, strict), false)
    assert.equal(strict.libp2p.getConnections(cheap.libp2p.peerId).length, 0)
    assert.equal(await connectsAndStays(worked, strict), true)
    // outbound is gated as well: the strict node will not dial the cheap one
    await assert.rejects(strict.libp2p.dial(cheap.libp2p.getMultiaddrs()[0]!))
  })
})

describe('Sybil resistance: network diversity', () => {
  it('classifies subnets and exempts loopback, LAN, and relayed addresses', () => {
    assert.equal(subnetKey('/ip4/203.0.113.7/tcp/1'), 'v4:203.0.113')
    assert.equal(subnetKey('/ip4/203.0.113.200/udp/9/quic-v1'), 'v4:203.0.113')
    for (const a of ['/ip4/127.0.0.1/tcp/1', '/ip4/10.1.2.3/tcp/1', '/ip4/192.168.1.5/tcp/1', '/ip4/172.20.0.1/tcp/1', '/ip4/169.254.1.1/tcp/1', '/ip6/::1/tcp/1', '/ip6/fe80::1/tcp/1', '/ip6/fd00::1/tcp/1', '/ip4/1.2.3.4/tcp/1/p2p/QmRelay/p2p-circuit', '/dns4/example.org/tcp/1']) assert.equal(subnetKey(a), null, a)
    assert.equal(subnetKey('/ip6/2001:db8:1:2::5/tcp/1'), 'v6:2001:db8:1')
    assert.equal(subnetKey('/ip6/2001:db8:1:ffff::9/tcp/1'), subnetKey('/ip6/2001:db8:1::1/tcp/1'))
    assert.equal(subnetKey('/ip4/10.1.2.3/tcp/1', { includePrivate: true }), 'v4:10.1.2')
  })

  it('limits distinct peers per subnet but not repeat connections of one peer', () => {
    const g = new SybilGuard({ maxPerSubnet: 2, clusterSize: 3, windowMs: 1000 })
    const conns = [{ peer: 'A', addr: '/ip4/203.0.113.1/tcp/1' }, { peer: 'B', addr: '/ip4/203.0.113.2/tcp/1' }]
    assert.equal(g.admit('C', '/ip4/203.0.113.3/tcp/1', conns), false)
    assert.equal(g.admit('A', '/ip4/203.0.113.1/tcp/2', conns), true)
    assert.equal(g.admit('C', '/ip4/198.51.100.3/tcp/1', conns), true, 'other subnet')
    assert.equal(g.admit('C', '/ip4/127.0.0.1/tcp/1', conns), true, 'loopback is exempt')
  })

  it('flags a cluster once, then again after the window slides', () => {
    const g = new SybilGuard({ maxPerSubnet: 8, clusterSize: 3, windowMs: 1000 })
    const a = (n: number): string => `/ip4/203.0.113.${n}/tcp/1`
    assert.deepEqual(g.observe('A', a(1), 0), [])
    assert.deepEqual(g.observe('B', a(2), 10), [])
    assert.deepEqual(g.observe('C', a(3), 20).sort(), ['A', 'B', 'C'])
    assert.deepEqual(g.observe('C', a(3), 30), [], 'already flagged')
    assert.deepEqual(g.observe('D', a(4), 40), ['D'], 'a fourth identity is flagged on its own')
    assert.equal(g.clusters(40).length, 1)
    assert.equal(g.clusters(5000).length, 0)
  })
})

describe('Reputation and malicious-node detection', () => {
  const mk = (o = {}) => { let t = 1_000_000; const store = new Store(':memory:'); const r = new Reputation(store, o, () => t); return { r, store, tick: (ms: number) => { t += ms } } }

  it('good behaviour raises the score up to a cap, bad behaviour lowers it', () => {
    const { r } = mk()
    for (let i = 0; i < 500; i++) r.record('p', 'valid-block')
    assert.equal(r.score('p'), 50)
    r.record('p', 'malformed')
    assert.equal(r.score('p'), 42)
    assert.equal(r.isBlocked('p'), false)
  })

  it('blocks at the threshold, escalates on repeats, and puts the peer on probation afterwards', () => {
    const { r, tick } = mk()
    assert.equal(r.record('x', 'bad-block'), false)
    assert.equal(r.record('x', 'bad-block'), true)
    assert.equal(r.isBlocked('x'), true)
    assert.equal(r.record('x', 'bad-block'), false, 'already blocked: no double strike')
    tick(3_600_000 + 1)
    assert.equal(r.isBlocked('x'), false, 'first block lasts one hour')
    assert.ok(r.score('x') < 0, 'probation: not forgiven')
    assert.equal(r.record('x', 'bad-signature'), true)
    tick(3_600_000 + 1)
    assert.equal(r.isBlocked('x'), true, 'second block lasts two hours')
    tick(3_600_000)
    assert.equal(r.isBlocked('x'), false)
    assert.equal(r.list().find((p) => p.peer === 'x')!.strikes, 2)
  })

  it('scores decay with the half-life so old mistakes are forgotten', () => {
    const { r, tick } = mk()
    r.record('d', 'bad-signature')
    assert.equal(r.score('d'), -25)
    tick(24 * 3_600_000)
    assert.equal(r.score('d'), -12.5)
  })

  it('never auto-blocks trusted peers, and a disabled threshold only scores', () => {
    const { r } = mk()
    r.trusted.add('relay')
    for (let i = 0; i < 10; i++) assert.equal(r.record('relay', 'bad-block'), false)
    assert.equal(r.isBlocked('relay'), false)
    assert.ok(r.score('relay') < -50)
    const off = mk({ banThreshold: -Infinity }).r
    for (let i = 0; i < 10; i++) off.record('q', 'bad-block')
    assert.equal(off.isBlocked('q'), false)
  })

  it('maps protocol drop reasons and ignores benign or unknown ones', () => {
    const { r } = mk()
    r.noteDrop('m', 'malformed'); r.noteDrop('m', 'error: boom'); r.noteDrop('m', 'not-a-member'); r.noteDrop('m', 'duplicate'); r.noteDrop('m', 'whatever')
    assert.equal(r.score('m'), -10)
  })

  it('persists across restarts including blocks, and the operator can reset a peer', () => {
    const store = new Store(':memory:')
    let t = 5_000_000
    const a = new Reputation(store, {}, () => t)
    a.record('z', 'bad-block'); a.record('z', 'bad-block')
    const b = new Reputation(store, {}, () => t)
    assert.equal(b.isBlocked('z'), true)
    assert.equal(b.reset('z'), true)
    assert.equal(new Reputation(store, {}, () => t).isBlocked('z'), false)
  })

  it('bounds memory: a flood of identities cannot grow the table without limit, and blocked peers are kept', () => {
    const { r, store } = mk({ maxPeers: 20 })
    r.record('bad', 'bad-block'); r.record('bad', 'bad-block')
    for (let i = 0; i < 200; i++) r.record(`n${i}`, 'malformed')
    assert.ok(r.list(1000).length <= 20)
    assert.equal(store.listReputation().length, r.list(1000).length)
    assert.equal(r.isBlocked('bad'), true)
    for (let i = 0; i < 50; i++) r.record(`g${i}`, 'valid-message')   // good news is not recorded when full
    assert.ok(r.list(1000).length <= 20)
  })

  it('records the reason without control characters and bounds its length', () => {
    const { r } = mk()
    r.record('c', 'malformed', 'a\nb\u0000' + 'x'.repeat(500))
    const reason = r.list()[0]!.lastReason
    assert.ok(!/[\u0000-\u001f]/.test(reason) && reason.length <= 120)
  })

  it('a node blocks and disconnects a peer that keeps sending malformed frames', async () => {
    const a = await track(); const b = await track()
    await b.libp2p.dial(a.libp2p.getMultiaddrs()[0]!)
    for (let i = 0; i < 8 && !a.reputation.isBlocked(id(b)); i++) {
      const s = await b.libp2p.dialProtocol(a.libp2p.peerId, '/frenet/msg/1.0.0')
      s.send(Buffer.from('{not json'))
      await s.close().catch(() => {})
      await new Promise((r) => setTimeout(r, 40))
    }
    await waitFor(() => a.reputation.isBlocked(id(b)))
    await waitFor(() => a.libp2p.getConnections(b.libp2p.peerId).length === 0)
    await assert.rejects(a.libp2p.dial(b.libp2p.peerId), 'we no longer dial it')
    assert.equal(await connectsAndStays(b, a), false, 'and it cannot come back')
    assert.ok(a.operator.snapshot() && (a.operator.snapshot() as any).reputation.blocked >= 1)
    a.reputation.reset(id(b))
    assert.equal(await connectsAndStays(b, a), true, 'an operator reset lets it back in')
  })

  it('valid signed messages earn reputation', async () => {
    const a = await track(); const b = await track()
    await b.libp2p.dial(a.libp2p.getMultiaddrs()[0]!)
    await b.messaging.send(a.libp2p.peerId, 'hello')
    await waitFor(() => a.reputation.score(id(b)) > 0)
  })
})

describe('Secure software updates', () => {
  const DAY = 86_400_000
  const now = 1_800_000_000_000
  const manifest = (o: Partial<UpdateManifest> = {}): UpdateManifest => ({
    v: 1, product: 'frenet', channel: 'stable', version: '0.2.0', seq: 5, created: now - DAY, expires: now + 29 * DAY,
    artifacts: [{ name: 'frenet-0.2.0.tgz', size: 3, sha256: sha256Hex(Buffer.from('abc')) }], ...o
  })
  const setup = async (threshold = 2, n = 3) => {
    const keys = await Promise.all(Array.from({ length: n }, () => generateReleaseKey()))
    return { keys, roots: { threshold, keys: keys.map((k) => k.did) } }
  }
  const base = (roots: any, o: object = {}) => ({ roots, currentVersion: '0.1.0', now, ...o })

  it('accepts a manifest signed by a threshold of trusted keys', async () => {
    const { keys, roots } = await setup()
    let env = await signManifest(manifest(), keys[0]!.key)
    const one = await verifyEnvelope(env, base(roots))
    assert.equal(one.ok, false)
    env = await signManifest(env, keys[2]!.key)
    const r = await verifyEnvelope(env, base(roots))
    assert.ok(r.ok && r.manifest.version === '0.2.0' && r.signers.length === 2)
  })

  it('does not count the same key twice, unknown keys, or garbage signatures', async () => {
    const { keys, roots } = await setup()
    const rogue = await generateReleaseKey()
    let env = await signManifest(manifest(), keys[0]!.key)
    env = await signManifest(env, rogue.key)
    env.signatures.push({ ...env.signatures[0]! })   // duplicate
    env.signatures.push({ keyid: keys[1]!.did, sig: Buffer.alloc(64).toString('base64url') })   // trusted key, bad signature
    const r = await verifyEnvelope(env, base(roots))
    assert.equal(r.ok, false)
  })

  it('rejects a tampered payload and a signature copied onto another payload', async () => {
    const { keys, roots } = await setup(1, 1)
    const env = await signManifest(manifest(), keys[0]!.key)
    const evil = await signManifest(manifest({ version: '9.9.9' }), (await generateReleaseKey()).key)
    assert.equal((await verifyEnvelope({ payload: evil.payload, signatures: env.signatures }, base(roots))).ok, false)
    const flipped = env.payload.slice(0, -2) + (env.payload.endsWith('A') ? 'B' : 'A') + env.payload.slice(-1)
    assert.equal((await verifyEnvelope({ ...env, payload: flipped }, base(roots))).ok, false)
    assert.equal((await verifyEnvelope({ ...env, payload: env.payload + '=' }, base(roots))).ok, false, 'non-canonical base64url')
  })

  it('fails closed with no or bad trust roots', async () => {
    const { keys } = await setup(1, 1)
    const env = await signManifest(manifest(), keys[0]!.key)
    assert.equal((await verifyEnvelope(env, base({ threshold: 1, keys: [] }))).ok, false)
    assert.equal((await verifyEnvelope(env, base({ threshold: 0, keys: [keys[0]!.did] }))).ok, false)
    assert.equal((await verifyEnvelope(env, base({ threshold: 2, keys: [keys[0]!.did] }))).ok, false)
    assert.throws(() => validateRoots({ threshold: 1, keys: [keys[0]!.did, keys[0]!.did] }))
    assert.throws(() => validateRoots({ threshold: 1, keys: ['did:web:example.org'] }))
    const upd = new Updates(new Store(':memory:'), null, '0.1.0')
    assert.equal(upd.configured, false)
    assert.equal((await upd.check(env, 'stable', now)).ok, false)
  })

  it('rejects expired, future-dated, over-long, wrong-product and wrong-channel manifests', async () => {
    const { keys, roots } = await setup(1, 1)
    const sign = (m: Partial<UpdateManifest>) => signManifest({ ...manifest(), ...m } as UpdateManifest, keys[0]!.key)
    assert.equal((await verifyEnvelope(await sign({ expires: now - 1 }), base(roots))).ok, false, 'expired')
    assert.equal((await verifyEnvelope(await sign({ created: now + DAY, expires: now + 2 * DAY }), base(roots))).ok, false, 'future')
    assert.equal((await verifyEnvelope(await sign({ created: now - DAY, expires: now + 200 * DAY }), base(roots))).ok, false, 'freeze window too long')
    assert.equal((await verifyEnvelope(await sign({ product: 'other' as any }), base(roots))).ok, false)
    assert.equal((await verifyEnvelope(await sign({ channel: 'beta' }), base(roots, { channel: 'stable' }))).ok, false)
    assert.equal((await verifyEnvelope(await sign({ version: '1.0' }), base(roots))).ok, false)
    assert.equal((await verifyEnvelope(await sign({ artifacts: [] }), base(roots))).ok, false)
    assert.equal((await verifyEnvelope(await sign({ artifacts: [{ name: '../x', size: 1, sha256: 'a'.repeat(64) }] }), base(roots))).ok, false, 'path traversal in name')
    assert.equal((await verifyEnvelope(await sign({ artifacts: [{ name: 'a', size: 1, sha256: 'A'.repeat(64) }] }), base(roots))).ok, false)
  })

  it('blocks rollback to an older validly signed release and downgrade below the running version', async () => {
    const { keys, roots } = await setup(1, 1)
    const old = await signManifest(manifest({ seq: 3, version: '0.1.5' }), keys[0]!.key)
    assert.equal((await verifyEnvelope(old, base(roots, { lastSeq: 5, lastVersion: '0.2.0' }))).ok, false, 'seq rollback')
    assert.equal((await verifyEnvelope(old, base(roots, { currentVersion: '0.2.0' }))).ok, false, 'version downgrade')
    assert.ok((await verifyEnvelope(old, base(roots))).ok, 'but fine when it really is newer than what runs')
    const dup = await signManifest(manifest({ seq: 5, version: '0.3.0' }), keys[0]!.key)
    assert.equal((await verifyEnvelope(dup, base(roots, { lastSeq: 5, lastVersion: '0.2.0' }))).ok, false, 'same seq, different version')
  })

  it('remembers the accepted sequence in the store', async () => {
    const { keys, roots } = await setup(1, 1)
    const store = new Store(':memory:')
    const upd = new Updates(store, roots, '0.1.0')
    const v5 = await signManifest(manifest({ seq: 5 }), keys[0]!.key)
    const v4 = await signManifest(manifest({ seq: 4, version: '0.1.9' }), keys[0]!.key)
    const r = await upd.check(v5, 'stable', now)
    assert.ok(r.ok)
    if (r.ok) upd.accept(r.manifest)
    assert.equal((await upd.check(v4, 'stable', now)).ok, false)
    assert.ok((await upd.check(v5, 'stable', now)).ok, 're-verifying the same release is fine')
    assert.equal(store.getUpdateState('stable')!.seq, 5)
  })

  it('verifies artifact bytes against the signed size and hash', () => {
    const m = manifest()
    assert.deepEqual(verifyArtifact(m, 'frenet-0.2.0.tgz', Buffer.from('abc')), { ok: true })
    assert.equal(verifyArtifact(m, 'frenet-0.2.0.tgz', Buffer.from('abd')).ok, false)
    assert.equal(verifyArtifact(m, 'frenet-0.2.0.tgz', Buffer.from('abcd')).ok, false)
    assert.equal(verifyArtifact(m, 'other.tgz', Buffer.from('abc')).ok, false)
  })

  it('compares semantic versions numerically', () => {
    assert.equal(compareSemver('0.10.0', '0.9.0'), 1)
    assert.equal(compareSemver('1.0.0', '1.0.0'), 0)
    assert.equal(compareSemver('1.2.3', '1.10.0'), -1)
    assert.throws(() => compareSemver('1.0', '1.0.0'))
  })
})
