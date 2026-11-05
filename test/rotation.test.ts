import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { after, describe, it } from 'node:test'
import { generateKeyPair, privateKeyToProtobuf } from '@libp2p/crypto/keys'
import type { PrivateKey } from '@libp2p/interface'
import { peerIdFromPrivateKey } from '@libp2p/peer-id'
import { Credentials, verifyCredential, verifyRevocation } from '../src/credentials.js'
import { didDocumentFor, createInception, createRotation, eventDigest, keyForSignature, keyDigest, verifyLog, type IdentityEvent, type IdentityState } from '../src/identity-log.js'
import { startFrenet, type FrenetNode } from '../src/node.js'
import { readIdentityLog, writeIdentityLog } from '../src/recovery.js'
import { initRotation, rotateIdentity } from '../src/rotation.js'
import { REVOKE_PROTOCOL } from '../src/revocations.js'
import { ask } from '../src/rpc.js'
import { Store } from '../src/store.js'
import { Revocations } from '../src/revocations.js'
import { base32 } from 'multiformats/bases/base32'
import { loadOrCreateIdentity } from '../src/identity.js'

const L = ['/ip4/127.0.0.1/tcp/0']
const dirs: string[] = []
const tmp = (): string => { const d = mkdtempSync(join(tmpdir(), 'frenet-rot-')); dirs.push(d); return d }
const nodes: FrenetNode[] = []
const track = async (o: Parameters<typeof startFrenet>[0]): Promise<FrenetNode> => { const n = await startFrenet(o); nodes.push(n); return n }
after(async () => { for (const n of nodes) await n.stop().catch(() => {}); for (const d of dirs) rmSync(d, { recursive: true, force: true }) })
const connect = (a: FrenetNode, b: FrenetNode) => a.libp2p.dial(b.libp2p.getMultiaddrs()[0]!)
const kp = (): Promise<PrivateKey> => generateKeyPair('Ed25519')
const fast = { N: 2 ** 10 }
const b64 = (x: object): string => Buffer.from(JSON.stringify(x)).toString('base64url')
const resolverFor = (...states: IdentityState[]) => async (id: string): Promise<IdentityState | null> => states.find((s) => s.id === id) ?? null
const waitFor = async (fn: () => boolean | Promise<boolean>, ms = 8000): Promise<void> => {
  const t = Date.now()
  while (!(await fn())) { if (Date.now() - t > ms) throw new Error('timeout'); await new Promise((r) => setTimeout(r, 50)) }
}

// ---------------------------------------------------------------------------------------------------------------
describe('key event log (did:frenet)', () => {
  it('creates an inception whose id is its digest, and a rotation only the committed key can make', async () => {
    const k0 = await kp(); const k1 = await kp(); const k2 = await kp()
    const s0 = await createInception(k0, k1.publicKey)
    assert.equal(s0.seq, 0); assert.equal(s0.id, eventDigest(s0.events[0]!)); assert.equal(s0.did, `did:frenet:${s0.id}`)
    assert.equal(s0.next, keyDigest(k1.publicKey.raw))
    assert.ok(!JSON.stringify(s0.events).includes(Buffer.from(k1.publicKey.raw).toString('base64')), 'the next key is only committed by hash')

    await assert.rejects(createRotation(s0, k2, (await kp()).publicKey), /not the pre-committed/)
    await assert.rejects(createRotation(s0, k0, k2.publicKey), /not the pre-committed/, 'the current key cannot rotate')
    const s1 = await createRotation(s0, k1, k2.publicKey)
    assert.equal(s1.id, s0.id, 'the DID is stable across rotation'); assert.equal(s1.seq, 1); assert.equal(s1.events[1]!.prev, eventDigest(s0.events[0]!))
    assert.deepEqual((await verifyLog(s1.events)).key, s1.key)
    assert.deepEqual((await verifyLog(s0.events)).id, s0.id, 'any prefix of a log is itself a valid log')
  })

  it('rejects forged, reordered, truncated-middle, self-committing and mis-timed logs', async () => {
    const k0 = await kp(); const k1 = await kp(); const k2 = await kp(); const thief = await kp()
    const s0 = await createInception(k0, k1.publicKey)
    const s1 = await createRotation(s0, k1, k2.publicKey)
    const [e0, e1] = s1.events as [IdentityEvent, IdentityEvent]
    const flip = (sig: string): string => (sig[0] === 'A' ? 'B' : 'A') + sig.slice(1)

    await assert.rejects(verifyLog([{ ...e0, sig: flip(e0.sig) }]), /bad signature/)
    await assert.rejects(verifyLog([{ ...e0, ts: e0.ts + 1 }]), /bad signature/)
    await assert.rejects(verifyLog([e0, { ...e1, prev: e0.next }]), /broken chain/)
    await assert.rejects(verifyLog([e1, e0]), /invalid event 0/)
    await assert.rejects(verifyLog([e1]), /invalid event 0/)
    await assert.rejects(verifyLog([e0, { ...e1, seq: 5 }]), /invalid event 1/)
    await assert.rejects(verifyLog([]), /invalid identity log/); await assert.rejects(verifyLog('x'), /invalid identity log/)
    await assert.rejects(verifyLog(Array(65).fill(e0)), /invalid identity log/)

    // someone holding only the current key K0 tries to append their own "rotation" to the log
    const forged = (await createRotation(await createInception(thief, k1.publicKey), k1, k2.publicKey)).events[1]!
    await assert.rejects(verifyLog([e0, { ...forged, prev: eventDigest(e0) }]), /bad signature|pre-committed/)
    // ... or hijack the commitment by rotating to a key of their choice
    const hijack = await createInception(k0, thief.publicKey)
    assert.notEqual(hijack.id, s0.id, 'a different inception is a different identity, not a fork of this one')

    // self-commitment and timestamps
    await assert.rejects(createInception(k0, k0.publicKey), /commits to its own key/)
    await assert.rejects(createInception(k0, k1.publicKey, Date.now() + 3_600_000), /invalid timestamp/)
    const early = await createInception(k0, k1.publicKey, Date.now() - 1000)
    const bad = { ...(await createRotation(early, k1, k2.publicKey)).events[1]!, ts: early.ts - 5 }
    await assert.rejects(verifyLog([early.events[0], bad]), /bad signature|backwards/)
  })

  it('a well-formed, validly signed rotation by a key that was NOT committed to is rejected', async () => {
    const k0 = await kp(); const k1 = await kp(); const thief = await kp(); const nextOfThief = await kp()
    const s0 = await createInception(k0, k1.publicKey)
    const e0 = s0.events[0]!
    // the thief holds K0's public data and a key of their own: they build a perfectly valid-looking event 1 signed by *their* key
    const body = { v: 1 as const, t: 'rot' as const, seq: 1, prev: eventDigest(e0), key: base32.baseEncode(thief.publicKey.raw), next: keyDigest(nextOfThief.publicKey.raw), ts: e0.ts + 1000 }
    const bytes = Buffer.from(`frenet-identity/v1\n${body.t}\n${body.seq}\n${body.prev}\n${body.key}\n${body.next}\n${body.ts}`)
    const forged = { ...body, sig: Buffer.from(await thief.sign(bytes)).toString('base64') }
    await assert.rejects(verifyLog([e0, forged]), /not made by the pre-committed key/)
    // ... and the same event signed by the legitimate committed key is accepted (so the test is really about the commitment)
    const legit = await createRotation(s0, k1, nextOfThief.publicKey)
    assert.equal((await verifyLog(legit.events)).seq, 1)
  })

  it('accepts a superseded key only for signatures dated before the rotation (documented backdating limit)', async () => {
    const k0 = await kp(); const k1 = await kp(); const k2 = await kp()
    const t0 = Date.now() - 600_000; const t1 = Date.now() - 300_000
    const s0 = await createInception(k0, k1.publicKey, t0)
    const s1 = await createRotation(s0, k1, k2.publicKey, t1)
    assert.ok(keyForSignature(s1, 0, t0 + 1000))
    assert.throws(() => keyForSignature(s1, 0, t1 + 1000), /already been rotated/)
    assert.throws(() => keyForSignature(s1, 0, t1 - 1, true), /has been rotated/, 'strict mode refuses every superseded key')
    assert.ok(keyForSignature(s1, 1, Date.now(), true))
    for (const seq of [2, -1, 1.5, '1', undefined]) assert.throws(() => keyForSignature(s1, seq, Date.now()), /unknown key/)
    // the stolen-old-key attacker simply backdates iat: that is why strict exists
    assert.ok(keyForSignature(s1, 0, t0 + 5000), 'backdated signature passes in the default mode')
  })

  it('serves a DID document for the current key', async () => {
    const k0 = await kp(); const k1 = await kp()
    const s = await createInception(k0, k1.publicKey)
    const d = didDocumentFor(s) as any
    assert.equal(d.id, s.did); assert.equal(d.verificationMethod[0].id, `${s.did}#0`); assert.equal(d.rotation.seq, 0)
    assert.equal(d.alsoKnownAs[0], `frenet-peer://${peerIdFromPrivateKey(k0).toString()}`)
  })
})

// ---------------------------------------------------------------------------------------------------------------
describe('credentials under a did:frenet', () => {
  it('issues and verifies with the key log, and survives rotation for credentials dated before it', async () => {
    const k0 = await kp(); const k1 = await kp(); const k2 = await kp(); const alice = await kp()
    const t0 = Date.now() - 600_000
    const s0 = await createInception(k0, k1.publicKey, t0)
    const store0 = new Store(':memory:')
    const issuer0 = new Credentials(store0, k0, { identity: s0 })
    assert.equal(issuer0.did, s0.did); assert.notEqual(issuer0.keyDid, issuer0.did)
    const aliceDid = new Credentials(new Store(':memory:'), alice).did
    const old = await issuer0.issue(aliceDid, 'Member', { n: 1 })
    assert.ok((await verifyCredential(old.jwt, { resolveLog: resolverFor(s0) })).valid)
    assert.deepEqual(await verifyCredential(old.jwt), { valid: false, error: 'cannot resolve did:frenet here' })
    assert.deepEqual(await verifyCredential(old.jwt, { resolveLog: resolverFor() }), { valid: false, error: 'unknown identity (no key log available)' })

    // rotate (after the credential was issued), then issue from the new key
    const s1 = await createRotation(s0, k1, k2.publicKey, Date.now() + 2000)
    const issuer1 = new Credentials(new Store(':memory:'), k1, { identity: s1 })
    assert.equal(issuer1.did, issuer0.did, 'same DID after rotation')
    const fresh = await issuer1.issue(aliceDid, 'Member', { n: 2 })
    const v = await verifyCredential(fresh.jwt, { resolveLog: resolverFor(s1) })
    assert.ok(v.valid && v.credential.issuer === s0.did)
    assert.ok((await verifyCredential(old.jwt, { resolveLog: resolverFor(s1) })).valid, 'credential signed by the old key before rotation still verifies')
    assert.deepEqual(await verifyCredential(old.jwt, { resolveLog: resolverFor(s1), strict: true }), { valid: false, error: 'signed with a key that has been rotated' })
    // a verifier that only knows the old log cannot validate the new key and must ask for a newer one
    assert.deepEqual(await verifyCredential(fresh.jwt, { resolveLog: resolverFor(s0) }), { valid: false, error: 'unknown key for this identity' })
  })

  it('a thief with only the old key cannot sign after rotation (undated or honestly dated)', async () => {
    const k0 = await kp(); const k1 = await kp(); const k2 = await kp(); const victim = await kp()
    const t0 = Date.now() - 600_000; const t1 = Date.now() - 300_000
    const s0 = await createInception(k0, k1.publicKey, t0)
    const s1 = await createRotation(s0, k1, k2.publicKey, t1)
    const thief = new Credentials(new Store(':memory:'), k0, { identity: s0 })   // still believes it is the identity
    const victimDid = new Credentials(new Store(':memory:'), victim).did
    const stolen = await thief.issue(victimDid, 'Admin', { root: true })         // signed *now*, after the rotation
    assert.deepEqual(await verifyCredential(stolen.jwt, { resolveLog: resolverFor(s1) }), { valid: false, error: 'signed with a key that had already been rotated' })
    // kid pointing at an epoch that was never theirs
    const parts = stolen.jwt.split('.')
    const hdr = JSON.parse(Buffer.from(parts[0]!, 'base64url').toString())
    for (const kid of [`${s0.did}#1`, `${s0.did}#01`, `${s0.did}`, `${s0.did}#x`, `did:key:zabc#0`]) {
      assert.equal((await verifyCredential(`${b64({ ...hdr, kid })}.${parts[1]}.${parts[2]}`, { resolveLog: resolverFor(s1) })).valid, false, kid)
    }
  })

  it('revocation statements from a did:frenet issuer verify against its log', async () => {
    const k0 = await kp(); const k1 = await kp(); const alice = await kp()
    const s0 = await createInception(k0, k1.publicKey)
    const store = new Store(':memory:')
    const issuer = new Credentials(store, k0, { identity: s0 })
    const c = await issuer.issue(new Credentials(new Store(':memory:'), alice).did, 'Member', {})
    const rv = await issuer.revoke(c.id)
    assert.deepEqual(await verifyRevocation(rv.jwt, { resolveLog: resolverFor(s0) }), { valid: true, issuer: s0.did, id: c.id })
    assert.equal((await verifyRevocation(rv.jwt)).valid, false)
  })
})

// ---------------------------------------------------------------------------------------------------------------
describe('rotation on a real node (CLI library path)', () => {
  it('rotation-init, restart as did:frenet, rotate after key loss, peers follow the log over the network', async () => {
    const dirA = tmp()
    let a = await track({ dataDir: dirA, listen: L, mdns: false })
    const peer0 = a.libp2p.peerId.toString()
    assert.equal(a.identity, null); assert.equal(a.did, a.keyDid)
    await a.stop()

    const { state, nextBackup } = await initRotation(dirA, 'next key passphrase 1', fast)
    assert.equal(statSync(join(dirA, 'identity-log.json')).mode & 0o777, 0o600)
    assert.ok(!readFileSync(join(dirA, 'identity.key')).toString('latin1').includes(nextBackup), 'next key never lands in the data dir')
    await assert.rejects(initRotation(dirA, 'next key passphrase 1', fast), /already has a key log/)

    a = await track({ dataDir: dirA, listen: L, mdns: false })
    assert.equal(a.did, state.did); assert.equal(a.identity!.seq, 0); assert.equal(a.libp2p.peerId.toString(), peer0, 'enabling rotation keeps the peer ID')
    const b = await track({ dataDir: ':memory:', listen: L, mdns: false })
    await connect(b, a); await a.identityLogs.announceOwn()
    const alice = await track({ dataDir: ':memory:', listen: L, mdns: false })

    const c1 = await a.credentials.issue(alice.did, 'Member', { n: 1 })
    await waitFor(async () => (await b.credentials.verify(c1.jwt)).valid)       // b had no log: fetched and verified over the network
    assert.equal(b.identityLogs.known(state.id)?.seq, 0)

    // total key loss: the node's key file is gone, only the offline next-key backup (and the public log) remain
    await a.stop()
    const logCopy = JSON.parse(JSON.stringify(readIdentityLog(dirA)))
    rmSync(join(dirA, 'identity.key')); rmSync(join(dirA, 'identity-log.json'))
    await assert.rejects(rotateIdentity(dirA, nextBackup, 'next key passphrase 1', 'next key passphrase 2', fast), /no identity log/)
    await assert.rejects(rotateIdentity(dirA, nextBackup, 'wrong passphrase wrong', 'next key passphrase 2', { ...fast, logEvents: logCopy }), /wrong passphrase or corrupted/)
    const r = await rotateIdentity(dirA, nextBackup, 'next key passphrase 1', 'next key passphrase 2', { ...fast, logEvents: logCopy })
    assert.equal(r.did, state.did); assert.equal(r.state.seq, 1); assert.notEqual(r.peerId, peer0, 'the libp2p key (peer ID) changes')
    assert.equal(statSync(join(dirA, 'identity.key')).mode & 0o777, 0o600)
    // the used next key is spent; a stale backup cannot be replayed
    await assert.rejects(rotateIdentity(dirA, nextBackup, 'next key passphrase 1', 'x'.repeat(12), fast), /not the pre-committed next key/)

    a = await track({ dataDir: dirA, listen: L, mdns: false })
    assert.equal(a.did, state.did); assert.equal(a.identity!.seq, 1); assert.equal(a.libp2p.peerId.toString(), r.peerId)
    await connect(b, a); await a.identityLogs.announceOwn()
    const c2 = await a.credentials.issue(alice.did, 'Member', { n: 2 })
    await waitFor(async () => (await b.credentials.verify(c2.jwt)).valid)       // b only knew epoch 0: the kid names #1, so it re-fetched the log
    assert.equal(b.identityLogs.known(state.id)?.seq, 1)
    assert.ok((await b.credentials.verify(c1.jwt)).valid, 'pre-rotation credential still valid')
    assert.deepEqual(await b.credentials.verify(c1.jwt, { strict: true }), { valid: false, error: 'signed with a key that has been rotated' })

    // the next rotation uses the *new* backup
    const r2 = await rotateIdentity(dirA, r.nextBackup, 'next key passphrase 2', 'next key passphrase 3', fast)
    assert.equal(r2.state.seq, 2); assert.equal(r2.did, state.did)
    assert.ok(readdirSync(dirA).filter((f) => f.startsWith('identity.key.replaced-')).length >= 1, 'the previous key is kept, not destroyed')
  })

  it('refuses to start when the log does not end in the identity key', async () => {
    const dir = tmp()
    const n = await startFrenet({ dataDir: dir, listen: L, mdns: false }); await n.stop()
    const { state } = await initRotation(dir, 'next key passphrase 1', fast)
    const other = await kp()
    const wrong = await createInception(other, (await kp()).publicKey)
    writeIdentityLog(dir, wrong.events)
    await assert.rejects(startFrenet({ dataDir: dir, listen: L, mdns: false }), /does not end in this node's identity key/)
    writeIdentityLog(dir, state.events)
    const ok = await track({ dataDir: dir, listen: L, mdns: false })
    assert.equal(ok.did, state.did)
    writeFileSync(join(dir, 'identity-log.json'), '{}')
    await ok.stop()
    await assert.rejects(startFrenet({ dataDir: dir, listen: L, mdns: false }), /not an identity log/)
    assert.ok(existsSync(join(dir, 'identity.key')))
  })

  it('a fetched log can never displace a longer or diverging one we hold', async () => {
    const a = await track({ dataDir: ':memory:', listen: L, mdns: false })
    const k0 = await kp(); const k1 = await kp(); const k2 = await kp()
    const s0 = await createInception(k0, k1.publicKey, Date.now() - 5000)
    const s1 = await createRotation(s0, k1, k2.publicKey, Date.now() - 1000)
    assert.equal((await a.identityLogs.adopt(s1.events))!.seq, 1)
    assert.equal((await a.identityLogs.adopt(s0.events))!.seq, 1, 'a shorter prefix does not roll us back')
    assert.equal(await a.identityLogs.adopt([{ ...s0.events[0], sig: 'x' }]), null, 'invalid log ignored')
    assert.equal(a.identityLogs.known(s0.id)!.seq, 1)
  })
})

// ---------------------------------------------------------------------------------------------------------------
describe('revocation distribution', () => {
  it('push on revoke, pull by a late verifier, and no forged revocations', async () => {
    const issuer = await track({ dataDir: ':memory:', listen: L, mdns: false })
    const v1 = await track({ dataDir: ':memory:', listen: L, mdns: false })
    const holder = await track({ dataDir: ':memory:', listen: L, mdns: false })
    const late = await track({ dataDir: ':memory:', listen: L, mdns: false })
    const mallory = await track({ dataDir: ':memory:', listen: L, mdns: false })
    await connect(issuer, v1); await connect(issuer, holder); await connect(mallory, v1)

    const cred = await issuer.credentials.issue(holder.did, 'Member', { n: 1 })
    await holder.credentials.hold(cred.jwt)

    // issuer revokes: statements are pushed to the peers it is connected to (v1, holder)
    const rv = await issuer.credentials.revoke(cred.id)
    assert.ok(rv.pushed >= 2, `pushed to ${rv.pushed}`)
    assert.deepEqual(await v1.credentials.verify(cred.jwt, { online: false }), { valid: false, error: 'revoked' })
    assert.deepEqual(await holder.credentials.verify(cred.jwt, { online: false }), { valid: false, error: 'revoked' })
    await assert.rejects(holder.credentials.present([cred.id], 'n1'), /no longer valid: revoked/)

    // a verifier that was not connected at the time pulls it from providers (online is the default)
    await connect(late, v1); await connect(late, issuer)
    assert.ok((await late.credentials.verify(cred.jwt, { online: false })).valid, 'offline check cannot know')
    await issuer.revocations.announce(issuer.did, cred.id)
    await waitFor(async () => !(await late.credentials.verify(cred.jwt)).valid, 15_000)
    assert.deepEqual(await late.credentials.verify(cred.jwt, { online: false }), { valid: false, error: 'revoked' }, 'the pulled statement is now stored locally')

    // Mallory cannot revoke someone else's credential by pushing a statement
    const other = await issuer.credentials.issue(holder.did, 'Member', { n: 2 })
    const forged = await mallory.credentials.issue(holder.did, 'Member', { n: 3 })
    const fromMallory = (await mallory.credentials.revoke(forged.id)).jwt
    const asked = (req: object) => ask(mallory.libp2p, { id: v1.libp2p.peerId, multiaddrs: [] }, REVOKE_PROTOCOL, req, AbortSignal.timeout(5000), 4096)
    assert.equal(await asked({ k: 'put', jwt: fromMallory }), true)                 // valid, but only about Mallory's own credential
    assert.ok((await v1.credentials.verify(other.jwt, { online: false })).valid)
    assert.equal(await asked({ k: 'put', jwt: fromMallory.slice(0, -3) + 'AAA' }), false)
    assert.equal(await asked({ k: 'put', jwt: cred.jwt }), false)                    // a credential is not a revocation
    assert.equal(await asked({ k: 'get', issuer: issuer.did, id: cred.id }), rv.jwt)
    assert.equal(await asked({ k: 'get', issuer: issuer.did, id: other.id }), null)
    assert.equal(await asked({ k: 'get', issuer: 'x', id: '../../etc' }), null, 'malformed lookups are refused')
    assert.equal(await asked({ k: 'nope' }), null)
  })

  it('caps stored foreign revocations and never evicts our own', () => {
    const s = new Store(':memory:')
    s.addRevocation('did:key:own', 'mine', 'jwt', true)
    for (let i = 0; i < 10_050; i++) s.addRevocation('did:key:other', `c${i}`, 'jwt')
    assert.ok(s.isRevoked('did:key:own', 'mine'))
    assert.equal(s.listRevocations().length, 10_001)
  })
})

describe('rotation CLI', () => {
  const cli = (args: string[]) => spawnSync(process.execPath, ['--import', 'tsx', 'src/cli.ts', ...args], { encoding: 'utf8', cwd: process.cwd(), timeout: 90_000 })
  it('rotation-init, identity, log and rotate (with a saved log after losing the data dir)', async () => {
    const d = tmp(); const out = tmp(); const fresh = tmp()
    const { key } = await loadOrCreateIdentity(d)
    const peer0 = peerIdFromPrivateKey(key).toString()
    const pw = join(out, 'pw'); writeFileSync(pw, 'cli rotation passphrase\n')
    assert.match(cli(['identity', '--data', d]).stdout, /fixed key: run `frenet identity rotation-init`/)
    assert.equal(cli(['identity', 'log', '--data', d]).status, 1)
    const nk = join(out, 'next.backup')
    const init = cli(['identity', 'rotation-init', '--data', d, '--next-out', nk, '--passphrase-file', pw])
    assert.equal(init.status, 0, init.stderr); assert.match(init.stdout, /DID did:frenet:[a-z2-7]{52}/)
    assert.equal(statSync(nk).mode & 0o777, 0o600)
    assert.equal(cli(['identity', 'rotation-init', '--data', d, '--next-out', join(out, 'again'), '--passphrase-file', pw]).status, 1)
    const shown = cli(['identity', '--data', d]); assert.match(shown.stdout, /rotatable, key #0/); assert.match(shown.stdout, new RegExp(peer0))
    const logFile = join(out, 'log.json'); const lg = cli(['identity', 'log', '--data', d]); assert.equal(lg.status, 0); writeFileSync(logFile, lg.stdout)
    const did = /did:frenet:[a-z2-7]{52}/.exec(init.stdout)![0]

    // the data directory is gone; only the offline backup and the public log copy remain
    const nk2 = join(out, 'next2.backup')
    assert.equal(cli(['identity', 'rotate', '--data', fresh, '--next-key', nk, '--next-out', nk2, '--passphrase-file', pw]).status, 1, 'no log, no rotation')
    const rot = cli(['identity', 'rotate', '--data', fresh, '--next-key', nk, '--next-out', nk2, '--log', logFile, '--passphrase-file', pw])
    assert.equal(rot.status, 0, rot.stderr); assert.match(rot.stdout, new RegExp(`DID unchanged: ${did}`)); assert.match(rot.stdout, /key #1/)
    const after = cli(['identity', '--data', fresh]); assert.match(after.stdout, new RegExp(did)); assert.ok(!after.stdout.includes(peer0), 'peer ID changed')
    assert.equal(cli(['identity', 'rotate', '--data', fresh, '--next-key', nk, '--next-out', join(out, 'x'), '--passphrase-file', pw]).status, 1, 'the spent next-key backup cannot be reused')
    const n = await startFrenet({ dataDir: fresh, listen: L, mdns: false })
    try { assert.equal(n.did, did); assert.equal(n.identity!.seq, 1) } finally { await n.stop() }
  })
})

describe('revocation lookup against a malicious provider', () => {
  const fakeNode = (reply: unknown) => ({
    peerId: { equals: () => false },
    peerStore: { merge: async () => {} },
    contentRouting: { async * findProviders () { yield { id: { equals: () => false }, multiaddrs: [] } }, provide: async () => {} },
    dialProtocol: async () => {
      const buf = Buffer.from(JSON.stringify(reply))
      return { send () {}, async close () {}, async * [Symbol.asyncIterator] () { yield { byteLength: buf.length, subarray: () => buf } } }
    },
    getConnections: () => [], handle: async () => {}, unhandle: async () => {}
  }) as any

  it('only accepts a statement for exactly the issuer and credential asked about', async () => {
    const issuer = await kp(); const mallory = await kp(); const holder = await kp()
    const holderDid = new Credentials(new Store(':memory:'), holder).did
    const iStore = new Store(':memory:'); const issuerC = new Credentials(iStore, issuer)
    const target = await issuerC.issue(holderDid, 'Member', {})
    const other = await issuerC.issue(holderDid, 'Member', { n: 2 })
    const mStore = new Store(':memory:'); const malloryC = new Credentials(mStore, mallory)
    const mine = await malloryC.issue(holderDid, 'Member', {})
    const real = await issuerC.revoke(other.id)                       // genuine, but for a different credential
    const hers = await malloryC.revoke(mine.id)                       // genuine, but by a different issuer
    const verifier = new Store(':memory:')
    const check = (jwt: unknown) => verifyRevocation(jwt)
    for (const [label, reply] of [['another credential of the same issuer', real.jwt], ['a different issuer', hers.jwt], ['garbage', 'x.y.z'], ['null', null]] as const) {
      const r = new Revocations(fakeNode(reply), verifier, check)
      assert.equal(await r.lookup(issuerC.did, target.id), false, label)
      assert.equal(verifier.isRevoked(issuerC.did, target.id), false, label)
    }
    assert.equal(verifier.isRevoked(issuerC.did, other.id), false, 'nothing was stored from the wrong answers')
    // the right statement is accepted and stored
    const good = (await issuerC.revoke(target.id)).jwt
    assert.equal(await new Revocations(fakeNode(good), verifier, check).lookup(issuerC.did, target.id), true)
    assert.equal(verifier.isRevoked(issuerC.did, target.id), true)
  })
})
