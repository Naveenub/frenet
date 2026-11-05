import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { after, describe, it } from 'node:test'
import { generateKeyPair, privateKeyToProtobuf } from '@libp2p/crypto/keys'
import type { PrivateKey } from '@libp2p/interface'
import { peerIdFromPrivateKey } from '@libp2p/peer-id'
import { startApi } from '../src/api.js'
import { Credentials, verifyCredential, verifyPresentation, verifyRevocation } from '../src/credentials.js'
import { didDocument, didFromPeerId, didFromPublicKeyRaw, parseDidKey, peerIdFromDid, resolveDid, toDid } from '../src/did.js'
import { loadOrCreateIdentity } from '../src/identity.js'
import { startFrenet, type FrenetNode } from '../src/node.js'
import { combineShares, createBackup, describeKey, gfDiv, gfMul, installKey, openBackup, parseShare, splitSecret } from '../src/recovery.js'
import { Store } from '../src/store.js'

const tmpDirs: string[] = []
const tmp = (): string => { const d = mkdtempSync(join(tmpdir(), 'frenet-p2-')); tmpDirs.push(d); return d }
const nodes: FrenetNode[] = []
after(async () => {
  for (const n of nodes) await n.stop().catch(() => {})
  for (const d of tmpDirs) rmSync(d, { recursive: true, force: true })
})

interface Actor { key: PrivateKey, did: string, store: Store, c: Credentials }
const actor = async (): Promise<Actor> => {
  const key = await generateKeyPair('Ed25519')
  const store = new Store(':memory:')
  const c = new Credentials(store, key)
  return { key, did: c.did, store, c }
}
const b64u = (x: object | Uint8Array): string => Buffer.from(x instanceof Uint8Array ? x : JSON.stringify(x)).toString('base64url')
const forge = async (key: PrivateKey, header: object, payload: object): Promise<string> => {
  const input = `${b64u(header)}.${b64u(payload)}`
  return `${input}.${b64u(await key.sign(Buffer.from(input)))}`
}
const decode = (jwt: string): { header: any, payload: any } => ({
  header: JSON.parse(Buffer.from(jwt.split('.')[0]!, 'base64url').toString()),
  payload: JSON.parse(Buffer.from(jwt.split('.')[1]!, 'base64url').toString())
})
const fast = { N: 2 ** 10 }   // cheap scrypt for tests that are not about the KDF cost

// ---------------------------------------------------------------------------------------------------------------
describe('DIDs (did:key)', () => {
  it('matches the did:key test vector and round-trips with peer IDs', async () => {
    const vector = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'
    assert.equal(didFromPublicKeyRaw(parseDidKey(vector).raw), vector)
    const key = await generateKeyPair('Ed25519')
    const pid = peerIdFromPrivateKey(key).toString()
    const did = didFromPeerId(pid)
    assert.match(did, /^did:key:z6Mk/)
    assert.equal(did, didFromPublicKeyRaw(key.publicKey.raw))
    assert.equal(peerIdFromDid(did), pid)
    assert.equal(toDid(pid), did); assert.equal(toDid(did), did)
  })

  it('derives a DID document from the identifier alone', async () => {
    const key = await generateKeyPair('Ed25519')
    const did = didFromPublicKeyRaw(key.publicKey.raw)
    const doc = didDocument(did)
    const vm = doc.verificationMethod[0]!
    assert.equal(doc.id, did); assert.equal(vm.controller, did); assert.equal(vm.id, `${did}#${vm.publicKeyMultibase}`)
    assert.equal(vm.publicKeyMultibase, did.slice('did:key:'.length))
    assert.deepEqual(doc.authentication, [vm.id]); assert.deepEqual(doc.assertionMethod, [vm.id])
    assert.deepEqual(resolveDid(vm.id).document, doc)
    assert.throws(() => resolveDid(`${did}#nope`), /unknown verification method/)
  })

  it('rejects other methods, key types, and malformed or non-canonical DIDs', () => {
    const good = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'
    for (const bad of [
      'did:web:example.com', 'did:key:', 'did:key:abc', `${good}#x`, `${good}/path`, `${good}?q=1`, `${good} `, good.slice(0, -3),
      'did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme',   // secp256k1 multikey: valid did:key, but not a key we support
      'did:key:z' + '1'.repeat(48), '', 42, null
    ]) assert.throws(() => parseDidKey(bad as any), undefined, String(bad))
    assert.throws(() => toDid('not-a-peer-id'))
  })
})

// ---------------------------------------------------------------------------------------------------------------
describe('verifiable credentials (VC-JWT)', () => {
  it('issues a credential that any third party can verify offline', async () => {
    const issuer = await actor(); const alice = await actor()
    const r = await issuer.c.issue(alice.did, 'UniversityDegree', { degree: 'BSc', year: 2026 }, { ttlMs: 86_400_000 })
    const { header, payload } = decode(r.jwt)
    assert.equal(header.alg, 'EdDSA'); assert.equal(header.typ, 'JWT'); assert.equal(header.kid, `${issuer.did}#${issuer.did.slice(8)}`)
    assert.equal(payload.iss, issuer.did); assert.equal(payload.sub, alice.did)
    assert.deepEqual(payload.vc.type, ['VerifiableCredential', 'UniversityDegree'])
    // a verifier with no state at all (no shared store, no network):
    const v = await verifyCredential(r.jwt)
    assert.ok(v.valid)
    if (v.valid) {
      assert.equal(v.credential.issuer, issuer.did); assert.equal(v.credential.subject, alice.did)
      assert.deepEqual(v.credential.claims, { degree: 'BSc', year: 2026 }); assert.deepEqual(v.credential.types, ['UniversityDegree'])
      assert.ok(v.credential.expires! > Date.now())
    }
  })

  it('accepts a peer ID as the subject and rejects bad types and claims', async () => {
    const issuer = await actor(); const alice = await actor()
    const pid = peerIdFromPrivateKey(alice.key).toString()
    assert.equal((await issuer.c.issue(pid, 'Member', {})).credential.subject, alice.did)
    for (const t of ['', '1bad', 'has space', 'VerifiableCredential', 'x'.repeat(65)]) await assert.rejects(issuer.c.issue(alice.did, t, {}), /invalid credential type/, t)
    await assert.rejects(issuer.c.issue(alice.did, 'T', { id: 'did:key:other' }), /"id"/)
    await assert.rejects(issuer.c.issue(alice.did, 'T', [1] as any), /object/)
    await assert.rejects(issuer.c.issue(alice.did, 'T', { big: 'x'.repeat(9000) }), /at most/)
    await assert.rejects(issuer.c.issue(alice.did, 'T', { n: 1 }, { ttlMs: -1 }), /expiry/)
    await assert.rejects(issuer.c.issue('did:web:x.example', 'T', {}), /unsupported DID/)
  })

  it('rejects tampering, alg games, wrong typ, kid mismatch and expiry', async () => {
    const issuer = await actor(); const alice = await actor(); const mallory = await actor()
    const { jwt } = await issuer.c.issue(alice.did, 'Member', { level: 1 }, { ttlMs: 60_000 })
    const [h, p, s] = jwt.split('.') as [string, string, string]
    const { header, payload } = decode(jwt)

    // changed claims keep the old signature
    const edited = b64u({ ...payload, vc: { ...payload.vc, credentialSubject: { level: 99 } } })
    assert.deepEqual(await verifyCredential(`${h}.${edited}.${s}`), { valid: false, error: 'bad signature' })
    // signature from a different key under the issuer's DID
    const other = await forge(mallory.key, header, payload)
    assert.deepEqual(await verifyCredential(other), { valid: false, error: 'bad signature' })
    // alg: none / HS256 / lower-case variants are refused before any key use
    for (const alg of ['none', 'HS256', 'eddsa', 'ES256']) {
      const r = await verifyCredential(`${b64u({ ...header, alg })}.${p}.${s}`)
      assert.deepEqual(r, { valid: false, error: 'unsupported alg (only EdDSA)' }, alg)
    }
    assert.equal((await verifyCredential(`${b64u({ ...header, alg: 'none' })}.${p}.`)).valid, false)
    // typ is pinned, and kid must be the issuer's own key
    assert.equal((await verifyCredential(await forge(issuer.key, { ...header, typ: 'frenet-revocation+jwt' }, payload))).valid, false)
    assert.deepEqual(await verifyCredential(await forge(issuer.key, { ...header, kid: `${mallory.did}#${mallory.did.slice(8)}` }, payload)), { valid: false, error: 'kid does not match issuer' })
    // malformed shapes
    for (const bad of ['', 'a.b', 'a.b.c.d', `${h}.${p}.${s}=`, `${h}.${p}.${b64u(Buffer.alloc(10))}`, 'x'.repeat(17 * 1024), null, 5]) assert.equal((await verifyCredential(bad)).valid, false)
    // expiry and not-yet-valid use the supplied clock
    const nowMs = Date.now()
    assert.equal((await verifyCredential(jwt, { now: nowMs + 3_600_000 })).valid, false)
    assert.deepEqual(await verifyCredential(jwt, { now: nowMs - 3_600_000 }), { valid: false, error: 'not yet valid' })
    assert.ok((await verifyCredential(jwt, { now: nowMs })).valid)
  })

  it('checks subject consistency, and keeps credentials, presentations and revocations from being confused', async () => {
    const issuer = await actor(); const alice = await actor(); const bob = await actor()
    const { jwt } = await issuer.c.issue(alice.did, 'Member', {})
    const { header, payload } = decode(jwt)
    const nowS = Math.floor(Date.now() / 1000)
    const base = { iss: issuer.did, sub: alice.did, jti: 'urn:uuid:x', nbf: nowS, vc: payload.vc }
    // credentialSubject.id must agree with sub
    const mismatch = await forge(issuer.key, header, { ...base, vc: { ...payload.vc, credentialSubject: { id: bob.did } } })
    assert.deepEqual(await verifyCredential(mismatch), { valid: false, error: 'credentialSubject.id does not match sub' })
    // a credential payload carrying a revocation or presentation claim is not a credential
    assert.deepEqual(await verifyCredential(await forge(issuer.key, header, { ...base, revokes: 'urn:uuid:y' })), { valid: false, error: 'not a credential' })
    assert.deepEqual(await verifyCredential(await forge(issuer.key, header, { ...base, vp: {} })), { valid: false, error: 'not a credential' })
    // a credential is never accepted as a revocation or a presentation
    assert.equal((await verifyRevocation(jwt)).valid, false)
    assert.equal((await verifyPresentation(jwt, { nonce: 'n1' })).valid, false)
  })

  it('revokes: statements are signed, issuer-scoped, and honoured by verifiers that import them', async () => {
    const issuer = await actor(); const alice = await actor(); const verifier = await actor(); const mallory = await actor()
    const { id, jwt } = await issuer.c.issue(alice.did, 'Member', {})
    assert.ok((await verifier.c.verify(jwt)).valid)
    await assert.rejects(alice.c.revoke(id), /no such credential/)   // only the issuer can produce a statement
    // Mallory cannot revoke someone else's credential: her statement is signed under *her* DID, so it only covers her own ids.
    const own = await mallory.c.issue(alice.did, 'Member', {})
    const m = await mallory.c.revoke(own.id)
    await verifier.c.importRevocation(m.jwt)
    const forged = await forge(mallory.key, { alg: 'EdDSA', typ: 'frenet-revocation+jwt', kid: `${mallory.did}#${mallory.did.slice(8)}` }, { iss: mallory.did, iat: Math.floor(Date.now() / 1000), revokes: id })
    await verifier.c.importRevocation(forged)
    assert.ok((await verifier.c.verify(jwt)).valid, 'a third party cannot revoke the issuer\'s credential')
    // the real statement does
    const st = await issuer.c.revoke(id)
    assert.deepEqual(await verifyRevocation(st.jwt), { valid: true, issuer: issuer.did, id })
    assert.deepEqual(await verifier.c.importRevocation(st.jwt), { issuer: issuer.did, id })
    assert.deepEqual(await verifier.c.verify(jwt), { valid: false, error: 'revoked' })
    assert.equal((await verifier.c.importRevocation(st.jwt)).id, id)   // idempotent
    // tampered / non-revocation input is refused
    await assert.rejects(verifier.c.importRevocation(jwt), /rejected/)
    assert.equal((await verifyRevocation(st.jwt.slice(0, -4) + 'AAAA')).valid, false)
    // the issuer's own record shows it
    assert.equal(issuer.c.list('issued').find((c) => c.id === id)!.revoked, true)
  })

  it('holds only credentials addressed to this identity, and re-checks them when presenting', async () => {
    const issuer = await actor(); const alice = await actor(); const bob = await actor()
    const toAlice = await issuer.c.issue(alice.did, 'Member', { n: 1 })
    const toBob = await issuer.c.issue(bob.did, 'Member', { n: 2 })
    await assert.rejects(alice.c.hold(toBob.jwt), /not addressed/)
    await assert.rejects(alice.c.hold(toAlice.jwt + 'x'), /rejected/)
    assert.equal((await alice.c.hold(toAlice.jwt)).id, toAlice.id)
    assert.deepEqual(alice.c.list('held').map((c) => c.id), [toAlice.id])
    // revocation after the fact blocks presenting
    const st = await issuer.c.revoke(toAlice.id)
    await alice.c.importRevocation(st.jwt)
    await assert.rejects(alice.c.present([toAlice.id], 'n1'), /no longer valid: revoked/)
    await assert.rejects(alice.c.present([toBob.id], 'n1'), /not held/)
  })

  it('presentations bind holder, verifier nonce, audience and lifetime', async () => {
    const issuer = await actor(); const alice = await actor(); const bob = await actor(); const verifier = await actor()
    const cred = await issuer.c.issue(alice.did, 'Member', { tier: 'gold' })
    await alice.c.hold(cred.jwt)
    const vp = await alice.c.present([cred.id], 'challenge-123', { audience: 'https://shop.example' })
    const ok = await verifier.c.verifyPresentation(vp.jwt, 'challenge-123', 'https://shop.example')
    assert.ok(ok.valid)
    if (ok.valid) { assert.equal(ok.holder, alice.did); assert.deepEqual(ok.credentials.map((c) => c.claims), [{ tier: 'gold' }]) }
    // replay under another challenge / to another verifier / without naming an audience
    assert.deepEqual(await verifier.c.verifyPresentation(vp.jwt, 'challenge-999', 'https://shop.example'), { valid: false, error: 'nonce mismatch' })
    assert.deepEqual(await verifier.c.verifyPresentation(vp.jwt, 'challenge-123', 'https://evil.example'), { valid: false, error: 'audience mismatch' })
    assert.deepEqual(await verifier.c.verifyPresentation(vp.jwt, 'challenge-123'), { valid: false, error: 'audience mismatch' })
    assert.equal((await verifyPresentation(vp.jwt, { nonce: '' })).valid, false)   // verifier must supply a challenge
    // expired
    assert.deepEqual(await verifyPresentation(vp.jwt, { nonce: 'challenge-123', audience: 'https://shop.example', now: Date.now() + 3_600_000 }), { valid: false, error: 'expired' })
    // Bob cannot present Alice's credential: signing it himself fails the holder binding
    const stolen = await forge(bob.key, { alg: 'EdDSA', typ: 'JWT', kid: `${bob.did}#${bob.did.slice(8)}` }, {
      iss: bob.did, jti: 'urn:uuid:vp', nonce: 'n', iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 60,
      vp: { '@context': ['https://www.w3.org/2018/credentials/v1'], type: ['VerifiablePresentation'], verifiableCredential: [cred.jwt] }
    })
    assert.deepEqual(await verifyPresentation(stolen, { nonce: 'n' }), { valid: false, error: 'credential is not about the presenter' })
    // input validation on create
    await assert.rejects(alice.c.present([], 'n'), /choose/)
    await assert.rejects(alice.c.present([cred.id], ''), /nonce/)
    await assert.rejects(alice.c.present([cred.id], 'n', { ttlMs: 10 }), /lifetime/)
    await assert.rejects(alice.c.present([cred.id], 'n', { audience: 'has space' }), /audience/)
  })
})

// ---------------------------------------------------------------------------------------------------------------
describe('account recovery: Shamir shares', () => {
  it('implements GF(256) arithmetic (FIPS-197 test vector)', () => {
    assert.equal(gfMul(0x57, 0x83), 0xc1)
    assert.equal(gfMul(0x57, 0x13), 0xfe)
    for (let a = 1; a < 256; a++) assert.equal(gfDiv(gfMul(a, 0x1d), 0x1d), a)
    assert.throws(() => gfDiv(1, 0))
  })

  it('agrees with an independent implementation: table-free GF multiply (exhaustive) and Gauss-Jordan recovery', () => {
    // Russian-peasant multiply modulo 0x11b: shares no code or tables with src/recovery.ts
    const mulBit = (a: number, b: number): number => { let p = 0; while (b) { if (b & 1) p ^= a; a <<= 1; if (a & 0x100) a ^= 0x11b; b >>= 1 } return p }
    for (let a = 0; a < 256; a++) for (let b = 0; b < 256; b++) assert.equal(gfMul(a, b), mulBit(a, b), `${a}*${b}`)
    const inv = (a: number): number => { let r = 1; for (let i = 0; i < 254; i++) r = mulBit(r, a); return r }   // a^254 = a^-1
    for (const [k, n] of [[2, 3], [3, 5], [5, 9], [8, 12]] as const) {
      const secret = Buffer.from(Array.from({ length: 40 }, (_, i) => (i * 37 + k) & 0xff))
      const shares = splitSecret(secret, k, n).map(parseShare)
      const pick = shares.filter((_, i) => i % 2 === 0 || i < k).slice(0, k).reverse()   // a scrambled k-subset
      const framed = Buffer.alloc(pick[0]!.data.length)
      for (let byte = 0; byte < framed.length; byte++) {
        // solve V c = y for the polynomial's coefficients; c[0] is the secret byte
        const m = pick.map((s) => { const row: number[] = []; let pw = 1; for (let j = 0; j < k; j++) { row.push(pw); pw = mulBit(pw, s.x) } row.push(s.data[byte]!); return row })
        for (let col = 0; col < k; col++) {
          const piv = m.findIndex((r, i) => i >= col && r[col] !== 0); assert.notEqual(piv, -1)
          ;[m[col], m[piv]] = [m[piv]!, m[col]!]
          const f = inv(m[col]![col]!); m[col] = m[col]!.map((v) => mulBit(v, f))
          for (let r = 0; r < k; r++) if (r !== col && m[r]![col] !== 0) { const g = m[r]![col]!; m[r] = m[r]!.map((v, c) => v ^ mulBit(g, m[col]![c]!)) }
        }
        framed[byte] = m[0]![k]!
      }
      assert.deepEqual(framed.subarray(0, 40), secret, `k=${k} n=${n}`)
      assert.deepEqual(new Uint8Array(combineShares(pick.map((s) => `frenet-share:1:${k}:${s.set}:${s.x}:${s.data.toString('base64url')}:${createHash('sha256').update(`frenet-share:1:${k}:${s.set}:${s.x}:${s.data.toString('base64url')}`).digest('hex').slice(0, 8)}`))), new Uint8Array(secret))
    }
  })

  it('any k of n shares recover a real identity key; k-1 do not', async () => {
    const key = await generateKeyPair('Ed25519')
    const bytes = privateKeyToProtobuf(key)
    const shares = splitSecret(bytes, 3, 5)
    assert.equal(shares.length, 5)
    const subsets: number[][] = []
    for (let a = 0; a < 5; a++) for (let b = a + 1; b < 5; b++) for (let c = b + 1; c < 5; c++) subsets.push([a, b, c])
    assert.equal(subsets.length, 10)
    for (const s of subsets) assert.deepEqual(combineShares(s.map((i) => shares[i]!)), bytes)
    assert.deepEqual(combineShares(shares), bytes)   // more than k is fine
    assert.equal(describeKey(combineShares([shares[4]!, shares[0]!, shares[2]!])).peerId, peerIdFromPrivateKey(key).toString())
    assert.throws(() => combineShares([shares[0]!, shares[1]!]), /need 3 shares, got 2/)
    assert.throws(() => combineShares([shares[0]!, shares[0]!, shares[1]!]), /need 3 shares, got 2/, 'duplicates do not count')
  })

  it('shares are independent of the secret and of each other (fresh randomness per split)', () => {
    const secret = Buffer.alloc(36, 7)
    const a = splitSecret(secret, 2, 3); const b = splitSecret(secret, 2, 3)
    assert.notEqual(parseShare(a[0]!).set, parseShare(b[0]!).set)
    assert.notDeepEqual(parseShare(a[0]!).data, parseShare(b[0]!).data)
    // 2-of-3 over a constant secret: a single share must not look like the secret
    for (const s of a) assert.notDeepEqual(parseShare(s).data.subarray(0, 36), secret)
  })

  it('detects typos, mixed splits, wrong parameters and forged-but-well-formed shares', () => {
    const secret = Buffer.from('some secret bytes that are long enough')
    const s1 = splitSecret(secret, 2, 3); const s2 = splitSecret(secret, 2, 3)
    const flipped = s1[0]!.replace(/.$/, (c) => (c === '0' ? '1' : '0'))
    assert.throws(() => parseShare(flipped), /damaged/)
    const body = s1[1]!.split(':'); body[5] = body[5]!.slice(0, -1) + (body[5]!.endsWith('A') ? 'B' : 'A')
    assert.throws(() => parseShare(body.join(':')), /damaged/)
    assert.throws(() => combineShares([s1[0]!, s2[1]!]), /different splits/)
    for (const bad of ['', 'hello', 'frenet-share:1:2:zz:1:AAAA:00000000', s1[0]!.replace('frenet-share:1', 'frenet-share:2')]) assert.throws(() => parseShare(bad))
    // a share whose checksum is valid but whose content was altered is caught by the secret's own hash
    const p = s1[0]!.split(':'); const data = Buffer.from(p[5]!, 'base64url'); data[0] ^= 0xff; p[5] = data.toString('base64url')
    const b = p.slice(0, 6).join(':')
    const rebuilt = `${b}:${createHash('sha256').update(b).digest('hex').slice(0, 8)}`
    assert.throws(() => combineShares([rebuilt, s1[1]!]), /do not combine to a valid secret/)
    // conflicting shares for one position
    assert.throws(() => combineShares([rebuilt, s1[0]!]), /two different shares/)
    // parameter limits
    assert.throws(() => splitSecret(secret, 1, 3)); assert.throws(() => splitSecret(secret, 4, 3)); assert.throws(() => splitSecret(secret, 2, 33))
    assert.throws(() => splitSecret(Buffer.alloc(0), 2, 3))
  })
})

describe('account recovery: encrypted backup', () => {
  it('round-trips under the right passphrase and refuses everything else', async () => {
    const key = await generateKeyPair('Ed25519'); const bytes = privateKeyToProtobuf(key)
    const text = await createBackup(bytes, 'correct horse battery staple', fast)
    assert.match(text, /^frenet-backup:v1:[A-Za-z0-9_-]+$/)
    assert.ok(!text.includes(Buffer.from(bytes).toString('base64')), 'key is not in the clear')
    const back = await openBackup(text, 'correct horse battery staple')
    assert.deepEqual(back.protobuf, new Uint8Array(bytes)); assert.equal(back.peerId, peerIdFromPrivateKey(key).toString()); assert.equal(back.did, didFromPublicKeyRaw(key.publicKey.raw))
    await assert.rejects(openBackup(text, 'correct horse battery stapl3'), /wrong passphrase or corrupted/)
    await assert.rejects(openBackup(text + '\n  ', 'wrong passphrase here!'), /wrong passphrase or corrupted/)
    assert.ok(await openBackup(`  ${text}\n`, 'correct horse battery staple'))   // surrounding whitespace is fine
    assert.notEqual(text, await createBackup(bytes, 'correct horse battery staple', fast), 'fresh salt and nonce every time')
    await assert.rejects(createBackup(bytes, 'short', fast), /at least 12/)
    await assert.rejects(createBackup(bytes, 'long enough passphrase', { N: 2 ** 30 }), /invalid scrypt cost/)
    await assert.rejects(createBackup(new Uint8Array(10), 'long enough passphrase', fast), /not a valid identity key/)
  })

  it('authenticates its header and bounds the work an untrusted file can demand', async () => {
    const key = await generateKeyPair('Ed25519')
    const text = await createBackup(privateKeyToProtobuf(key), 'a perfectly fine passphrase', fast)
    const doc = JSON.parse(Buffer.from(text.slice('frenet-backup:v1:'.length), 'base64url').toString())
    const wrap = (d: object): string => 'frenet-backup:v1:' + Buffer.from(JSON.stringify(d)).toString('base64url')
    await assert.rejects(openBackup(wrap({ ...doc, peer: 'someone-else' }), 'a perfectly fine passphrase'), /wrong passphrase or corrupted/)   // header is in the AAD
    await assert.rejects(openBackup(wrap({ ...doc, N: 2 ** 20 }), 'a perfectly fine passphrase'), /unsupported or corrupted/)
    await assert.rejects(openBackup(wrap({ ...doc, N: 3 }), 'a perfectly fine passphrase'), /unsupported or corrupted/)
    await assert.rejects(openBackup(wrap({ ...doc, kdf: 'pbkdf2' }), 'a perfectly fine passphrase'), /unsupported or corrupted/)
    await assert.rejects(openBackup('hello', 'a perfectly fine passphrase'), /not a FRENET backup/)
    await assert.rejects(openBackup('frenet-backup:v1:!!!', 'a perfectly fine passphrase'), /not a FRENET backup/)
    const ct = Buffer.from(doc.ct, 'base64'); ct[0] ^= 1
    await assert.rejects(openBackup(wrap({ ...doc, ct: ct.toString('base64') }), 'a perfectly fine passphrase'), /wrong passphrase or corrupted/)
  })

  it('works at the default scrypt cost', async () => {
    const key = await generateKeyPair('Ed25519'); const bytes = privateKeyToProtobuf(key)
    assert.deepEqual((await openBackup(await createBackup(bytes, 'default cost passphrase'), 'default cost passphrase')).protobuf, new Uint8Array(bytes))
  })
})

describe('account recovery: restoring the identity', () => {
  it('installs with 0600, is idempotent, and never silently replaces a different key', async () => {
    const dir = tmp()
    const a = privateKeyToProtobuf(await generateKeyPair('Ed25519'))
    const b = privateKeyToProtobuf(await generateKeyPair('Ed25519'))
    const r1 = installKey(join(dir, 'fresh'), a)
    assert.equal(r1.unchanged, false); assert.equal(r1.replaced, null)
    const file = join(dir, 'fresh', 'identity.key')
    assert.equal(statSync(file).mode & 0o777, 0o600)
    assert.deepEqual(new Uint8Array(readFileSync(file)), new Uint8Array(a))
    assert.equal(installKey(join(dir, 'fresh'), a).unchanged, true)
    assert.throws(() => installKey(join(dir, 'fresh'), b), /different identity/)
    assert.deepEqual(new Uint8Array(readFileSync(file)), new Uint8Array(a), 'refusal leaves the key untouched')
    const r2 = installKey(join(dir, 'fresh'), b, { force: true })
    assert.ok(r2.replaced && existsSync(r2.replaced)); assert.equal(statSync(r2.replaced!).mode & 0o777, 0o600)
    assert.deepEqual(new Uint8Array(readFileSync(r2.replaced!)), new Uint8Array(a), 'old key is kept')
    assert.deepEqual(new Uint8Array(readFileSync(file)), new Uint8Array(b))
    assert.deepEqual(readdirSync(join(dir, 'fresh')).filter((f) => f.includes('.tmp-')), [])
    assert.throws(() => installKey(join(dir, 'x'), new Uint8Array(5)), /not a valid identity key/)
  })

  it('a node started on a restored key has the same peer ID, DID and publisher key (from backup and from shares)', async () => {
    const src = tmp()
    const original = await startFrenet({ dataDir: src, listen: ['/ip4/127.0.0.1/tcp/0'], mdns: false, nat: false })
    const peerId = original.libp2p.peerId.toString(); const did = original.did; const publisher = original.names.publisherKey
    await original.stop()
    const bytes = new Uint8Array(readFileSync(join(src, 'identity.key')))

    for (const how of ['backup', 'shares'] as const) {
      const dst = tmp()
      const recovered = how === 'backup'
        ? (await openBackup(await createBackup(bytes, 'recovery test passphrase', fast), 'recovery test passphrase')).protobuf
        : combineShares(splitSecret(bytes, 3, 5).slice(1, 4))
      installKey(dst, recovered)
      const n = await startFrenet({ dataDir: dst, listen: ['/ip4/127.0.0.1/tcp/0'], mdns: false, nat: false })
      nodes.push(n)
      assert.equal(n.libp2p.peerId.toString(), peerId, how); assert.equal(n.did, did, how); assert.equal(n.names.publisherKey, publisher, how)
      // the recovered identity can still sign: a credential it issues verifies under the original DID
      const issued = await n.credentials.issue(did, 'Recovered', { ok: true })
      const v = await verifyCredential(issued.jwt)
      assert.ok(v.valid && v.credential.issuer === did)
      await n.stop()
    }
    // restoring after a total loss lets the node keep updating its names: Names.publish re-reads the network seq (existing behaviour)
  })
})

describe('account recovery: CLI', () => {
  const cli = (args: string[], opts: { input?: string } = {}) => spawnSync(process.execPath, ['--import', 'tsx', 'src/cli.ts', ...args], { encoding: 'utf8', input: opts.input, cwd: process.cwd(), timeout: 60_000 })

  it('identity, backup, restore, split and recovery restore work end to end', async () => {
    const a = tmp(); const b = tmp(); const c = tmp(); const out = tmp()
    const { key } = await loadOrCreateIdentity(a)
    const peerId = peerIdFromPrivateKey(key).toString()
    const pw = join(out, 'pw'); writeFileSync(pw, 'cli passphrase for tests\n', { mode: 0o600 })

    const id = cli(['identity', '--data', a])
    assert.equal(id.status, 0, id.stderr); assert.match(id.stdout, new RegExp(peerId)); assert.match(id.stdout, /DID\s+did:key:z6Mk/)
    assert.equal(cli(['identity', '--data', join(out, 'none')]).status, 1)

    const backup = join(out, 'id.backup')
    const bk = cli(['backup', '--data', a, '--out', backup, '--passphrase-file', pw])
    assert.equal(bk.status, 0, bk.stderr); assert.equal(statSync(backup).mode & 0o777, 0o600)
    assert.ok(!readFileSync(backup, 'utf8').includes(Buffer.from(readFileSync(join(a, 'identity.key'))).toString('base64')))
    assert.equal(cli(['backup', '--data', a, '--out', backup, '--passphrase-file', pw]).status, 1, 'never overwrites an existing backup')

    writeFileSync(join(out, 'bad'), 'wrong passphrase!!\n')
    assert.equal(cli(['restore', backup, '--data', b, '--passphrase-file', join(out, 'bad')]).status, 1)
    assert.ok(!existsSync(join(b, 'identity.key')))
    const rs = cli(['restore', backup, '--data', b, '--passphrase-file', pw])
    assert.equal(rs.status, 0, rs.stderr); assert.match(rs.stdout, new RegExp(peerId))
    assert.deepEqual(readFileSync(join(b, 'identity.key')), readFileSync(join(a, 'identity.key')))

    const split = cli(['recovery', 'split', '-k', '2', '-n', '3', '--data', a])
    assert.equal(split.status, 0, split.stderr)
    const shares = split.stdout.trim().split('\n'); assert.equal(shares.length, 3)
    assert.match(split.stderr, /any 2 recover/)
    const viaStdin = cli(['recovery', 'restore', '--data', c], { input: `${shares[2]}\n${shares[0]}\n` })
    assert.equal(viaStdin.status, 0, viaStdin.stderr)
    assert.deepEqual(readFileSync(join(c, 'identity.key')), readFileSync(join(a, 'identity.key')))
    const tooFew = cli(['recovery', 'restore', '--data', tmp(), shares[1]!])
    assert.equal(tooFew.status, 1); assert.match(tooFew.stderr, /need 2 shares, got 1/)
    const d = tmp()
    const viaArgs = cli(['recovery', 'restore', '--data', d, shares[0]!, shares[1]!])
    assert.equal(viaArgs.status, 0, viaArgs.stderr)
    // a different identity needs --force
    const e = tmp(); await loadOrCreateIdentity(e)
    assert.equal(cli(['recovery', 'restore', '--data', e, shares[0]!, shares[1]!]).status, 1)
    const forced = cli(['recovery', 'restore', '--data', e, '--force', shares[0]!, shares[1]!])
    assert.equal(forced.status, 0, forced.stderr); assert.match(forced.stdout, /Previous key kept/)
    assert.deepEqual(readFileSync(join(e, 'identity.key')), readFileSync(join(a, 'identity.key')))
  })
})

// ---------------------------------------------------------------------------------------------------------------
describe('DID and credential local API', () => {
  it('serves identity, resolves DIDs, and runs the issue / hold / present / verify / revoke flow', async () => {
    const issuer = await startFrenet({ dataDir: ':memory:', listen: ['/ip4/127.0.0.1/tcp/0'], mdns: false, nat: false }); nodes.push(issuer)
    const holder = await startFrenet({ dataDir: ':memory:', listen: ['/ip4/127.0.0.1/tcp/0'], mdns: false, nat: false }); nodes.push(holder)
    const ia = await startApi(issuer, 0); const ha = await startApi(holder, 0)
    const mk = (port: number) => async (path: string, body?: unknown) => {
      const r = await fetch(`http://127.0.0.1:${port}${path}`, body === undefined ? undefined : { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) })
      return { status: r.status, json: await r.json() as any }
    }
    const I = mk(ia.port); const H = mk(ha.port)
    try {
      const me = await H('/api/identity')
      assert.equal(me.json.peerId, holder.libp2p.peerId.toString()); assert.equal(me.json.did, holder.did); assert.equal(me.json.document.id, holder.did)
      assert.equal((await H('/api/status')).json.did, holder.did)
      assert.equal((await I(`/api/did/resolve?peer=${holder.libp2p.peerId.toString()}`)).json.id, holder.did)
      assert.equal((await I(`/api/did/resolve?did=${encodeURIComponent(holder.did)}`)).json.id, holder.did)
      assert.equal((await I('/api/did/resolve?did=did:web:x.example')).status, 400)

      const issued = await I('/api/credentials/issue', { subject: holder.libp2p.peerId.toString(), type: 'Membership', claims: { club: 'frenet' }, ttlDays: 30 })
      assert.equal(issued.status, 200)
      const { id, jwt } = issued.json
      assert.equal((await I('/api/credentials/issue', { subject: 'nope', type: 'Membership', claims: {} })).status, 400)
      assert.equal((await H('/api/credentials/verify', { jwt })).json.valid, true)
      assert.equal((await H('/api/credentials/import', { jwt })).status, 200)
      assert.equal((await I('/api/credentials/import', { jwt })).status, 400, 'issuer cannot import a credential about someone else')
      const listed = (await H('/api/credentials')).json
      assert.equal(listed.credentials.length, 1); assert.equal(listed.credentials[0].role, 'held'); assert.equal(listed.credentials[0].id, id)

      const vp = await H('/api/presentations/create', { credentials: [id], nonce: 'abc123', audience: 'issuer-node' })
      assert.equal(vp.status, 200)
      assert.equal((await I('/api/presentations/verify', { jwt: vp.json.jwt, nonce: 'abc123', audience: 'issuer-node' })).json.valid, true)
      assert.equal((await I('/api/presentations/verify', { jwt: vp.json.jwt, nonce: 'other', audience: 'issuer-node' })).json.valid, false)

      const rev = await I('/api/credentials/revoke', { id })
      assert.equal(rev.status, 200)
      assert.equal((await I('/api/credentials/verify', { jwt })).json.valid, false)
      assert.equal((await H('/api/credentials/verify', { jwt })).json.valid, true, 'holder has not seen the revocation yet')
      assert.equal((await H('/api/credentials/revocations', { jwt: rev.json.jwt })).status, 200)
      assert.equal((await H('/api/credentials/verify', { jwt })).json.error, 'revoked')
      assert.equal((await H('/api/credentials')).json.credentials[0].revoked, true)
      assert.equal((await H('/api/presentations/create', { credentials: [id], nonce: 'abc123' })).status, 400)
      assert.equal((await H('/api/credentials/revocations', { jwt })).status, 400)
      // key material is not reachable over HTTP
      for (const p of ['/api/identity/key', '/api/backup', '/api/recovery']) assert.notEqual((await H(p)).status, 200)
    } finally { ia.server.close(); ha.server.close() }
  })
})
