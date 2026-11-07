import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import { generateKeyPair } from '@libp2p/crypto/keys'
import type { PrivateKey } from '@libp2p/interface'
import { base58btc } from 'multiformats/bases/base58'
import { verifyCredential } from '../src/credentials.js'
import { didFromPublicKeyRaw, toDid } from '../src/did.js'
import { createInception, createRotation } from '../src/identity-log.js'
import { HandleChanged, Handles, httpsJson, isNonPublicAddress, isWebDid, parseWebDidDocument, signHandleProof, webDidUrl, WebDids, type JsonFetcher } from '../src/webid.js'

const multikey = (k: PrivateKey): string => base58btc.encode(Uint8Array.from([0xed, 0x01, ...k.publicKey.raw]))
const docFor = (did: string, k: PrivateKey, extra: object = {}): object => ({
  id: did,
  verificationMethod: [{ id: `${did}#key-1`, type: 'Multikey', controller: did, publicKeyMultibase: multikey(k) }],
  authentication: [`${did}#key-1`],
  assertionMethod: [`${did}#key-1`],
  ...extra
})
const serve = (files: Record<string, unknown>): JsonFetcher => async (url) => {
  const f = files[url.toString()]
  if (f === undefined) throw new Error('unexpected HTTP status 404')
  return f
}
const b64 = (x: object): string => Buffer.from(JSON.stringify(x)).toString('base64url')
async function jwt (k: PrivateKey, header: object, payload: object): Promise<string> {
  const input = `${b64(header)}.${b64(payload)}`
  return `${input}.${Buffer.from(await k.sign(Buffer.from(input))).toString('base64url')}`
}

describe('did:web', () => {
  it('maps DIDs to URLs and rejects ports, IPs, traversal and uppercase', () => {
    assert.equal(webDidUrl('did:web:example.com').toString(), 'https://example.com/.well-known/did.json')
    assert.equal(webDidUrl('did:web:example.com:users:alice').toString(), 'https://example.com/users/alice/did.json')
    for (const bad of ['did:web:example.com%3A8443', 'did:web:127.0.0.1', 'did:web:localhost', 'did:web:Example.com', 'did:web:example.com:..:x', 'did:web:example.com:a/b', 'did:web:', 'did:web:a..com']) assert.equal(isWebDid(bad), false, bad)
    assert.throws(() => webDidUrl('did:web:localhost'))
  })

  it('accepts a well-formed document and rejects a mismatched id, wrong key type and no keys', async () => {
    const k = await generateKeyPair('Ed25519')
    const did = 'did:web:example.com'
    assert.equal(parseWebDidDocument(did, docFor(did, k)).keys.length, 1)
    assert.throws(() => parseWebDidDocument(did, docFor('did:web:evil.com', k)), /name this DID/)
    assert.throws(() => parseWebDidDocument(did, { ...docFor(did, k), verificationMethod: [{ id: `${did}#k`, type: 'Multikey', controller: did, publicKeyMultibase: 'zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme' }] }), /no Ed25519/)
    assert.throws(() => parseWebDidDocument(did, { id: did, verificationMethod: [] }), /no usable/)
    const jwk = { id: did, verificationMethod: [{ id: '#j', type: 'JsonWebKey2020', controller: did, publicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x: Buffer.from(k.publicKey.raw).toString('base64url') } }], assertionMethod: ['#j'] }
    assert.equal(parseWebDidDocument(did, jwk).keys[0]!.kid, `${did}#j`)
  })

  it('verifies a VC-JWT issued by a did:web, and rejects forgeries and unauthorised keys', async () => {
    const issuer = await generateKeyPair('Ed25519')
    const other = await generateKeyPair('Ed25519')
    const did = 'did:web:example.com'
    const url = 'https://example.com/.well-known/did.json'
    const web = new WebDids(serve({ [url]: docFor(did, issuer) }))
    const sub = didFromPublicKeyRaw(other.publicKey.raw)
    const now = Math.floor(Date.now() / 1000)
    const payload = { iss: did, sub, jti: 'urn:uuid:1', iat: now, nbf: now, vc: { '@context': ['https://www.w3.org/2018/credentials/v1'], type: ['VerifiableCredential', 'Member'], credentialSubject: { role: 'admin' } } }
    const good = await jwt(issuer, { alg: 'EdDSA', typ: 'JWT', kid: `${did}#key-1` }, payload)
    const r = await verifyCredential(good, { web })
    assert.equal(r.valid, true)
    if (r.valid) assert.equal(r.credential.issuer, did)
    assert.equal((await verifyCredential(good, {})).valid, false)                                                    // no resolver: refused
    const forged = await jwt(other, { alg: 'EdDSA', typ: 'JWT', kid: `${did}#key-1` }, payload)                     // signed by a key the domain does not list
    assert.equal((await verifyCredential(forged, { web })).valid, false)
    const badKid = await jwt(issuer, { alg: 'EdDSA', typ: 'JWT', kid: `${did}#nope` }, payload)
    assert.equal((await verifyCredential(badKid, { web })).valid, false)
    const web2 = new WebDids(serve({ [url]: docFor(did, issuer, { authentication: [], assertionMethod: [] }) }))   // key listed but not authorised
    assert.equal((await verifyCredential(good, { web: web2 })).valid, false)
  })

  it('accepts did:web as a subject DID', () => {
    assert.equal(toDid('did:web:example.com'), 'did:web:example.com')
  })
})

describe('SSRF guard', () => {
  it('classifies non-public addresses', () => {
    for (const a of ['127.0.0.1', '10.1.2.3', '192.168.0.1', '172.16.5.5', '169.254.169.254', '100.64.0.1', '0.0.0.0', '::1', 'fe80::1', 'fd00::1', '::ffff:127.0.0.1', '::ffff:10.0.0.1', 'not-an-ip']) assert.equal(isNonPublicAddress(a), true, a)
    for (const a of ['93.184.216.34', '8.8.8.8', '2606:4700:4700::1111', '::ffff:8.8.8.8']) assert.equal(isNonPublicAddress(a), false, a)
  })
  it('the default fetcher refuses http, ports, credentials, IPs and localhost without any request', async () => {
    for (const u of ['http://example.com/x', 'https://example.com:8443/x', 'https://user:pw@example.com/x', 'https://127.0.0.1/x', 'https://localhost/x']) await assert.rejects(httpsJson(new URL(u)), /refused/, u)
  })
})

describe('handles (alice@example.com)', () => {
  const NAMES = 'https://example.com/.well-known/frenet-names.json'
  it('resolves a plain entry and a consented entry; a wrong proof is an error', async () => {
    const alice = await generateKeyPair('Ed25519')
    const bob = await generateKeyPair('Ed25519')
    const aliceDid = didFromPublicKeyRaw(alice.publicKey.raw)
    const bobDid = didFromPublicKeyRaw(bob.publicKey.raw)
    const proof = await signHandleProof(alice, 'alice@example.com', aliceDid)
    const files = { [NAMES]: { v: 1, names: { alice: { did: aliceDid, proof }, bob: bobDid, mallory: { did: bobDid, proof }, carol: { did: aliceDid, proof: 'A'.repeat(86) } } } }
    const fetchJson = serve(files)
    const h = new Handles(new WebDids(fetchJson), { fetchJson })
    assert.deepEqual(await h.resolve('alice@example.com'), { handle: 'alice@example.com', did: aliceDid, domain: 'example.com', proof: 'verified', pin: 'off' })
    assert.deepEqual(await h.resolve('@Alice@Example.com', { fresh: true }), { handle: 'alice@example.com', did: aliceDid, domain: 'example.com', proof: 'verified', pin: 'off' })
    assert.equal((await h.resolve('bob@example.com')).proof, 'none')
    await assert.rejects(h.resolve('bob@example.com', { requireProof: true, fresh: true }), /no consent proof/)
    await assert.rejects(h.resolve('mallory@example.com'), /does not match/)                 // domain tried to hand alice's proof to bob's key
    await assert.rejects(h.resolve('carol@example.com'), /does not match/)
  })

  it('rejects malformed handles, missing names, prototype keys and bad documents', async () => {
    const k = await generateKeyPair('Ed25519')
    const did = didFromPublicKeyRaw(k.publicKey.raw)
    const fetchJson = serve({
      [NAMES]: { v: 1, names: { alice: did, evil: 'did:example:123' } },
      'https://bad.example/.well-known/frenet-names.json': { v: 2, names: {} }
    })
    const h = new Handles(new WebDids(fetchJson), { fetchJson })
    for (const bad of ['alice', 'alice@localhost', 'alice@127.0.0.1', '@@example.com', 'a b@example.com', 'alice@example.com/x']) await assert.rejects(h.resolve(bad), /invalid handle/, bad)
    await assert.rejects(h.resolve('nobody@example.com'), /not found/)
    await assert.rejects(h.resolve('__proto__@example.com'), /invalid handle/)
    await assert.rejects(h.resolve('constructor@example.com'), /not found/)
    await assert.rejects(h.resolve('evil@example.com'), /unsupported DID/)
    await assert.rejects(h.resolve('x@bad.example'), /no valid frenet-names/)
  })

  it('verifies the consent proof of a did:web target through its document', async () => {
    const k = await generateKeyPair('Ed25519')
    const did = 'did:web:alice.example'
    const proof = await signHandleProof(k, 'alice@example.com', did)
    const fetchJson = serve({ [NAMES]: { v: 1, names: { alice: { did, proof } } }, 'https://alice.example/.well-known/did.json': docFor(did, k) })
    const h = new Handles(new WebDids(fetchJson), { fetchJson })
    assert.equal((await h.resolve('alice@example.com')).proof, 'verified')
  })
})

describe('handle pinning (trust on first use)', () => {
  const NAMES = 'https://example.com/.well-known/frenet-names.json'
  it('pins the first DID, refuses a silent change, and accepts it only with repin', async () => {
    const a = await generateKeyPair('Ed25519'); const b = await generateKeyPair('Ed25519')
    const da = didFromPublicKeyRaw(a.publicKey.raw); const db = didFromPublicKeyRaw(b.publicKey.raw)
    const files: Record<string, unknown> = { [NAMES]: { v: 1, names: { alice: da } } }
    const fetchJson: JsonFetcher = async (u) => files[u.toString()]
    const pins = new Map<string, string>()
    const h = new Handles(new WebDids(fetchJson), { fetchJson, pins: { get: (k) => pins.get(k) ?? null, set: (k, v) => { pins.set(k, v) } } })
    assert.equal((await h.resolve('alice@example.com', { fresh: true })).pin, 'new')
    assert.equal((await h.resolve('alice@example.com', { fresh: true })).pin, 'match')
    files[NAMES] = { v: 1, names: { alice: db } }                                               // domain re-points the handle
    await assert.rejects(h.resolve('alice@example.com', { fresh: true }), (e: unknown) => e instanceof HandleChanged && e.pinned === da && e.now === db)
    assert.equal(pins.get('alice@example.com'), da)                                              // a failed check never moves the pin
    assert.equal((await h.resolve('alice@example.com', { repin: true })).pin, 'repinned')
    assert.equal(pins.get('alice@example.com'), db)
  })
})

describe('handle proofs for did:frenet', () => {
  const NAMES = 'https://example.com/.well-known/frenet-names.json'
  it('verifies against the current key epoch and dies on rotation until re-signed', async () => {
    const k0 = await generateKeyPair('Ed25519'); const k1 = await generateKeyPair('Ed25519'); const k2 = await generateKeyPair('Ed25519'); const k3 = await generateKeyPair('Ed25519')
    const s0 = await createInception(k0, k1.publicKey)
    const proof0 = await signHandleProof(k0, 'alice@example.com', s0.did)
    let state = s0
    const files: Record<string, unknown> = { [NAMES]: { v: 1, names: { alice: { did: s0.did, proof: proof0, kseq: 0 } } } }
    const fetchJson: JsonFetcher = async (u) => files[u.toString()]
    const h = new Handles(new WebDids(fetchJson), { fetchJson, resolveLog: async (id) => (id === state.id ? state : null) })
    assert.equal((await h.resolve('alice@example.com', { fresh: true })).proof, 'verified')
    files[NAMES] = { v: 1, names: { alice: { did: s0.did, proof: proof0, kseq: 1 } } }          // wrong epoch claimed
    await assert.rejects(h.resolve('alice@example.com', { fresh: true }), /superseded|again|does not match/)
    files[NAMES] = { v: 1, names: { alice: { did: s0.did, proof: proof0 } } }                   // epoch missing
    await assert.rejects(h.resolve('alice@example.com', { fresh: true }), /key epoch/)
    state = await createRotation(s0, k1, k2.publicKey)                                          // rotate: the old proof (and old key) no longer vouch
    files[NAMES] = { v: 1, names: { alice: { did: s0.did, proof: proof0, kseq: 0 } } }
    await assert.rejects(h.resolve('alice@example.com', { fresh: true }), /superseded/)
    const proof1 = await signHandleProof(k1, 'alice@example.com', s0.did)
    files[NAMES] = { v: 1, names: { alice: { did: s0.did, proof: proof1, kseq: 1 } } }
    assert.equal((await h.resolve('alice@example.com', { fresh: true })).proof, 'verified')
    const stolen = await signHandleProof(k0, 'alice@example.com', s0.did)                       // old key re-signing at the new epoch
    files[NAMES] = { v: 1, names: { alice: { did: s0.did, proof: stolen, kseq: 1 } } }
    await assert.rejects(h.resolve('alice@example.com', { fresh: true }), /does not match/)
    void k3
    const noLog = new Handles(new WebDids(fetchJson), { fetchJson })
    files[NAMES] = { v: 1, names: { alice: { did: s0.did, proof: proof1, kseq: 1 } } }
    await assert.rejects(noLog.resolve('alice@example.com'), /no key log resolver/)
  })
})
