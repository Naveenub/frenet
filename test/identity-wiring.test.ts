import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { after, describe, it } from 'node:test'
import { generateKeyPair } from '@libp2p/crypto/keys'
import type { PrivateKey } from '@libp2p/interface'
import { base58btc } from 'multiformats/bases/base58'
import { startApi } from '../src/api.js'
import { didFromPublicKeyRaw } from '../src/did.js'
import { initRotation } from '../src/rotation.js'
import { startFrenet, type FrenetNode } from '../src/node.js'
import { signHandleProof, type JsonFetcher } from '../src/webid.js'

const L = ['/ip4/127.0.0.1/tcp/0']
const dirs: string[] = []
const nodes: FrenetNode[] = []
const apis: Array<{ server: { close: () => unknown, closeAllConnections?: () => void } }> = []
after(async () => {
  for (const a of apis) { a.server.closeAllConnections?.(); a.server.close() }
  for (const n of nodes) await n.stop().catch(() => {})
  for (const d of dirs) rmSync(d, { recursive: true, force: true })
})

const multikey = (k: PrivateKey): string => base58btc.encode(Uint8Array.from([0xed, 0x01, ...k.publicKey.raw]))
const b64 = (x: object): string => Buffer.from(JSON.stringify(x)).toString('base64url')
async function jwt (k: PrivateKey, header: object, payload: object): Promise<string> {
  const input = `${b64(header)}.${b64(payload)}`
  return `${input}.${Buffer.from(await k.sign(Buffer.from(input))).toString('base64url')}`
}
async function boot (dataDir: string, files: Record<string, unknown> = {}): Promise<{ n: FrenetNode, get: (p: string) => Promise<{ status: number, json: any }>, files: Record<string, unknown> }> {
  const fetchJson: JsonFetcher = async (url) => {
    const f = files[url.toString()]
    if (f === undefined) throw new Error('unexpected HTTP status 404')
    return f
  }
  const n = await startFrenet({ dataDir, listen: L, mdns: false, nat: false, fetchJson }); nodes.push(n)
  const api = await startApi(n, 0); apis.push(api)
  const get = async (p: string): Promise<{ status: number, json: any }> => { const r = await fetch(`http://127.0.0.1:${api.port}${p}`); return { status: r.status, json: await r.json() as any } }
  return { n, get, files }
}

describe('did:web and handles are wired into the node', () => {
  it('resolves did:web and handles over the API, pins handles on first use, refuses silent changes', async () => {
    const alice = await generateKeyPair('Ed25519')
    const eve = await generateKeyPair('Ed25519')
    const aliceDid = didFromPublicKeyRaw(alice.publicKey.raw)
    const eveDid = didFromPublicKeyRaw(eve.publicKey.raw)
    const web = 'did:web:example.com'
    const files: Record<string, unknown> = {
      'https://example.com/.well-known/did.json': { id: web, verificationMethod: [{ id: `${web}#k`, type: 'Multikey', controller: web, publicKeyMultibase: multikey(alice) }], authentication: [`${web}#k`], assertionMethod: [`${web}#k`] },
      'https://example.com/.well-known/frenet-names.json': { v: 1, names: { alice: { did: aliceDid, proof: await signHandleProof(alice, 'alice@example.com', aliceDid) } } }
    }
    const { n, get } = await boot(':memory:', files)

    assert.equal((await get(`/api/did/resolve?did=${encodeURIComponent(web)}`)).json.id, web)
    assert.equal((await get('/api/did/resolve?did=did:web:nowhere.example')).status, 400)

    const first = await get('/api/handles/resolve?handle=Alice@Example.com&requireProof=1')
    assert.equal(first.status, 200)
    assert.deepEqual(first.json, { handle: 'alice@example.com', did: aliceDid, domain: 'example.com', proof: 'verified', pin: 'new' })
    assert.deepEqual((await get('/api/handles')).json.pins.map((p: any) => [p.handle, p.did]), [['alice@example.com', aliceDid]])

    // the domain silently re-points the handle at another key: refused, pin kept
    files['https://example.com/.well-known/frenet-names.json'] = { v: 1, names: { alice: eveDid } }
    const changed = await get('/api/handles/resolve?handle=alice@example.com&fresh=1')
    assert.equal(changed.status, 409); assert.equal(changed.json.pinned, aliceDid); assert.equal(changed.json.now, eveDid)
    assert.equal(n.store.getHandlePin('alice@example.com'), aliceDid)
    assert.equal((await get('/api/handles/resolve?handle=alice@example.com&fresh=1&repin=1')).json.pin, 'repinned')
    assert.equal((await get('/api/handles/resolve?handle=nobody@example.com')).status, 400)
    assert.equal((await get('/api/handles/resolve?handle=not-a-handle')).status, 400)
  })

  it('this node verifies a credential issued by a did:web (it used to reject all of them)', async () => {
    const issuer = await generateKeyPair('Ed25519')
    const did = 'did:web:issuer.example'
    const files = { 'https://issuer.example/.well-known/did.json': { id: did, verificationMethod: [{ id: `${did}#k`, type: 'Multikey', controller: did, publicKeyMultibase: multikey(issuer) }], authentication: [`${did}#k`], assertionMethod: [`${did}#k`] } }
    const { n } = await boot(':memory:', files)
    const now = Math.floor(Date.now() / 1000)
    const payload = { iss: did, sub: n.did, jti: 'urn:uuid:wired-1', iat: now, nbf: now, vc: { '@context': ['https://www.w3.org/2018/credentials/v1'], type: ['VerifiableCredential', 'Member'], credentialSubject: { role: 'admin' } } }
    const good = await jwt(issuer, { alg: 'EdDSA', typ: 'JWT', kid: `${did}#k` }, payload)
    const r = await n.credentials.verify(good)
    assert.equal(r.valid, true, JSON.stringify(r))
    const stranger = await generateKeyPair('Ed25519')
    assert.equal((await n.credentials.verify(await jwt(stranger, { alg: 'EdDSA', typ: 'JWT', kid: `${did}#k` }, payload))).valid, false)
  })

  it('a rotatable identity serves its own DID document and key log over the API', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'frenet-idw-')); dirs.push(dir)
    const first = await startFrenet({ dataDir: dir, listen: L, mdns: false, nat: false })
    await first.stop()
    const { state } = await initRotation(dir, 'next key passphrase 1', { N: 2 ** 10 })
    const { n, get } = await boot(dir)
    assert.equal(n.did, state.did)
    const me = await get('/api/identity')
    assert.equal(me.status, 200)
    assert.equal(me.json.did, state.did); assert.equal(me.json.keyDid, n.keyDid); assert.equal(me.json.document.id, state.did)
    assert.equal(me.json.document.rotation.seq, 0)
    const log = await get('/api/identity/log')
    assert.equal(log.json.did, state.did); assert.equal(log.json.events.length, 1)
    const res = await get(`/api/did/resolve?did=${encodeURIComponent(state.did)}`)
    assert.equal(res.status, 200); assert.equal(res.json.id, state.did)
  })

  it('a fixed-key identity has no key log', async () => {
    const { get } = await boot(':memory:')
    assert.equal((await get('/api/identity/log')).status, 404)
    assert.equal((await get('/api/did/resolve?did=did:frenet:' + 'a'.repeat(52))).status, 404)   // unknown identity: no log anywhere
  })
})
