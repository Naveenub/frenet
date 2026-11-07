import assert from 'node:assert/strict'
import { after, describe, it } from 'node:test'
import { generateKeyPair } from '@libp2p/crypto/keys'
import { CID } from 'multiformats/cid'
import * as raw from 'multiformats/codecs/raw'
import { create as createDigest } from 'multiformats/hashes/digest'
import { mkdtempSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { privateKeyToProtobuf } from '@libp2p/crypto/keys'
import { cidFor, verify } from '../src/blocks.js'
import { loadOrCreateIdentity } from '../src/identity.js'
import { startFrenet, type FrenetNode } from '../src/node.js'

const nodes: FrenetNode[] = []
const track = async (o: Partial<Parameters<typeof startFrenet>[0]> = {}) => { const n = await startFrenet({ dataDir: ':memory:', listen: ['/ip4/127.0.0.1/tcp/0'], mdns: false, nat: false, quic: false, ...o }); nodes.push(n); return n }
after(async () => { for (const n of nodes) await n.stop() })

describe('core architecture', () => {
  it('the DHT accepts provider records only: value records are refused', async () => {
    const n = await track()
    const dht = (n.libp2p.services as any).dht
    const key = new TextEncoder().encode('/pk/anything')
    await assert.rejects(dht.validators.pk(key, new Uint8Array(32)), /provider records only/)
    await assert.rejects(dht.selectors.pk(key, []), /provider records only/)
  })

  it('uses Ed25519 identities only', async () => {
    const n = await track()
    assert.equal(n.libp2p.peerId.type, 'Ed25519')
    const rsa = await generateKeyPair('secp256k1')
    await assert.rejects(startFrenet({ dataDir: ':memory:', listen: ['/ip4/127.0.0.1/tcp/0'], mdns: false, nat: false, quic: false, privateKey: rsa }), /must be Ed25519/)
    const dir = mkdtempSync(join(tmpdir(), 'frenet-id-'))
    writeFileSync(join(dir, 'identity.key'), privateKeyToProtobuf(rsa))
    await assert.rejects(loadOrCreateIdentity(dir), /must be Ed25519/)
  })

  it('content addressing: blocks are CIDv1 raw + sha2-256 and verified strictly', async () => {
    const data = new TextEncoder().encode('hello frenet')
    const cid = cidFor(data)
    assert.equal(cid.version, 1)
    assert.equal(cid.code, raw.code)
    assert.equal(cid.multihash.code, 0x12)
    const other = CID.createV1(0x70, createDigest(0x12, cid.multihash.digest))   // dag-pb codec, same hash
    assert.notEqual(other.toString(), cid.toString())
    assert.equal(verify(cid, data), true)
    assert.equal(verify(other, data), false, 'a CID with a different codec is not accepted for these bytes')
    const n = await track()
    assert.equal(n.blocks.putLocal(data).toString(), cid.toString())
  })
})
