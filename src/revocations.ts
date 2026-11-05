import type { Libp2p } from '@libp2p/interface'
import { cidFor } from './blocks.js'
import type { RevocationCheck } from './credentials.js'
import { MAX_REVOCATION_JWT } from './credentials.js'
import { RateLimiter } from './messaging.js'
import { ask, readJson } from './rpc.js'
import type { Store } from './store.js'

/**
 * Revocation distribution. A revocation is a small statement signed by the issuer (see credentials.ts). It spreads
 * three ways, none of which needs a server:
 *  - the issuer pushes it to every peer it is connected to when it revokes (`/frenet/revoke/1.0.0`, `put`),
 *  - the issuer and every node that has accepted it announce a DHT provider record under
 *    `frenet-revoke/v1\n<issuer>\n<credential id>`, so
 *  - a verifier can *pull*: ask the providers of that key (`get`) whether a given credential was revoked.
 * Everything received is signature-checked against the issuer's DID before it is stored, so peers cannot forge
 * revocations for credentials they did not issue, and a statement can only ever affect its own issuer's credentials.
 *
 * Limits: absence is not proof. A verifier that cannot reach any provider (or an issuer that was offline while
 * revoking and has no peers) cannot learn of a revocation, so a credential check is "not known revoked", not
 * "known good". The lookup reveals to DHT neighbours which credential you are checking (verifiers can disable it).
 */
export const REVOKE_PROTOCOL = '/frenet/revoke/1.0.0'
const MAX_REQUEST_BYTES = MAX_REVOCATION_JWT + 256
const MAX_RESPONSE_BYTES = MAX_REVOCATION_JWT + 64
const PROVIDERS_PER_LOOKUP = 8
const PUSH_FANOUT = 32
const LOOKUP_CACHE_MS = 60_000
const DID_RE = /^did:(key:z[1-9A-HJ-NP-Za-km-z]{40,60}|frenet:[a-z2-7]{52})$/
const ID_RE = /^[A-Za-z0-9:._-]{1,100}$/

const revokeCid = (issuer: string, id: string) => cidFor(Buffer.from(`frenet-revoke/v1\n${issuer}\n${id}`))

export class Revocations {
  private limiter = new RateLimiter(30, 3)
  private looked = new Map<string, number>()

  /** `verify` is injected (it needs the DID resolver) to keep this module free of credential internals. */
  constructor (private node: Libp2p, private store: Store, private verify: (jwt: unknown) => Promise<RevocationCheck>) {}

  async start (): Promise<void> {
    await this.node.handle(REVOKE_PROTOCOL, async (stream, connection) => {
      try {
        if (!this.limiter.allow(connection.remotePeer.toString())) { stream.abort(new Error('rate limited')); return }
        const req = await readJson(stream as any, MAX_REQUEST_BYTES)
        let out: unknown
        if (req?.k === 'get' && DID_RE.test(String(req.issuer)) && ID_RE.test(String(req.id))) {
          out = this.store.getRevocation(req.issuer, req.id)
        } else if (req?.k === 'put' && typeof req.jwt === 'string') {
          const r = await this.verify(req.jwt)
          if (r.valid) {
            const fresh = this.store.addRevocation(r.issuer, r.id, req.jwt)
            if (fresh) void this.announce(r.issuer, r.id)   // become a provider so others can pull it from us
          }
          out = r.valid
        } else { stream.abort(new Error('bad request')); return }
        stream.send(Buffer.from(JSON.stringify(out)))
        await stream.close()
      } catch { stream.abort(new Error('bad request')) }
    }, { maxInboundStreams: 32, maxOutboundStreams: 32, runOnLimitedConnection: true })
  }

  async stop (): Promise<void> { await this.node.unhandle(REVOKE_PROTOCOL) }

  async announce (issuer: string, id: string): Promise<boolean> {
    try { await this.node.contentRouting.provide(revokeCid(issuer, id), { signal: AbortSignal.timeout(5000) }); return true } catch { return false }
  }

  /** Record a verified statement locally and make it findable. Returns false if it was already known. */
  async accept (issuer: string, id: string, jwt: string, own = false): Promise<boolean> {
    const fresh = this.store.addRevocation(issuer, id, jwt, own)
    void this.announce(issuer, id)
    return fresh
  }

  /** Tell the peers we are connected to. Best effort: returns how many accepted it. */
  async push (jwt: string): Promise<number> {
    const peers = [...new Set(this.node.getConnections().map((c) => c.remotePeer))].slice(0, PUSH_FANOUT)
    let ok = 0
    const signal = AbortSignal.timeout(5000)
    await Promise.all(peers.map(async (peer) => {
      const r = await ask(this.node, { id: peer, multiaddrs: [] }, REVOKE_PROTOCOL, { k: 'put', jwt }, signal, 64)
      if (r === true) ok++
    }))
    return ok
  }

  /**
   * Pull: ask the providers of (issuer, credential id) whether a revocation exists. A statement is only accepted if it
   * verifies and is for exactly this issuer and id. Returns true if the credential is (now known to be) revoked.
   * Lookups are remembered for a minute so repeated verification does not hammer the DHT.
   */
  async lookup (issuer: string, id: string, timeoutMs = 3000): Promise<boolean> {
    if (this.store.isRevoked(issuer, id)) return true
    const k = `${issuer}\n${id}`
    if (Date.now() - (this.looked.get(k) ?? 0) < LOOKUP_CACHE_MS) return false
    this.looked.set(k, Date.now())
    if (this.looked.size > 5000) this.looked.delete(this.looked.keys().next().value as string)
    const signal = AbortSignal.timeout(timeoutMs)
    let asked = 0
    try {
      for await (const prov of this.node.contentRouting.findProviders(revokeCid(issuer, id), { signal })) {
        if (prov.id.equals(this.node.peerId)) continue
        if (++asked > PROVIDERS_PER_LOOKUP) break
        const jwt = await ask(this.node, prov, REVOKE_PROTOCOL, { k: 'get', issuer, id }, signal, MAX_RESPONSE_BYTES)
        if (typeof jwt !== 'string') continue
        const r = await this.verify(jwt)
        if (r.valid && r.issuer === issuer && r.id === id) { this.store.addRevocation(issuer, id, jwt); return true }
      }
    } catch { /* no providers / timeout: not known revoked */ }
    return this.store.isRevoked(issuer, id)
  }
}
