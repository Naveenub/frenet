import { noise } from '@chainsafe/libp2p-noise'
import { yamux } from '@chainsafe/libp2p-yamux'
import { quic } from '@chainsafe/libp2p-quic'
import { autoNAT } from '@libp2p/autonat'
import { bootstrap } from '@libp2p/bootstrap'
import { circuitRelayServer, circuitRelayTransport } from '@libp2p/circuit-relay-v2'
import { dcutr } from '@libp2p/dcutr'
import { identify } from '@libp2p/identify'
import { kadDHT, passthroughMapper } from '@libp2p/kad-dht'
import { mdns } from '@libp2p/mdns'
import { ping } from '@libp2p/ping'
import { tcp } from '@libp2p/tcp'
import { uPnPNAT } from '@libp2p/upnp-nat'
import { createLibp2p } from 'libp2p'
import { peerIdFromString } from '@libp2p/peer-id'
import type { Libp2p, PrivateKey } from '@libp2p/interface'
import { base32 } from 'multiformats/bases/base32'
import { loadOrCreateIdentity } from './identity.js'
import { IdentityLogs, verifyLog, type IdentityState } from './identity-log.js'
import { readIdentityLog } from './recovery.js'
import { Revocations } from './revocations.js'
import { Blocks } from './blocks.js'
import { Calls } from './calls.js'
import { Credentials, type RevocationCheck } from './credentials.js'
import { FileStore } from './files.js'
import { Groups } from './groups.js'
import { Messaging } from './messaging.js'
import { Moderation } from './moderation.js'
import { Names } from './names.js'
import { SitePermissions } from './permissions.js'
import { TrackerBlocker } from './trackers.js'
import { Operator } from './operator.js'
import { Reputation, type ReputationEvent, type ReputationOptions } from './reputation.js'
import { Sites } from './sites.js'
import { Store } from './store.js'
import { meetsIdentityWork, SybilGuard } from './sybil.js'
import { frenetKeyResolver, ZkAuth } from './zkauth.js'

export interface FrenetOptions {
  dataDir: string | ':memory:'
  listen?: string[]
  bootstrap?: string[]
  mdns?: boolean
  /**
   * NAT traversal: AutoNAT reachability checks, circuit-relay v2 client,
   * DCUtR hole punching and UPnP port mapping. Default true.
   */
  nat?: boolean
  /** Relay multiaddrs (with /p2p/<id>) to reserve a slot on, so NATed peers stay reachable. */
  relays?: string[]
  /** Also act as a circuit-relay v2 server for other peers (needs a publicly reachable address). */
  relayServer?: boolean
  /** Extra public multiaddrs to announce (e.g. a forwarded port or DNS name). */
  announce?: string[]
  /** STUN servers (`stun:host[:port]`) handed to the dashboard's WebRTC calls. None by default: calls then work on LAN/public addresses only and no third party learns your IP. */
  iceServers?: string[]
  /** QUIC transport (UDP, `/quic-v1`) next to TCP. Default true. When `listen` is not given, a QUIC listener is added. */
  quic?: boolean
  /** Refuse peers whose key lacks this many bits of identity proof-of-work (see `frenet identity mine`). Default 0 (off). */
  minIdentityBits?: number
  /** At most this many distinct peers per IPv4 /24 (IPv6 /48) at once; loopback/LAN/relayed are exempt. Default 8, 0 disables. */
  maxPeersPerSubnet?: number
  /** Block peers whose reputation falls below the threshold. Default true; false still scores peers but never blocks. */
  autoBan?: boolean
  reputation?: Partial<ReputationOptions>
  quotaBytes?: number
  replicaTtlMs?: number
  /** Announce every stored block on the DHT again this often, ms (default 12 h, 0 = never). See RetentionOptions. */
  reannounceMs?: number
  /** Delay before the first re-announce after start, ms (default 30 s). */
  reannounceDelayMs?: number
  /** Only meaningful with dataDir ':memory:' (tests, embedding): use this key instead of a fresh random one. */
  privateKey?: PrivateKey
}

export interface FrenetNode {
  libp2p: Libp2p
  store: Store
  messaging: Messaging
  blocks: Blocks
  files: FileStore
  sites: Sites
  names: Names
  calls: Calls
  groups: Groups
  operator: Operator
  moderation: Moderation
  /** Per-origin permission grants for sites served by the gateway (default: everything off). */
  permissions: SitePermissions
  /** Host-based tracker blocking used by the web proxy. */
  trackers: TrackerBlocker
  reputation: Reputation
  sybil: SybilGuard
  credentials: Credentials
  /** Anonymous membership proofs (linkable ring proofs) and single-use verifier challenges. */
  zk: ZkAuth
  identityLogs: IdentityLogs
  revocations: Revocations
  /** Primary DID: did:frenet when this node has a rotatable identity (key log), otherwise the did:key of its key. */
  did: string
  /** did:key of the current key (same key as the peer ID). */
  keyDid: string
  /** The verified key log of a rotatable identity, or null for a plain fixed-key identity. */
  identity: IdentityState | null
  iceServers: string[]
  startedAt: number
  stop: () => Promise<void>
}

export async function startFrenet (opts: FrenetOptions): Promise<FrenetNode> {
  let privateKey
  if (opts.dataDir === ':memory:') {
    const { generateKeyPair } = await import('@libp2p/crypto/keys')
    privateKey = opts.privateKey ?? await generateKeyPair('Ed25519')
  } else {
    privateKey = (await loadOrCreateIdentity(opts.dataDir)).key
  }
  // A rotatable identity (did:frenet) keeps a public key log next to the key. It is verified before anything is opened,
  // and it must end in the key this node actually runs with: otherwise we would sign as an identity we do not control.
  let identity: IdentityState | null = null
  if (opts.dataDir !== ':memory:') {
    const events = readIdentityLog(opts.dataDir)
    if (events) {
      identity = await verifyLog(events)
      if (identity.key !== base32.baseEncode(privateKey.publicKey.raw)) throw new Error("identity-log.json does not end in this node's identity key; restore the matching key or remove the log")
    }
  }

  if (opts.reannounceMs !== undefined && !(Number.isFinite(opts.reannounceMs) && opts.reannounceMs >= 0)) throw new Error('reannounceMs must be a number >= 0 (0 turns re-announcing off)')
  const iceServers = opts.iceServers ?? []
  for (const s of iceServers) if (!/^stuns?:[A-Za-z0-9.:[\]-]{1,200}$/.test(s)) throw new Error(`invalid ICE server "${s}" (use stun:host[:port] or stuns:host[:port])`)
  const banned = new Set<string>()
  const store = new Store(opts.dataDir)
  const reputation = new Reputation(store, { ...(opts.autoBan === false ? { banThreshold: -Infinity } : {}), ...opts.reputation })
  const minBits = opts.minIdentityBits ?? 0
  const maxPerSubnet = opts.maxPeersPerSubnet ?? 8
  const sybil = new SybilGuard({ maxPerSubnet: maxPerSubnet > 0 ? maxPerSubnet : Infinity, clusterSize: 6, windowMs: 3_600_000 })
  let self: Libp2p | null = null
  const peerDiscovery = []
  if (opts.mdns !== false) peerDiscovery.push(mdns())

  const useNat = opts.nat !== false
  const relays = opts.relays ?? []
  const useQuic = opts.quic !== false
  const listen = [...(opts.listen ?? ['/ip4/0.0.0.0/tcp/0', ...(useQuic ? ['/ip4/0.0.0.0/udp/0/quic-v1'] : [])])]
  // Reserve a slot on each configured relay; with none configured, let libp2p
  // discover relays among connected peers that run the hop protocol.
  for (const r of relays) listen.push(`${r.replace(/\/p2p-circuit$/, '')}/p2p-circuit`)
  if (useNat && relays.length === 0) listen.push('/p2p-circuit')
  // Bootstrap peers and relays are dialed at startup (relays so the reservation can be made).
  const boot = [...(opts.bootstrap ?? []), ...relays]
  // Operator-chosen bootstrap/relay peers are exempt from the proof-of-work rule and from auto-blocking (still scored).
  for (const a of boot) { const m = /\/p2p\/([^/]+)/.exec(a); if (m) reputation.trusted.add(m[1]!) }
  const refused = (p: { toString: () => string }): boolean => banned.has(p.toString()) || reputation.isBlocked(p.toString())
  const workOk = (p: { toString: () => string, publicKey?: { raw: Uint8Array } }): boolean => reputation.trusted.has(p.toString()) || meetsIdentityWork(p.publicKey?.raw, minBits)
  if (boot.length) peerDiscovery.push(bootstrap({ list: boot }))

  const services: Record<string, any> = {
    identify: identify(),
    ping: ping(),
    dht: kadDHT({
      protocol: '/frenet/kad/1.0.0',
      clientMode: false,
      peerInfoMapper: passthroughMapper
    })
  }
  if (useNat) {
    services.autonat = autoNAT()
    services.dcutr = dcutr()
    services.upnp = uPnPNAT()
  }
  if (opts.relayServer) {
    // Relayed links are limited by design; peers upgrade to direct via DCUtR.
    services.relay = circuitRelayServer({
      reservations: { maxReservations: 64, defaultDurationLimit: 2 * 60_000, defaultDataLimit: BigInt(2 * 1024 * 1024) }
    })
  }

  const libp2p = await createLibp2p({
    privateKey,
    addresses: { listen, ...(opts.announce?.length ? { announce: opts.announce } : {}) },
    transports: [tcp(), ...(useQuic ? [quic()] : []), ...(useNat || opts.relayServer ? [circuitRelayTransport()] : [])],
    connectionEncrypters: [noise()],   // Noise XX: authenticated, forward-secret
    streamMuxers: [yamux()],
    // Refuse banned or auto-blocked peers, peers whose identity lacks the required proof-of-work, and (inbound)
    // peers beyond the per-subnet diversity limit. The peer ID is known only after the handshake.
    connectionGater: {
      denyDialPeer: (p) => refused(p),
      denyInboundEncryptedConnection: (p, c) => {
        if (refused(p) || !workOk(p)) return true
        if (reputation.trusted.has(p.toString())) return false
        const inbound = (self?.getConnections() ?? []).filter((x) => x.direction === 'inbound').map((x) => ({ peer: x.remotePeer.toString(), addr: x.remoteAddr.toString() }))
        return !sybil.admit(p.toString(), c.remoteAddr.toString(), inbound)
      },
      denyOutboundEncryptedConnection: (p) => refused(p) || !workOk(p),
      denyInboundRelayReservation: (p) => refused(p)
    },
    peerDiscovery,
    services
  })

  self = libp2p
  const messaging = new Messaging(libp2p, store, privateKey)
  const moderation = new Moderation(store, libp2p, privateKey)
  const blocks = new Blocks(libp2p, store, moderation, {
    ...(opts.quotaBytes ? { quotaBytes: opts.quotaBytes } : {}),
    ...(opts.replicaTtlMs ? { replicaTtlMs: opts.replicaTtlMs } : {}),
    ...(opts.reannounceMs !== undefined ? { reannounceMs: opts.reannounceMs } : {}),
    ...(opts.reannounceDelayMs !== undefined ? { reannounceDelayMs: opts.reannounceDelayMs } : {})
  })
  moderation.fetchBlock = (cid, maxBytes) => blocks.peek(cid, maxBytes)
  const files = new FileStore(blocks, store)
  const sites = new Sites(blocks, files)
  const names = new Names(libp2p, store, blocks, privateKey, moderation)
  const calls = new Calls(libp2p, privateKey)
  const groups = new Groups(libp2p, store, privateKey)
  const operator = new Operator(libp2p, store, banned, { reputation, sybil, minIdentityBits: minBits })
  const identityLogs = new IdentityLogs(libp2p, store)
  const revocations: Revocations = new Revocations(libp2p, store, (jwt: unknown): Promise<RevocationCheck> => credentials.checkRevocation(jwt))
  const credentials: Credentials = new Credentials(store, privateKey, { identity, logs: identityLogs, revocations })
  const zk = new ZkAuth(store, privateKey, { resolveFrenet: frenetKeyResolver((id) => identityLogs.resolve(id, { network: false })) })
  // Malicious-node detection: every verified-bad act feeds the peer's reputation; crossing the threshold blocks and disconnects it.
  const report = (peer: string, ev: ReputationEvent, detail = ''): void => {
    if (reputation.record(peer, ev, detail)) { void libp2p.hangUp(peerIdFromString(peer)).catch(() => {}) }
  }
  const dropped = (proto: string) => (d: { peer: string, reason: string }): void => {
    operator.noteDrop(proto, d.reason)
    if (reputation.noteDrop(d.peer, d.reason)) void libp2p.hangUp(peerIdFromString(d.peer)).catch(() => {})
  }
  messaging.on('dropped', dropped('msg'))
  calls.on('dropped', dropped('call'))
  groups.on('dropped', dropped('group'))
  messaging.on('message', (m) => report(m.peer, 'valid-message'))
  blocks.report = report
  names.report = report
  libp2p.addEventListener('connection:open', (evt) => {
    const c = evt.detail
    if (c.direction !== 'inbound') return
    for (const p of sybil.observe(c.remotePeer.toString(), c.remoteAddr.toString())) report(p, 'sybil-cluster', 'many identities from one network range')
  })
  store.sweep()
  const sweeper = setInterval(() => store.sweep(), 10 * 60 * 1000)
  sweeper.unref()
  await messaging.start()
  await calls.start()
  await groups.start()
  await blocks.start()
  await names.start()
  if (identity) await identityLogs.adopt(identity.events, true)
  await identityLogs.start()
  await revocations.start()
  await libp2p.start()

  // Auto-dial discovered peers (mDNS / bootstrap).
  libp2p.addEventListener('peer:discovery', (evt) => {
    const info = evt.detail
    if (info.id.equals(libp2p.peerId)) return
    libp2p.dial(info.multiaddrs.length ? info.multiaddrs : info.id).catch(() => {})
  })

  return {
    libp2p,
    store,
    messaging,
    blocks,
    files,
    sites,
    names,
    calls,
    groups,
    operator,
    moderation,
    permissions: new SitePermissions(store),
    trackers: new TrackerBlocker(store),
    reputation,
    sybil,
    credentials,
    zk,
    identityLogs,
    revocations,
    did: credentials.did,
    keyDid: credentials.keyDid,
    identity,
    iceServers,
    startedAt: Date.now(),
    stop: async () => {
      clearInterval(sweeper)
      await messaging.stop()
      await calls.stop()
      await groups.stop()
      await blocks.stop()
      await names.stop()
      await identityLogs.stop()
      await revocations.stop()
      await libp2p.stop()
      store.close()
    }
  }
}
