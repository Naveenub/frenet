import { noise } from '@chainsafe/libp2p-noise'
import { yamux } from '@chainsafe/libp2p-yamux'
import { quic } from '@chainsafe/libp2p-quic'
import { autoNATv2 } from '@libp2p/autonat-v2'
import { bootstrap } from '@libp2p/bootstrap'
import { circuitRelayServer, circuitRelayTransport } from '@libp2p/circuit-relay-v2'
import { dcutr } from '@libp2p/dcutr'
import { identify } from '@libp2p/identify'
import { kadDHT, passthroughMapper } from '@libp2p/kad-dht'
import { mdns } from '@libp2p/mdns'
import { ping } from '@libp2p/ping'
import { tcp } from '@libp2p/tcp'
import { uPnPNAT } from '@libp2p/upnp-nat'
import { webRTC, webRTCDirect } from '@libp2p/webrtc'
import { createLibp2p } from 'libp2p'
import { peerIdFromPrivateKey, peerIdFromString } from '@libp2p/peer-id'
import type { Libp2p, PrivateKey } from '@libp2p/interface'
import { base32 } from 'multiformats/bases/base32'
import { isPeerId } from './channel.js'
import { assertEd25519, loadOrCreateIdentity } from './identity.js'
import { IdentityLogs, verifyLog, type IdentityState } from './identity-log.js'
import { readIdentityLog } from './recovery.js'
import { Revocations } from './revocations.js'
import { Admin } from './admin.js'
import { Blocks } from './blocks.js'
import { Calls } from './calls.js'
import { Credentials, type RevocationCheck } from './credentials.js'
import { Handles, WebDids, type JsonFetcher } from './webid.js'
import { FileStore } from './files.js'
import { Groups } from './groups.js'
import { Messaging } from './messaging.js'
import { Outbox } from './outbox.js'
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

/** DHT value records are not part of FRENET: the DHT only maps CIDs to the peers that hold them. */
export async function noValueRecords (): Promise<never> {
  throw new Error('FRENET DHT stores provider records only; value records are refused')
}

export interface FrenetOptions {
  dataDir: string | ':memory:'
  /** Fetcher for did:web documents and domain handles (https only, SSRF-guarded by default). Tests inject a fake; there is no other network use. */
  fetchJson?: JsonFetcher
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
  /** STUN/TURN servers (`stun:host[:port]`, `turn:host[:port]`, and the `stuns:`/`turns:` forms) handed to the dashboard's WebRTC calls. None by default: calls then work on LAN/public addresses only and no third party learns your IP. A TURN server relays the (DTLS-SRTP encrypted) media and sees both addresses and the traffic volume. */
  iceServers?: string[]
  /** Credentials for every `turn:`/`turns:` entry in `iceServers` (required when there is one). They are handed to the local dashboard over the loopback API. */
  turnUsername?: string
  turnCredential?: string
  /** QUIC transport (UDP, `/quic-v1`) next to TCP. Default true. When `listen` is not given, a QUIC listener is added. */
  quic?: boolean
  /**
   * libp2p WebRTC transports (native `node-datachannel`), opt-in: `/webrtc-direct` (UDP, no signalling server, DTLS with a certhash in the
   * address) and `/webrtc` (private-to-private: signalled over a circuit relay, so it needs `nat` or a `relays` entry). This is node-to-node
   * transport; browser call media is separate and stays in the dashboard. When `listen` is not given, a `/udp/0/webrtc-direct` listener is
   * added (plus `/webrtc` when relays are in use). Default false.
   */
  webrtc?: boolean
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
  /** Peer IDs allowed to administer this node remotely (ban, unban, disconnect, sweep, re-announce, blocklist, stats). Empty = remote administration is off and its protocol is not registered. */
  adminPeers?: string[]
  /**
   * `mobile`: a low-resource preset for phones and other small devices (for example Node.js under Termux): at most 24
   * connections, DHT client mode (announces and fetches, does not serve other peers' DHT queries), no relay server.
   * It is a configuration of this same node, not an app.
   */
  profile?: 'default' | 'mobile'
  /** Only meaningful with dataDir ':memory:' (tests, embedding): use this key instead of a fresh random one. */
  privateKey?: PrivateKey
}

export interface FrenetNode {
  libp2p: Libp2p
  store: Store
  messaging: Messaging
  outbox: Outbox
  blocks: Blocks
  files: FileStore
  sites: Sites
  names: Names
  calls: Calls
  groups: Groups
  operator: Operator
  admin: Admin
  profile: 'default' | 'mobile'
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
  /** did:web resolver (https, SSRF-guarded). */
  webDids: WebDids
  /** Domain handles (`alice@example.com`) with trust-on-first-use pinning. */
  handles: Handles
  revocations: Revocations
  /** Primary DID: did:frenet when this node has a rotatable identity (key log), otherwise the did:key of its key. */
  did: string
  /** did:key of the current key (same key as the peer ID). */
  keyDid: string
  /** The verified key log of a rotatable identity, or null for a plain fixed-key identity. */
  identity: IdentityState | null
  iceServers: string[]
  turn: { username: string, credential: string } | null
  startedAt: number
  stop: () => Promise<void>
}

export async function startFrenet (opts: FrenetOptions): Promise<FrenetNode> {
  let privateKey
  if (opts.dataDir === ':memory:') {
    const { generateKeyPair } = await import('@libp2p/crypto/keys')
    privateKey = assertEd25519(opts.privateKey ?? await generateKeyPair('Ed25519'))
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
  for (const a of opts.adminPeers ?? []) if (!isPeerId(a)) throw new Error(`invalid admin peer ID "${a}"`)   // before anything is opened
  if ((opts.adminPeers ?? []).includes(peerIdFromPrivateKey(privateKey as any).toString())) throw new Error('this node cannot be its own remote admin')
  const profile = opts.profile ?? 'default'
  if (profile !== 'default' && profile !== 'mobile') throw new Error('profile must be "default" or "mobile"')
  if (profile === 'mobile' && opts.relayServer) throw new Error('the mobile profile cannot run a relay server (it is rarely reachable and relaying drains battery and data)')
  const iceServers = opts.iceServers ?? []
  for (const s of iceServers) if (!/^(stuns?|turns?):[A-Za-z0-9.:[\]-]{1,200}$/.test(s)) throw new Error(`invalid ICE server "${s}" (use stun[s]:host[:port] or turn[s]:host[:port])`)
  const usesTurn = iceServers.some((s) => /^turns?:/.test(s))
  const turnOk = (v: string | undefined): boolean => typeof v === 'string' && v.length >= 1 && v.length <= 256 && !/[\u0000-\u001f\u007f]/.test(v)
  if (usesTurn && !(turnOk(opts.turnUsername) && turnOk(opts.turnCredential))) throw new Error('a turn: ICE server needs turnUsername and turnCredential (1-256 characters, no control characters)')
  if (!usesTurn && (opts.turnUsername !== undefined || opts.turnCredential !== undefined)) throw new Error('turnUsername/turnCredential were given but no turn: ICE server is configured')
  const turn = usesTurn ? { username: opts.turnUsername as string, credential: opts.turnCredential as string } : null
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
  const useWebrtc = opts.webrtc === true
  const listen = [...(opts.listen ?? ['/ip4/0.0.0.0/tcp/0', ...(useQuic ? ['/ip4/0.0.0.0/udp/0/quic-v1'] : []), ...(useWebrtc ? ['/ip4/0.0.0.0/udp/0/webrtc-direct'] : [])])]
  // Reserve a slot on each configured relay; with none configured, let libp2p
  // discover relays among connected peers that run the hop protocol.
  for (const r of relays) listen.push(`${r.replace(/\/p2p-circuit$/, '')}/p2p-circuit`)
  if (useNat && relays.length === 0) listen.push('/p2p-circuit')
  if (useWebrtc && (useNat || relays.length > 0)) listen.push('/webrtc')   // private-to-private: needs the circuit-relay listeners above
  // Bootstrap peers and relays are dialed at startup (relays so the reservation can be made).
  const boot = [...(opts.bootstrap ?? []), ...relays]
  // Operator-chosen bootstrap/relay peers are exempt from the proof-of-work rule and from auto-blocking (still scored).
  for (const a of opts.adminPeers ?? []) reputation.trusted.add(a)   // an operator-chosen admin is never auto-blocked or held to the PoW rule (still scored; a manual ban still applies)
  for (const a of boot) { const m = /\/p2p\/([^/]+)/.exec(a); if (m) reputation.trusted.add(m[1]!) }
  const refused = (p: { toString: () => string }): boolean => banned.has(p.toString()) || reputation.isBlocked(p.toString())
  const workOk = (p: { toString: () => string, publicKey?: { raw: Uint8Array } }): boolean => reputation.trusted.has(p.toString()) || meetsIdentityWork(p.publicKey?.raw, minBits)
  if (boot.length) peerDiscovery.push(bootstrap({ list: boot }))

  const services: Record<string, any> = {
    identify: identify(),
    ping: ping(),
    dht: kadDHT({
      protocol: '/frenet/kad/1.0.0',
      clientMode: profile === 'mobile',
      peerInfoMapper: passthroughMapper,
      // Provider records only. kad-dht ships a default validator for "/pk/" value records and would store them on request;
      // replace it with a refusal so this node never accepts or serves arbitrary DHT values (no value store, no storage abuse).
      validators: { pk: noValueRecords },
      selectors: { pk: noValueRecords }
    })
  }
  if (useNat) {
    // v2, not v1: the v1 server answers a QUIC client's check by "dialing" the connection it already has, then closes it
    // (@libp2p/autonat 3.0.32), which drops the client's relay reservation. v2 dials back on a fresh connection.
    // The mobile profile holds at most 24 connections and AutoNAT v2 skips verification at 80% (20 of 24), so a phone with 20 peers
    // never got an address confirmed. 96% allows it up to 23 of 24 and still leaves the one free slot a dial-back needs.
    services.autonat = autoNATv2(profile === 'mobile' ? { connectionThreshold: 96 } : {})
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
    transports: [tcp(), ...(useQuic ? [quic()] : []), ...(useWebrtc ? [webRTCDirect()] : []), ...(useNat || opts.relayServer || relays.length > 0 ? [circuitRelayTransport()] : []), ...(useWebrtc && (useNat || relays.length > 0) ? [webRTC()] : [])],
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
    ...(profile === 'mobile' ? { connectionManager: { maxConnections: 24 } } : {}),
    peerDiscovery,
    services
  })

  self = libp2p
  const outbox = new Outbox(libp2p, store)
  const messaging = new Messaging(libp2p, store, privateKey, outbox)
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
  const groups = new Groups(libp2p, store, privateKey, outbox)
  const operator = new Operator(libp2p, store, banned, { reputation, sybil, minIdentityBits: minBits })
  const admin = new Admin(libp2p, store, privateKey, { operator, moderation, blocks }, opts.adminPeers)
  const identityLogs = new IdentityLogs(libp2p, store)
  const revocations: Revocations = new Revocations(libp2p, store, (jwt: unknown): Promise<RevocationCheck> => credentials.checkRevocation(jwt))
  const webDids = new WebDids(opts.fetchJson)
  const credentials: Credentials = new Credentials(store, privateKey, { identity, logs: identityLogs, revocations, web: webDids })
  const handles = new Handles(webDids, {
    ...(opts.fetchJson ? { fetchJson: opts.fetchJson } : {}),
    pins: { get: (h) => store.getHandlePin(h), set: (h, d) => store.setHandlePin(h, d) },
    resolveLog: async (id) => (identity && identity.id === id ? identity : identityLogs.resolve(id, { network: true }))
  })
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
  admin.on('dropped', dropped('admin'))
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
  outbox.start()
  await admin.start()
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
    outbox,
    blocks,
    files,
    sites,
    names,
    calls,
    groups,
    operator,
    admin,
    profile,
    moderation,
    permissions: new SitePermissions(store),
    trackers: new TrackerBlocker(store),
    reputation,
    sybil,
    credentials,
    zk,
    identityLogs,
    webDids,
    handles,
    revocations,
    did: credentials.did,
    keyDid: credentials.keyDid,
    identity,
    iceServers,
    turn,
    startedAt: Date.now(),
    stop: async () => {
      clearInterval(sweeper)
      outbox.stop()
      await messaging.stop()
      await calls.stop()
      await groups.stop()
      await admin.stop()
      await blocks.stop()
      await names.stop()
      await identityLogs.stop()
      await revocations.stop()
      await libp2p.stop()
      store.close()
    }
  }
}
