import { noise } from '@chainsafe/libp2p-noise'
import { yamux } from '@chainsafe/libp2p-yamux'
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
import type { Libp2p } from '@libp2p/interface'
import { loadOrCreateIdentity } from './identity.js'
import { Blocks } from './blocks.js'
import { FileStore } from './files.js'
import { Messaging } from './messaging.js'
import { Names } from './names.js'
import { Sites } from './sites.js'
import { Store } from './store.js'

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
  quotaBytes?: number
  replicaTtlMs?: number
  /** Only meaningful with dataDir ':memory:' (tests). */
  ephemeralIdentity?: boolean
}

export interface FrenetNode {
  libp2p: Libp2p
  store: Store
  messaging: Messaging
  blocks: Blocks
  files: FileStore
  sites: Sites
  names: Names
  startedAt: number
  stop: () => Promise<void>
}

export async function startFrenet (opts: FrenetOptions): Promise<FrenetNode> {
  let privateKey
  if (opts.dataDir === ':memory:') {
    const { generateKeyPair } = await import('@libp2p/crypto/keys')
    privateKey = await generateKeyPair('Ed25519')
  } else {
    privateKey = (await loadOrCreateIdentity(opts.dataDir)).key
  }

  const peerDiscovery = []
  if (opts.mdns !== false) peerDiscovery.push(mdns())

  const useNat = opts.nat !== false
  const relays = opts.relays ?? []
  const listen = [...(opts.listen ?? ['/ip4/0.0.0.0/tcp/0'])]
  // Reserve a slot on each configured relay; with none configured, let libp2p
  // discover relays among connected peers that run the hop protocol.
  for (const r of relays) listen.push(`${r.replace(/\/p2p-circuit$/, '')}/p2p-circuit`)
  if (useNat && relays.length === 0) listen.push('/p2p-circuit')
  // Bootstrap peers and relays are dialed at startup (relays so the reservation can be made).
  const boot = [...(opts.bootstrap ?? []), ...relays]
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
    transports: [tcp(), ...(useNat || opts.relayServer ? [circuitRelayTransport()] : [])],
    connectionEncrypters: [noise()],   // Noise XX: authenticated, forward-secret
    streamMuxers: [yamux()],
    peerDiscovery,
    services
  })

  const store = new Store(opts.dataDir)
  const messaging = new Messaging(libp2p, store, privateKey)
  const blocks = new Blocks(libp2p, store, { ...(opts.quotaBytes ? { quotaBytes: opts.quotaBytes } : {}), ...(opts.replicaTtlMs ? { replicaTtlMs: opts.replicaTtlMs } : {}) })
  const files = new FileStore(blocks, store)
  const sites = new Sites(blocks, files)
  const names = new Names(libp2p, store, blocks, privateKey)
  store.sweep()
  const sweeper = setInterval(() => store.sweep(), 10 * 60 * 1000)
  sweeper.unref()
  await messaging.start()
  await blocks.start()
  await names.start()
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
    startedAt: Date.now(),
    stop: async () => {
      clearInterval(sweeper)
      await messaging.stop()
      await blocks.stop()
      await names.stop()
      await libp2p.stop()
      store.close()
    }
  }
}
