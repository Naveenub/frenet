import { noise } from '@chainsafe/libp2p-noise'
import { yamux } from '@chainsafe/libp2p-yamux'
import { bootstrap } from '@libp2p/bootstrap'
import { identify } from '@libp2p/identify'
import { kadDHT, passthroughMapper } from '@libp2p/kad-dht'
import { mdns } from '@libp2p/mdns'
import { ping } from '@libp2p/ping'
import { tcp } from '@libp2p/tcp'
import { createLibp2p } from 'libp2p'
import type { Libp2p } from '@libp2p/interface'
import { loadOrCreateIdentity } from './identity.js'
import { Blocks } from './blocks.js'
import { FileStore } from './files.js'
import { Messaging } from './messaging.js'
import { Store } from './store.js'

export interface FrenetOptions {
  dataDir: string | ':memory:'
  listen?: string[]
  bootstrap?: string[]
  mdns?: boolean
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
  if (opts.bootstrap?.length) peerDiscovery.push(bootstrap({ list: opts.bootstrap }))

  const libp2p = await createLibp2p({
    privateKey,
    addresses: { listen: opts.listen ?? ['/ip4/0.0.0.0/tcp/0'] },
    transports: [tcp()],
    connectionEncrypters: [noise()],   // Noise XX: authenticated, forward-secret
    streamMuxers: [yamux()],
    peerDiscovery,
    services: {
      identify: identify(),
      ping: ping(),
      dht: kadDHT({
        protocol: '/frenet/kad/1.0.0',
        clientMode: false,
        peerInfoMapper: passthroughMapper
      })
    }
  })

  const store = new Store(opts.dataDir)
  const messaging = new Messaging(libp2p, store)
  const blocks = new Blocks(libp2p, store, { ...(opts.quotaBytes ? { quotaBytes: opts.quotaBytes } : {}), ...(opts.replicaTtlMs ? { replicaTtlMs: opts.replicaTtlMs } : {}) })
  const files = new FileStore(blocks, store)
  store.sweep()
  const sweeper = setInterval(() => store.sweep(), 10 * 60 * 1000)
  sweeper.unref()
  await messaging.start()
  await blocks.start()
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
    startedAt: Date.now(),
    stop: async () => {
      clearInterval(sweeper)
      await messaging.stop()
      await blocks.stop()
      await libp2p.stop()
      store.close()
    }
  }
}
