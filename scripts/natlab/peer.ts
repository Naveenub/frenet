// One real FRENET node for test/natlab.test.ts, run inside a network namespace.
// argv[2] = JSON FrenetOptions. stdin: one JSON command per line {id, cmd, ...}; stdout: one JSON event per line.
import { createInterface } from 'node:readline'
import { multiaddr } from '@multiformats/multiaddr'
import { peerIdFromString } from '@libp2p/peer-id'
import { startFrenet } from '../../src/node.js'

const out = (o: object): void => { process.stdout.write(`${JSON.stringify(o)}\n`) }
const { fillers = 0, ...opts } = JSON.parse(process.argv[2] ?? '{}') as { fillers?: number } & Record<string, unknown>
// `fillers`: extra bare nodes in this process, one per address 24.0.<i>.10 (see lab.sh), to give another peer something to connect to
const fillerNodes = await Promise.all(Array.from({ length: fillers }, (_, i) =>
  startFrenet({ dataDir: ':memory:', mdns: false, nat: false, listen: [`/ip4/24.0.${i + 1}.10/tcp/4002`], announce: [`/ip4/24.0.${i + 1}.10/tcp/4002`] })))
const node = await startFrenet({ dataDir: ':memory:', ...opts })
const lp = node.libp2p

const state = () => ({
  peer: lp.peerId.toString(),
  addrs: lp.getMultiaddrs().map(String),
  observed: ((lp as any).components?.addressManager?.getObservedAddrs?.() ?? []).map(String),
  conns: lp.getConnections().map((c) => ({ peer: c.remotePeer.toString(), addr: c.remoteAddr.toString(), dir: c.direction, limited: c.limits != null }))
})

node.messaging.on('message', (m) => out({ ev: 'message', peer: m.peer, body: m.body }))
out({ ev: 'ready', ...state(), fillerAddrs: fillerNodes.map((f) => f.libp2p.getMultiaddrs().map(String).find((a) => a.startsWith('/ip4/24.')) ?? '') })

createInterface({ input: process.stdin }).on('line', (line) => {
  void (async () => {
    const c = JSON.parse(line) as { id: number, cmd: string, addr?: string, peer?: string, body?: string }
    try {
      if (c.cmd === 'state') out({ ev: 'reply', id: c.id, ...state() })
      else if (c.cmd === 'dial') { const conn = await lp.dial(multiaddr(c.addr!)); out({ ev: 'reply', id: c.id, addr: conn.remoteAddr.toString(), limited: conn.limits != null }) }
      else if (c.cmd === 'send') { await node.messaging.send(peerIdFromString(c.peer!), c.body!); out({ ev: 'reply', id: c.id }) }
      else if (c.cmd === 'stop') { await node.stop(); await Promise.all(fillerNodes.map((f) => f.stop())); out({ ev: 'reply', id: c.id }); process.exit(0) }
      else throw new Error(`unknown cmd ${c.cmd}`)
    } catch (e) { out({ ev: 'reply', id: c.id, error: (e as Error).message }) }
  })()
})
