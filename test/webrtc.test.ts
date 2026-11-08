import assert from 'node:assert/strict'
import { after, describe, it } from 'node:test'
import { startFrenet, type FrenetNode } from '../src/node.js'

const nodes: FrenetNode[] = []
const track = async (o: Parameters<typeof startFrenet>[0]) => { const n = await startFrenet(o); nodes.push(n); return n }
after(async () => { for (const n of nodes) await n.stop().catch(() => {}) })
const waitFor = async (fn: () => boolean, ms = 8000) => {
  const t = Date.now()
  while (!fn()) { if (Date.now() - t > ms) throw new Error('timeout'); await new Promise((r) => setTimeout(r, 25)) }
}

describe('WebRTC transport between two real nodes (loopback UDP, no signalling server)', () => {
  it('connects over /webrtc-direct and exchanges a signed message', async () => {
    const a = await track({ dataDir: ':memory:', listen: ['/ip4/127.0.0.1/udp/0/webrtc-direct'], mdns: false, nat: false, quic: false, webrtc: true })
    const b = await track({ dataDir: ':memory:', listen: ['/ip4/127.0.0.1/tcp/0'], mdns: false, nat: false, quic: false, webrtc: true })
    const addr = a.libp2p.getMultiaddrs().map(String).find((m) => m.includes('/webrtc-direct'))
    assert.ok(addr, 'node A announces a /webrtc-direct address')
    assert.match(addr, /certhash/)
    const got: string[] = []
    a.messaging.on('message', (m) => got.push(`${m.peer}:${m.body}`))
    const conn = await b.libp2p.dial(a.libp2p.getMultiaddrs().find((m) => m.toString().includes('/webrtc-direct'))!)
    assert.ok(conn.remoteAddr.toString().includes('/webrtc-direct'))
    assert.equal(conn.remotePeer.toString(), a.libp2p.peerId.toString())
    await b.messaging.send(a.libp2p.peerId, 'over webrtc')
    await waitFor(() => got.length === 1)
    assert.equal(got[0], `${b.libp2p.peerId}:over webrtc`)
  })

  it('is off unless asked for: no webrtc listener by default', async () => {
    const n = await track({ dataDir: ':memory:', listen: ['/ip4/127.0.0.1/tcp/0'], mdns: false, nat: false, quic: false })
    assert.ok(!n.libp2p.getMultiaddrs().some((m) => m.toString().includes('webrtc')))
  })
})
