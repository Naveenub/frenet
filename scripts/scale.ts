// Scale harness: N real FRENET nodes in ONE process over loopback TCP + Noise + yamux, sparse topology
// (each node dials only 2 earlier nodes, so content must be found through the DHT, not a full mesh).
// Measures what one machine can show: join time, DHT content fetch success/latency, message latency, memory.
// It does NOT show WAN latency, NAT behaviour or thousands of independent hosts; see docs/TESTNET.md.
// Usage: FRENET_SCALE_N=50 FRENET_SCALE_FETCHES=40 node --import tsx scripts/scale.ts [--json]
import { performance } from 'node:perf_hooks'
import { startFrenet, type FrenetNode } from '../src/node.js'

const N = Number(process.env.FRENET_SCALE_N ?? 20)
const FETCHES = Number(process.env.FRENET_SCALE_FETCHES ?? 20)
const MSGS = Number(process.env.FRENET_SCALE_MSGS ?? 20)
const SETTLE = Number(process.env.FRENET_SCALE_SETTLE_MS ?? 6000)
const json = process.argv.includes('--json')
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))
const pct = (xs: number[], p: number) => { const s = [...xs].sort((a, b) => a - b); return s.length ? Math.round(s[Math.min(s.length - 1, Math.floor(p * s.length))]) : null }
const pick = <T>(xs: T[], not?: T): T => { let x: T; do { x = xs[Math.floor(Math.random() * xs.length)] } while (x === not && xs.length > 1); return x }

export interface ScaleReport {
  nodes: number, joinMs: number, rtMin: number, rtMedian: number, avgConnections: number
  fetch: { tried: number, ok: number, p50Ms: number | null, p95Ms: number | null }
  message: { tried: number, ok: number, p50Ms: number | null, p95Ms: number | null }
  rssMb: number
}

export async function runScale (n = N, fetches = FETCHES, msgs = MSGS): Promise<ScaleReport> {
  const nodes: FrenetNode[] = []
  const t0 = performance.now()
  try {
    for (let i = 0; i < n; i++) {
      const node = await startFrenet({ dataDir: ':memory:', listen: ['/ip4/127.0.0.1/tcp/0'], mdns: false, nat: false, quic: false })
      for (const j of new Set([0, Math.floor(Math.random() * i)])) {
        if (i > 0) await node.libp2p.dial(nodes[j].libp2p.getMultiaddrs()[0]).catch(() => {})
      }
      nodes.push(node)
    }
    const joinMs = Math.round(performance.now() - t0)
    // Fixed settle, not a convergence gate: a late joiner that dials only 2 peers can keep a tiny routing table for minutes (see rtMin).
    const size = (x: FrenetNode) => (x.libp2p.services as any).dht?.routingTable?.size ?? 0
    await sleep(SETTLE)
    const rt = nodes.map(size).sort((x, y) => x - y)
    const avgConnections = Math.round(nodes.reduce((s, x) => s + x.libp2p.getConnections().length, 0) / n * 10) / 10

    const fetchMs: number[] = []; let fetchOk = 0
    for (let k = 0; k < fetches; k++) {
      const src = pick(nodes); const dst = pick(nodes, src)
      const data = Buffer.from(`scale-${k}-${Math.random()}`)
      const { cid } = await src.blocks.put(data)
      const t = performance.now()
      const got = await Promise.race([dst.blocks.get(cid), sleep(15000).then(() => null)]).catch(() => null)
      if (got && Buffer.from(got).equals(data)) { fetchOk++; fetchMs.push(performance.now() - t) }
    }

    const msgMs: number[] = []; let msgOk = 0
    for (let k = 0; k < msgs; k++) {
      const a = pick(nodes); const b = pick(nodes, a)
      const arrived = new Promise<number>((resolve) => {
        const tag = `m${k}-${Math.random()}`; const t = performance.now()
        b.messaging.on('message', (m) => { if (m.body === tag) resolve(performance.now() - t) })
        a.messaging.send(b.libp2p.peerId, tag).catch(() => {})
      })
      const ms = await Promise.race([arrived, sleep(10000).then(() => null)])
      if (ms !== null) { msgOk++; msgMs.push(ms) }
    }
    return {
      nodes: n, joinMs, rtMin: rt[0], rtMedian: rt[Math.floor(rt.length / 2)], avgConnections,
      fetch: { tried: fetches, ok: fetchOk, p50Ms: pct(fetchMs, 0.5), p95Ms: pct(fetchMs, 0.95) },
      message: { tried: msgs, ok: msgOk, p50Ms: pct(msgMs, 0.5), p95Ms: pct(msgMs, 0.95) },
      rssMb: Math.round(process.memoryUsage().rss / 1048576)
    }
  } finally {
    await Promise.all(nodes.map((x) => x.stop().catch(() => {})))
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  runScale().then((r) => {
    console.log(json ? JSON.stringify(r) : r)
    const min = Number(process.env.FRENET_SCALE_MIN_FETCH_OK ?? 0) // e.g. 0.9 = fail the run below 90% fetch success
    process.exit(r.fetch.ok / Math.max(1, r.fetch.tried) < min ? 2 : 0)
  }).catch((e) => { console.error(e); process.exit(1) })
}
