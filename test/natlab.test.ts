// Connectivity tests on real network stacks: Linux namespaces behind real (netfilter) NAT, not loopback.
// Needs root + iproute2 + iptables (+ miniupnpd for the UPnP test). Opt in:  FRENET_NATLAB=1 sudo -E npm run test:natlab
// Topology and the NAT models are in scripts/natlab/lab.sh. Skipped everywhere else (npm test, CI without root).
import assert from 'node:assert/strict'
import { type ChildProcessWithoutNullStreams, execFileSync, spawn } from 'node:child_process'
import { createInterface } from 'node:readline'
import { after, before, describe, it } from 'node:test'

const LAB = new URL('../scripts/natlab/lab.sh', import.meta.url).pathname
const PEER = new URL('../scripts/natlab/peer.ts', import.meta.url).pathname
const ROOT = new URL('..', import.meta.url).pathname
const enabled = process.env.FRENET_NATLAB === '1' && process.getuid?.() === 0
const skip = enabled ? false : 'set FRENET_NATLAB=1 and run as root (Linux namespaces + iptables), see scripts/natlab/lab.sh'
const have = (bin: string): boolean => { try { execFileSync('which', [bin], { stdio: 'ignore' }); return true } catch { return false } }

interface Conn { peer: string, addr: string, dir: string, limited: boolean }
interface State { peer: string, addrs: string[], conns: Conn[] }

class Peer {
  private proc: ChildProcessWithoutNullStreams
  private seq = 0
  private waiting = new Map<number, (r: any) => void>()
  readonly messages: Array<{ peer: string, body: string }> = []
  log = ''
  id = ''
  ready: Promise<State>

  constructor (readonly ns: string, opts: object) {
    this.proc = spawn('ip', ['netns', 'exec', ns, process.execPath, '--import', 'tsx', PEER, JSON.stringify(opts)], { cwd: ROOT })
    this.proc.stderr.on('data', (d) => { this.log += String(d); if (process.env.FRENET_NATLAB_LOG) process.stderr.write(`[${ns}] ${d}`) })
    this.ready = new Promise((resolve, reject) => {
      this.proc.once('exit', (code) => reject(new Error(`peer in ${ns} exited (${code}): ${this.log.slice(-600)}`)))
      createInterface({ input: this.proc.stdout }).on('line', (l) => {
        const e = JSON.parse(l)
        if (e.ev === 'ready') { this.id = e.peer; resolve(e) }
        else if (e.ev === 'message') this.messages.push({ peer: e.peer, body: e.body })
        else if (e.ev === 'reply') { this.waiting.get(e.id)?.(e); this.waiting.delete(e.id) }
      })
    })
  }

  async call (cmd: string, args: object = {}, ms = 20_000): Promise<any> {
    await this.ready
    const id = ++this.seq
    const r = await new Promise<any>((resolve, reject) => {
      const t = setTimeout(() => reject(new Error(`${cmd} timed out on ${this.ns}`)), ms)
      this.waiting.set(id, (x) => { clearTimeout(t); resolve(x) })
      this.proc.stdin.write(`${JSON.stringify({ id, cmd, ...args })}\n`)
    })
    if (r.error) throw new Error(`${cmd} on ${this.ns}: ${r.error}`)
    return r
  }

  state = (): Promise<State> => this.call('state')
  dial = (addr: string): Promise<{ addr: string, limited: boolean }> => this.call('dial', { addr })
  send = (peer: string, body: string): Promise<void> => this.call('send', { peer, body })

  async until (pred: (s: State) => boolean, ms = 30_000, what = 'condition'): Promise<State> {
    const t = Date.now()
    for (;;) {
      const s = await this.state()
      if (pred(s)) return s
      if (Date.now() - t > ms) throw new Error(`timeout waiting for ${what} on ${this.ns}; state=${JSON.stringify(s)}`)
      await new Promise((r) => setTimeout(r, 250))
    }
  }

  async stop (): Promise<void> {
    if (this.proc.exitCode !== null) return
    await this.call('stop', {}, 5000).catch(() => {})
    this.proc.kill('SIGKILL')
  }
}

const lab = (...a: string[]): void => { execFileSync('bash', [LAB, ...a], { stdio: ['ignore', 'inherit', 'inherit'] }) }
const peers: Peer[] = []
const start = (ns: string, opts: object): Peer => { const p = new Peer(ns, { mdns: false, ...opts }); peers.push(p); return p }
const stopAll = async (): Promise<void> => { await Promise.all(peers.splice(0).map((p) => p.stop())) }
const isCircuit = (a: string): boolean => a.includes('/p2p-circuit')
const direct = (s: State, peer: string): Conn[] => s.conns.filter((c) => c.peer === peer && !isCircuit(c.addr) && !c.limited)

const PUBLIC = '20.20.20'   // routable-looking on purpose: libp2p ignores RFC1918 addresses for NAT traversal
const TCP = ['/ip4/0.0.0.0/tcp/4001']
const QUIC = ['/ip4/0.0.0.0/udp/4001/quic-v1']
const PUBLIC_ANNOUNCE = [`/ip4/${PUBLIC}.10/tcp/4001`, `/ip4/${PUBLIC}.10/udp/4001/quic-v1`]
const relayAddr = (r: State, proto: 'tcp' | 'quic'): string => {
  const a = r.addrs.find((x) => x.startsWith(`/ip4/${PUBLIC}.10/`) && (proto === 'quic' ? x.includes('/quic-v1') : x.includes('/tcp/')))
  assert.ok(a, `relay has no public ${proto} address: ${r.addrs.join(' ')}`)
  return a
}

describe('NAT lab', { skip }, () => {
  before(() => { lab('up') })
  after(async () => { await stopAll(); lab('down') })

  describe('relay between two peers behind separate NATs', () => {
    for (const proto of ['tcp', 'quic'] as const) {
      it(`delivers a message over ${proto} through a public relay`, async () => {
        // A public node must announce its address (--announce): libp2p does not advertise an unconfirmed public listen address.
        const relay = start('frrelay', { listen: [...TCP, ...QUIC], announce: PUBLIC_ANNOUNCE, relayServer: true })
        const rs = await relay.ready
        const addr = relayAddr(rs, proto)
        const a = start('frA', { listen: ['/ip4/0.0.0.0/tcp/0', '/ip4/0.0.0.0/udp/0/quic-v1'], relays: [addr] })
        const b = start('frB', { listen: ['/ip4/0.0.0.0/tcp/0', '/ip4/0.0.0.0/udp/0/quic-v1'], relays: [addr] })
        try {
          const sa = await a.until((s) => s.addrs.some(isCircuit), 20_000, 'a relay reservation')
          await b.until((s) => s.addrs.some(isCircuit), 20_000, 'a relay reservation')
          const circuit = sa.addrs.find(isCircuit)!
          assert.ok(circuit.includes(rs.peer), 'circuit address goes through our relay')
          // The NATed hosts' private addresses must not be reachable from each other: only the relay path can work.
          const c = await b.dial(circuit)
          assert.ok(isCircuit(c.addr))
          await b.send(a.id, `hello via relay over ${proto}`)
          await a.until(() => a.messages.length === 1, 10_000, 'the message')
          assert.deepEqual(a.messages[0], { peer: b.id, body: `hello via relay over ${proto}` })
        } finally { await stopAll() }
      })
    }
  })

  describe('mobile profile behind a NAT', () => {
    it('reserves a relay slot and receives a message over the relay (DHT client mode, 24 connections)', async () => {
      const relay = start('frrelay', { listen: [...TCP, ...QUIC], announce: PUBLIC_ANNOUNCE, relayServer: true })
      const addr = relayAddr(await relay.ready, 'quic')
      const phone = start('frA', { profile: 'mobile', listen: ['/ip4/0.0.0.0/tcp/0', '/ip4/0.0.0.0/udp/0/quic-v1'], relays: [addr] })
      const other = start('frB', { listen: ['/ip4/0.0.0.0/tcp/0', '/ip4/0.0.0.0/udp/0/quic-v1'], relays: [addr] })
      try {
        const sa = await phone.until((s) => s.addrs.some(isCircuit), 20_000, 'a relay reservation')
        await other.until((s) => s.addrs.some(isCircuit), 20_000, 'a relay reservation')
        await other.dial(sa.addrs.find(isCircuit)!)
        await other.send(phone.id, 'hello phone')
        await phone.until(() => phone.messages.length === 1, 10_000, 'the message')
        assert.equal(phone.messages[0]!.body, 'hello phone')
      } finally { await stopAll() }
    })
  })

  describe('DCUtR hole punching (cone NAT on both sides)', () => {
    for (const proto of ['tcp', 'quic'] as const) {
      // Known limitation, kept as a todo so it flips to a pass when it works. DCUtR runs, but libp2p's TCP and QUIC
      // transports dial from a fresh source port instead of the listening socket, so the NAT mapping the peer was
      // told about is never the one the punch uses (see docs/ARCHITECTURE.md, "NAT traversal").
      it(`upgrades a relayed ${proto} link to a direct one`, { todo: 'transports do not dial from the listening socket' }, async () => {
        lab('nat', 'frnatA', 'cone'); lab('nat', 'frnatB', 'cone')
        const relay = start('frrelay', { listen: [...TCP, ...QUIC], announce: PUBLIC_ANNOUNCE, relayServer: true })
        const addr = relayAddr(await relay.ready, proto)
        const a = start('frA', { listen: ['/ip4/0.0.0.0/tcp/0', '/ip4/0.0.0.0/udp/0/quic-v1'], relays: [addr] })
        const b = start('frB', { listen: ['/ip4/0.0.0.0/tcp/0', '/ip4/0.0.0.0/udp/0/quic-v1'], relays: [addr] })
        try {
          const sa = await a.until((s) => s.addrs.some(isCircuit), 20_000, 'a relay reservation')
          await b.until((s) => s.addrs.some(isCircuit), 20_000, 'a relay reservation')
          await b.dial(sa.addrs.find(isCircuit)!)
          await b.until((x) => direct(x, a.id).length > 0, 15_000, 'a direct connection to A')
        } finally { await stopAll() }
      })
    }
  })

  describe('symmetric NAT', () => {
    it('still delivers through the relay when both NATs pick a new port per flow', async () => {
      lab('nat', 'frnatA', 'symmetric'); lab('nat', 'frnatB', 'symmetric')
      const relay = start('frrelay', { listen: [...TCP, ...QUIC], announce: PUBLIC_ANNOUNCE, relayServer: true })
      const addr = relayAddr(await relay.ready, 'quic')
      const a = start('frA', { listen: ['/ip4/0.0.0.0/tcp/0', '/ip4/0.0.0.0/udp/0/quic-v1'], relays: [addr] })
      const b = start('frB', { listen: ['/ip4/0.0.0.0/tcp/0', '/ip4/0.0.0.0/udp/0/quic-v1'], relays: [addr] })
      try {
        const sa = await a.until((s) => s.addrs.some(isCircuit), 20_000, 'a relay reservation')
        await b.until((s) => s.addrs.some(isCircuit), 20_000, 'a relay reservation')
        await b.dial(sa.addrs.find(isCircuit)!)
        await b.send(a.id, 'through symmetric NATs')
        await a.until(() => a.messages.length === 1, 10_000, 'the message')
        assert.equal(a.messages[0]!.body, 'through symmetric NATs')
        const s = await b.state()
        assert.equal(direct(s, a.id).length, 0, 'no direct path exists, the relay carries it')
      } finally { await stopAll(); lab('nat', 'frnatA', 'cone'); lab('nat', 'frnatB', 'cone') }
    })
  })

  describe('QUIC behind a NAT', () => {
    it('a NATed node reaches a public QUIC node and both can message over that one connection', async () => {
      const pub = start('frrelay', { listen: QUIC, announce: [PUBLIC_ANNOUNCE[1]], nat: false })
      const ps = await pub.ready
      const a = start('frA', { listen: ['/ip4/0.0.0.0/udp/0/quic-v1'], nat: false })
      await a.ready
      try {
        const c = await a.dial(relayAddr(ps, 'quic'))
        assert.ok(c.addr.includes('/quic-v1') && !isCircuit(c.addr), `direct QUIC connection expected, got ${c.addr}`)
        await a.send(pub.id, 'out through the NAT')
        await pub.until(() => pub.messages.length === 1, 10_000, 'the inbound message')
        // The reply has to reuse A's outbound connection: nothing can open a new one towards a private address.
        await pub.send(a.id, 'and back')
        await a.until(() => a.messages.length === 1, 10_000, 'the reply')
        assert.deepEqual([pub.messages[0]!.body, a.messages[0]!.body], ['out through the NAT', 'and back'])
        const s = await pub.state()
        assert.ok(s.conns.every((x) => x.addr.includes('/quic-v1') && x.addr.includes('20.20.20.2')), `the public node sees A only as its NAT address: ${JSON.stringify(s.conns)}`)
      } finally { await stopAll() }
    })
  })

  describe('mDNS between two hosts on a LAN', () => {
    it('discovers a peer on another host with no bootstrap list and connects over the LAN, not loopback', async () => {
      const a = start('frL1', { mdns: true })
      const b = start('frL2', { mdns: true })
      try {
        await Promise.all([a.ready, b.ready])
        const s = await a.until((x) => x.conns.some((c) => c.peer === b.id), 30_000, 'mDNS discovery of B')
        const c = s.conns.find((x) => x.peer === b.id)!
        assert.ok(c.addr.includes('/ip4/10.201.0.2/'), `connected over the LAN address, got ${c.addr}`)
        await a.send(b.id, 'found you by mDNS')
        await b.until(() => b.messages.length === 1, 10_000, 'the message')
        assert.equal(b.messages[0]!.body, 'found you by mDNS')
      } finally { await stopAll() }
    })
  })

  describe('UPnP port mapping on the home router', { skip: have('miniupnpd') && have('nft') ? false : 'miniupnpd and nft are not installed' }, () => {
    it('asks the router for a port and becomes directly reachable through it', async () => {
      lab('upnp', 'frnatA', 'start')
      // UPnP only proposes the mapping. AutoNAT v2 confirms it after 4 dial-backs from 4 different first octets (hardcoded in
      // @libp2p/autonat-v2), so four public peers, and it checks on each *new* connection: A meets them once the mapping exists.
      const pubs = [['frrelay', '20.20.20.10'], ['frP1', '21.21.21.10'], ['frP2', '22.22.22.10'], ['frP3', '23.23.23.10']]
        .map(([ns, ip]) => start(ns!, { listen: TCP, announce: [`/ip4/${ip}/tcp/4001`] }))
      const boot = (await Promise.all(pubs.map((p) => p.ready))).map((s) => s.addrs.find((x) => !x.startsWith('/ip4/127.'))!)
      const a = start('frA', { listen: ['/ip4/0.0.0.0/tcp/4001'] })
      const b = start('frB', { listen: ['/ip4/0.0.0.0/tcp/0'], nat: false })
      const router = (): string => execFileSync('ip', ['netns', 'exec', 'frnatA', 'nft', 'list', 'ruleset'], { encoding: 'utf8' })
      try {
        await Promise.all([a.ready, b.ready])
        const t = Date.now()
        while (!/dnat ip to 192\.168\.1\.10:4001/.test(router())) {
          if (Date.now() - t > 40_000) assert.fail(`the router never got a forwarding rule for 4001:\n${router()}`)
          await new Promise((r) => setTimeout(r, 500))
        }
        for (const addr of boot) await a.dial(addr)
        const mapped = `/ip4/${PUBLIC}.2/tcp/4001`
        const s = await a.until((x) => x.addrs.some((m) => m.startsWith(mapped)), 40_000, `the confirmed UPnP address ${mapped}`)
        // B sits behind its own NAT and only has the mapped address, like any remote peer reading it from a record.
        const c = await b.dial(s.addrs.find((m) => m.startsWith(mapped))!)
        assert.ok(!isCircuit(c.addr) && !c.limited, 'a direct connection, not a relayed one')
        await b.send(a.id, 'through the UPnP mapping')
        await a.until(() => a.messages.length === 1, 10_000, 'the message')
        assert.equal(a.messages[0]!.body, 'through the UPnP mapping')
      } finally { await stopAll(); lab('upnp', 'frnatA', 'stop') }
    })
  })
})
