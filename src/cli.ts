#!/usr/bin/env node
import { homedir } from 'node:os'
import { join } from 'node:path'
import { parseArgs } from 'node:util'
import { startApi } from './api.js'
import { IDENTITY_COMMANDS, runIdentityCommand } from './cli-identity.js'
import { startGateway } from './gateway.js'
import { parseUpstream, startWebProxy } from './webproxy.js'
import { runUpdateCommand } from './cli-update.js'
import { runZkCommand } from './cli-zk.js'
import { startFrenet } from './node.js'
import { runAdminCommand } from './cli-admin.js'

// Identity and recovery subcommands (frenet identity | backup | restore | recovery ...) run without starting a node.
const subcommand = process.argv[2]
if (subcommand && IDENTITY_COMMANDS.includes(subcommand)) {
  process.exit(await runIdentityCommand(subcommand, process.argv.slice(3)))
}

if (subcommand === 'zk') process.exit(await runZkCommand(process.argv.slice(3)))
if (subcommand === 'admin') process.exit(await runAdminCommand(process.argv.slice(3)))
if (subcommand === 'update') process.exit(await runUpdateCommand(process.argv.slice(3)))

const { values } = parseArgs({
  options: {
    data: { type: 'string', default: process.env.FRENET_DATA ?? join(homedir(), '.frenet') },
    listen: { type: 'string', multiple: true },
    bootstrap: { type: 'string', multiple: true },
    'api-port': { type: 'string', default: '7777' },
    'quota-mb': { type: 'string', default: '1024' },
    'replica-ttl-days': { type: 'string', default: '7' },
    'reannounce-hours': { type: 'string', default: '12' },
    relay: { type: 'string', multiple: true },
    'relay-server': { type: 'boolean', default: false },
    announce: { type: 'string', multiple: true },
    'ice-server': { type: 'string', multiple: true },
    'no-nat': { type: 'boolean', default: false },
    'no-quic': { type: 'boolean', default: false },
    'min-identity-bits': { type: 'string', default: '0' },
    'max-peers-per-subnet': { type: 'string', default: '8' },
    'no-auto-ban': { type: 'boolean', default: false },
    'gateway-port': { type: 'string', default: '7778' },
    'no-gateway': { type: 'boolean', default: false },
    'proxy-port': { type: 'string', default: '7779' },
    'no-proxy': { type: 'boolean', default: false },
    'proxy-allow-private': { type: 'boolean', default: false },
    'proxy-upstream': { type: 'string' },
    'no-mdns': { type: 'boolean', default: false },
    'admin-peer': { type: 'string', multiple: true },
    profile: { type: 'string', default: 'default' },
    help: { type: 'boolean', short: 'h', default: false }
  }
})

if (values.help) {
  console.log(`frenet [--data DIR] [--listen MULTIADDR]... [--bootstrap MULTIADDR]... [--api-port N] [--quota-mb N] [--replica-ttl-days N] [--reannounce-hours N] [--relay MULTIADDR]... [--relay-server] [--announce MULTIADDR]... [--ice-server stun:HOST[:PORT]]... [--no-nat] [--no-quic] [--min-identity-bits N] [--max-peers-per-subnet N] [--no-auto-ban] [--gateway-port N] [--no-gateway] [--proxy-port N] [--no-proxy] [--proxy-allow-private] [--proxy-upstream socks5://HOST:PORT] [--no-mdns] [--admin-peer PEERID]... [--profile default|mobile]
  default data dir: ~/.frenet   default listen: /ip4/0.0.0.0/tcp/0   dashboard: http://127.0.0.1:7777
  HTTPS browsing: a local HTTPS-only proxy with tracker blocking (default port 7779; PAC file at http://127.0.0.1:7779/proxy.pac). --proxy-allow-private also lets it tunnel to LAN/loopback addresses (off by default). --proxy-upstream socks5://127.0.0.1:9050 sends all web traffic through a SOCKS5 proxy such as Tor (names are resolved there, not here).
  --reannounce-hours N: announce every stored block on the DHT again at start-up and every N hours (default 12, 0 = never).
  QUIC is on by default (udp, /quic-v1) next to TCP. --min-identity-bits N refuses peers whose key lacks N bits of work (see: frenet identity mine --bits N).
  --admin-peer ID: let that peer administer this node remotely (ban, unban, disconnect, sweep, re-announce, blocklist, stats; nothing else). Off without it.
  remote administration (from the admin's own running node): frenet admin PEERID status|bans|ban|unban|disconnect|sweep|reannounce|block|unblock [--addr MULTIADDR] [--peer P] [--reason R] [--kind K --target T]
  --profile mobile: low-resource preset for phones (Node.js, e.g. Termux): 24 connections, DHT client mode, 256 MB quota, 24 h re-announce, no site gateway, no relay server (explicit flags still win).
  secure updates download/install: frenet update fetch --url URL | install --staged DIR --target DIR | rollback --target DIR
  anonymous membership proofs (zero-knowledge): frenet zk challenge | ring | tag | prove | verify   (frenet zk --help)
  secure updates: frenet update keygen | manifest | sign | verify   (frenet update --help)
  identity & recovery (node stopped): frenet identity | backup --out FILE | restore FILE | recovery split -k K -n N | recovery restore [SHARE...]   (frenet <cmd> --help)`)
  process.exit(0)
}

const profile = values.profile as string
if (profile !== 'default' && profile !== 'mobile') { console.error('error: --profile must be "default" or "mobile"'); process.exit(2) }
const mobile = profile === 'mobile'
// Mobile defaults apply only where the flag was left at its own default; anything the operator typed wins.
const quotaMb = mobile && values['quota-mb'] === '1024' ? '256' : values['quota-mb']!
const reannounceH = mobile && values['reannounce-hours'] === '12' ? '24' : values['reannounce-hours']!

const node = await startFrenet({
  profile: profile as 'default' | 'mobile',
  ...(values['admin-peer']?.length ? { adminPeers: values['admin-peer'] } : {}),
  dataDir: values.data!,
  listen: values.listen,
  bootstrap: values.bootstrap,
  mdns: !values['no-mdns'],
  nat: !values['no-nat'],
  quic: !values['no-quic'],
  minIdentityBits: Number(values['min-identity-bits']),
  maxPeersPerSubnet: Number(values['max-peers-per-subnet']),
  autoBan: !values['no-auto-ban'],
  relays: values.relay,
  relayServer: values['relay-server'],
  announce: values.announce,
  iceServers: values['ice-server'],
  quotaBytes: Number(quotaMb) * 1024 * 1024,
  replicaTtlMs: Number(values['replica-ttl-days']) * 86_400_000,
  reannounceMs: Number(reannounceH) * 3_600_000
})
const gateway = values['no-gateway'] || mobile ? null : await startGateway(node, Number(values['gateway-port']))
const proxy = values['no-proxy'] ? null : await startWebProxy(node.trackers, Number(values['proxy-port']), { allowPrivate: values['proxy-allow-private'], ...(values['proxy-upstream'] ? { upstream: parseUpstream(values['proxy-upstream']) } : {}) })
const api = await startApi(node, Number(values['api-port']), '127.0.0.1', gateway?.port, proxy ?? undefined)

console.log(`FRENET node ${node.libp2p.peerId.toString()}`)
for (const a of node.libp2p.getMultiaddrs()) console.log(`  listening ${a.toString()}`)
console.log(`dashboard http://127.0.0.1:${api.port}`)
if (gateway) console.log(`site gateway http://<site-id>.localhost:${gateway.port}/`)
if (proxy) console.log(`web proxy (HTTPS only, tracker blocking) 127.0.0.1:${proxy.port}  PAC http://127.0.0.1:${proxy.port}/proxy.pac`)

const shutdown = async (): Promise<void> => { api.server.close(); gateway?.server.close(); proxy?.server.close(); await node.stop(); process.exit(0) }
process.on('SIGINT', shutdown)
process.on('SIGTERM', shutdown)
