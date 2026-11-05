#!/usr/bin/env node
import { homedir } from 'node:os'
import { join } from 'node:path'
import { parseArgs } from 'node:util'
import { startApi } from './api.js'
import { IDENTITY_COMMANDS, runIdentityCommand } from './cli-identity.js'
import { startGateway } from './gateway.js'
import { runUpdateCommand } from './cli-update.js'
import { startFrenet } from './node.js'

// Identity and recovery subcommands (frenet identity | backup | restore | recovery ...) run without starting a node.
const subcommand = process.argv[2]
if (subcommand && IDENTITY_COMMANDS.includes(subcommand)) {
  process.exit(await runIdentityCommand(subcommand, process.argv.slice(3)))
}

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
    'no-mdns': { type: 'boolean', default: false },
    help: { type: 'boolean', short: 'h', default: false }
  }
})

if (values.help) {
  console.log(`frenet [--data DIR] [--listen MULTIADDR]... [--bootstrap MULTIADDR]... [--api-port N] [--quota-mb N] [--replica-ttl-days N] [--reannounce-hours N] [--relay MULTIADDR]... [--relay-server] [--announce MULTIADDR]... [--ice-server stun:HOST[:PORT]]... [--no-nat] [--no-quic] [--min-identity-bits N] [--max-peers-per-subnet N] [--no-auto-ban] [--gateway-port N] [--no-gateway] [--no-mdns]
  default data dir: ~/.frenet   default listen: /ip4/0.0.0.0/tcp/0   dashboard: http://127.0.0.1:7777
  --reannounce-hours N: announce every stored block on the DHT again at start-up and every N hours (default 12, 0 = never).
  QUIC is on by default (udp, /quic-v1) next to TCP. --min-identity-bits N refuses peers whose key lacks N bits of work (see: frenet identity mine --bits N).
  secure updates: frenet update keygen | manifest | sign | verify   (frenet update --help)
  identity & recovery (node stopped): frenet identity | backup --out FILE | restore FILE | recovery split -k K -n N | recovery restore [SHARE...]   (frenet <cmd> --help)`)
  process.exit(0)
}

const node = await startFrenet({
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
  quotaBytes: Number(values['quota-mb']) * 1024 * 1024,
  replicaTtlMs: Number(values['replica-ttl-days']) * 86_400_000,
  reannounceMs: Number(values['reannounce-hours']) * 3_600_000
})
const gateway = values['no-gateway'] ? null : await startGateway(node, Number(values['gateway-port']))
const api = await startApi(node, Number(values['api-port']), '127.0.0.1', gateway?.port)

console.log(`FRENET node ${node.libp2p.peerId.toString()}`)
for (const a of node.libp2p.getMultiaddrs()) console.log(`  listening ${a.toString()}`)
console.log(`dashboard http://127.0.0.1:${api.port}`)
if (gateway) console.log(`site gateway http://<site-id>.localhost:${gateway.port}/`)

const shutdown = async (): Promise<void> => { api.server.close(); gateway?.server.close(); await node.stop(); process.exit(0) }
process.on('SIGINT', shutdown)
process.on('SIGTERM', shutdown)
