#!/usr/bin/env node
import { homedir } from 'node:os'
import { join } from 'node:path'
import { parseArgs } from 'node:util'
import { startApi } from './api.js'
import { startFrenet } from './node.js'

const { values } = parseArgs({
  options: {
    data: { type: 'string', default: process.env.FRENET_DATA ?? join(homedir(), '.frenet') },
    listen: { type: 'string', multiple: true },
    bootstrap: { type: 'string', multiple: true },
    'api-port': { type: 'string', default: '7777' },
    'no-mdns': { type: 'boolean', default: false },
    help: { type: 'boolean', short: 'h', default: false }
  }
})

if (values.help) {
  console.log(`frenet [--data DIR] [--listen MULTIADDR]... [--bootstrap MULTIADDR]... [--api-port N] [--no-mdns]
  default data dir: ~/.frenet   default listen: /ip4/0.0.0.0/tcp/0   dashboard: http://127.0.0.1:7777`)
  process.exit(0)
}

const node = await startFrenet({
  dataDir: values.data!,
  listen: values.listen,
  bootstrap: values.bootstrap,
  mdns: !values['no-mdns']
})
const api = await startApi(node, Number(values['api-port']))

console.log(`FRENET node ${node.libp2p.peerId.toString()}`)
for (const a of node.libp2p.getMultiaddrs()) console.log(`  listening ${a.toString()}`)
console.log(`dashboard http://127.0.0.1:${api.port}`)

const shutdown = async (): Promise<void> => { api.server.close(); await node.stop(); process.exit(0) }
process.on('SIGINT', shutdown)
process.on('SIGTERM', shutdown)
