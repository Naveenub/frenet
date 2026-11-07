import { parseArgs } from 'node:util'
import { ADMIN_COMMANDS } from './admin.js'

const USAGE = `frenet admin PEERID COMMAND [--addr MULTIADDR] [--peer P] [--reason TEXT] [--kind cid|name|publisher --target T] [--api-port N]
  commands: ${ADMIN_COMMANDS.join(' | ')}
  Runs through YOUR running node (its local API), which signs the command with your node key and sends it to PEERID.
  PEERID must have started with --admin-peer <your peer ID>. --addr is only needed if your node is not already connected to it.`

/** Thin client: the signing key stays inside the running node; this just asks its loopback API to send the command. */
export async function runAdminCommand (argv: string[]): Promise<number> {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: { addr: { type: 'string' }, peer: { type: 'string' }, reason: { type: 'string' }, kind: { type: 'string' }, target: { type: 'string' }, 'api-port': { type: 'string', default: '7777' }, help: { type: 'boolean', short: 'h', default: false } }
  })
  const [peer, cmd] = positionals
  if (values.help || !peer || !cmd) { console.log(USAGE); return values.help ? 0 : 2 }
  const args: Record<string, string> = {}
  for (const k of ['peer', 'reason', 'kind', 'target'] as const) if (values[k] !== undefined) args[k] = values[k]!
  try {
    const res = await fetch(`http://127.0.0.1:${values['api-port']}/api/admin/remote`, {
      method: 'POST', headers: { 'content-type': 'application/json' }, signal: AbortSignal.timeout(30_000),
      body: JSON.stringify({ peer, cmd, args, ...(values.addr ? { addr: values.addr } : {}) })
    })
    const out = await res.json() as any
    if (!res.ok) { console.error(`error: ${out.error}`); return 1 }
    console.log(JSON.stringify(out.result, null, 2))
    return 0
  } catch (e) {
    console.error(`error: ${(e as Error).message} (is your node running on port ${values['api-port']}?)`)
    return 1
  }
}
