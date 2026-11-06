import { randomBytes } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'
import { parseArgs } from 'node:util'
import { privateKeyFromProtobuf } from '@libp2p/crypto/keys'
import { readKeyFile } from './recovery.js'
import { checkPolicy, proveMembership, resolveRing, ringId, tagFor, verifyMembership } from './zkauth.js'

/**
 * `frenet zk challenge | ring | tag | prove | verify`: anonymous membership proofs from the terminal, offline (no node
 * needs to run). The key is read from the data directory and never printed or sent anywhere. `verify` here is stateless:
 * it checks the maths and the parameters you give it, but it cannot know whether the nonce was fresh or the tag was used
 * before; that is what the node's API (`/api/zk/*`) tracks.
 */
export const ZK_COMMANDS = ['zk']

const USAGE = `frenet zk challenge                                       print a fresh single-use nonce (verifier side)
frenet zk ring --ring FILE                                show the ring size and fingerprint (ringId)
frenet zk tag --scope S [--data DIR]                      your one-per-scope tag (anyone holding your key can compute it)
frenet zk prove --ring FILE --scope S --nonce N [--audience A] [--min-ring N] [--ring-id ID] [--data DIR]
frenet zk verify --ring FILE --scope S --nonce N --proof FILE|- [--audience A] [--min-ring N] [--ring-id ID]
  FILE: one DID (did:key) or Ed25519 peer ID per line; # comments allowed. Rings default to >= 5 members.
  did:frenet members need a running node (use the API).`

const members = (file: string): string[] => readFileSync(file, 'utf8').split(/\r?\n/).map((l) => l.replace(/#.*/, '').trim()).filter(Boolean)

export async function runZkCommand (argv: string[]): Promise<number> {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      data: { type: 'string', default: process.env.FRENET_DATA ?? join(homedir(), '.frenet') },
      ring: { type: 'string' },
      scope: { type: 'string' },
      nonce: { type: 'string' },
      audience: { type: 'string' },
      proof: { type: 'string' },
      'min-ring': { type: 'string' },
      'ring-id': { type: 'string' },
      help: { type: 'boolean', short: 'h', default: false }
    }
  })
  try {
    const sub = positionals[0]
    if (values.help || !sub) { console.log(USAGE); return values.help ? 0 : 1 }
    const need = (k: 'ring' | 'scope' | 'nonce'): string => { const v = values[k]; if (!v) throw new Error(`--${k} is required`); return v }
    const policy = { ...(values['min-ring'] ? { minRing: Number(values['min-ring']) } : {}), ...(values['ring-id'] ? { ringId: values['ring-id'] } : {}) }
    const params = (): { scope: string, nonce: string, audience?: string } => ({ scope: need('scope'), nonce: need('nonce'), ...(values.audience ? { audience: values.audience } : {}) })

    if (sub === 'challenge') { console.log(randomBytes(18).toString('base64url')); return 0 }
    if (sub === 'ring') {
      const ring = await resolveRing(members(need('ring')))
      console.log(JSON.stringify({ ringSize: ring.length, ringId: ringId(ring) }))
      return 0
    }
    if (sub === 'tag') {
      console.log(tagFor(privateKeyFromProtobuf(readKeyFile(values.data!)), need('scope')))
      return 0
    }
    if (sub === 'prove') {
      const ring = await resolveRing(members(need('ring')))
      checkPolicy(ring, policy)
      const r = proveMembership(privateKeyFromProtobuf(readKeyFile(values.data!)), ring, params())
      console.log(JSON.stringify({ ...r, ringSize: ring.length, ringId: ringId(ring) }))
      return 0
    }
    if (sub === 'verify') {
      if (!values.proof) throw new Error('--proof FILE (or - for stdin) is required')
      const raw = values.proof === '-' ? readFileSync(0, 'utf8') : readFileSync(values.proof, 'utf8')
      let proof = raw.trim()
      try { const j = JSON.parse(proof) as { proof?: unknown }; if (typeof j.proof === 'string') proof = j.proof } catch { /* bare proof string */ }
      const ring = await resolveRing(members(need('ring')))
      checkPolicy(ring, policy)
      const r = verifyMembership(proof, ring, params())
      console.log(JSON.stringify(r.valid ? { ...r, ringSize: ring.length, ringId: ringId(ring) } : r))
      return r.valid ? 0 : 1
    }
    throw new Error(`unknown subcommand "${sub}" (try: frenet zk --help)`)
  } catch (e) {
    console.error(`error: ${(e as Error).message}`)
    return 1
  }
}
