import { closeSync, existsSync, openSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { basename, join } from 'node:path'
import { parseArgs } from 'node:util'
import { privateKeyFromProtobuf, privateKeyToProtobuf } from '@libp2p/crypto/keys'
import { Store } from './store.js'
import { generateReleaseKey, MAX_VALIDITY_MS, sha256Hex, signManifest, Updates, validateRoots, verifyArtifact, type TrustRoots, type UpdateManifest } from './updates.js'

/**
 * `frenet update keygen | manifest | sign | verify`. Verification never installs anything; it answers one question:
 * "are these bytes the release the maintainers signed, and is it newer than what I accepted before?"
 */
const USAGE = `frenet update keygen --out KEYFILE                      new release signing key (prints its did:key)
frenet update manifest --version X.Y.Z --seq N [--channel stable] [--days 30] [--notes TEXT] --out FILE ARTIFACT...
frenet update sign --key KEYFILE --in MANIFEST_OR_ENVELOPE --out ENVELOPE      add this key's signature (repeat for each signer)
frenet update verify ENVELOPE [--roots FILE] [--channel stable] [--current X.Y.Z] [--artifact FILE]... [--accept] [--data DIR]
  roots file: {"threshold": 2, "keys": ["did:key:z...", ...]}   default <data>/update-roots.json; with none, everything is refused`

const here = (rel: string): string => new URL(rel, import.meta.url).pathname

function runningVersion (): string {
  try { return JSON.parse(readFileSync(here('../package.json'), 'utf8')).version } catch { return '0.0.0' }
}

export async function runUpdateCommand (argv: string[]): Promise<number> {
  const sub = argv[0]
  const { values, positionals } = parseArgs({
    args: argv.slice(1),
    allowPositionals: true,
    options: {
      out: { type: 'string' }, key: { type: 'string' }, in: { type: 'string' }, roots: { type: 'string' },
      channel: { type: 'string', default: 'stable' }, current: { type: 'string' }, artifact: { type: 'string', multiple: true },
      version: { type: 'string' }, seq: { type: 'string' }, days: { type: 'string', default: '30' }, notes: { type: 'string' },
      accept: { type: 'boolean', default: false },
      data: { type: 'string', default: process.env.FRENET_DATA ?? join(homedir(), '.frenet') },
      help: { type: 'boolean', short: 'h', default: false }
    }
  })
  try {
    if (values.help || !sub) { console.log(USAGE); return sub ? 0 : 2 }

    if (sub === 'keygen') {
      if (!values.out) throw new Error('--out KEYFILE is required')
      const { key, did } = await generateReleaseKey()
      const fd = openSync(values.out, 'wx', 0o600)
      try { writeFileSync(fd, privateKeyToProtobuf(key)) } finally { closeSync(fd) }
      console.log(`release key written to ${values.out} (mode 0600)\npublic identifier (put this in the trust roots): ${did}`)
      console.log('Keep the key file offline. Anyone holding it can sign releases.')
      return 0
    }

    if (sub === 'manifest') {
      if (!values.out || !values.version || !values.seq || positionals.length === 0) throw new Error('usage: frenet update manifest --version X.Y.Z --seq N --out FILE ARTIFACT...')
      const days = Number(values.days)
      if (!(days > 0) || days * 86_400_000 > MAX_VALIDITY_MS) throw new Error('--days must be 1..90')
      const now = Date.now()
      const m: UpdateManifest = {
        v: 1, product: 'frenet', channel: values.channel!, version: values.version, seq: Number(values.seq), created: now, expires: now + days * 86_400_000,
        artifacts: positionals.map((f) => { const b = readFileSync(f); return { name: basename(f), size: b.length, sha256: sha256Hex(b) } }),
        ...(values.notes ? { notes: values.notes } : {})
      }
      const fd = openSync(values.out, 'wx')
      try { writeFileSync(fd, JSON.stringify(m, null, 2) + '\n') } finally { closeSync(fd) }
      console.log(`manifest for ${m.version} (seq ${m.seq}, ${m.artifacts.length} artifact(s)) written to ${values.out}; now sign it with 'frenet update sign'`)
      return 0
    }

    if (sub === 'sign') {
      if (!values.key || !values.in || !values.out) throw new Error('usage: frenet update sign --key KEYFILE --in FILE --out FILE')
      const key = privateKeyFromProtobuf(readFileSync(values.key))
      const input = JSON.parse(readFileSync(values.in, 'utf8'))
      const env = await signManifest(input, key)
      writeFileSync(values.out, JSON.stringify(env, null, 2) + '\n')
      console.log(`${env.signatures.length} signature(s) now on ${values.out}`)
      return 0
    }

    if (sub === 'verify') {
      const file = positionals[0]
      if (!file) throw new Error('usage: frenet update verify ENVELOPE [...]')
      const rootsFile = values.roots ?? join(values.data!, 'update-roots.json')
      let roots: TrustRoots | null = null
      if (existsSync(rootsFile)) roots = validateRoots(JSON.parse(readFileSync(rootsFile, 'utf8')))
      else if (values.roots) throw new Error(`no such roots file: ${rootsFile}`)
      const store = new Store(existsSync(values.data!) ? values.data! : ':memory:')
      try {
        const updates = new Updates(store, roots, values.current ?? runningVersion())
        const r = await updates.check(JSON.parse(readFileSync(file, 'utf8')), values.channel)
        if (!r.ok) { console.error(`REFUSED: ${r.error}`); return 1 }
        for (const f of values.artifact ?? []) {
          if (statSync(f).size > 2 * 1024 ** 3) throw new Error(`${f} is too large`)
          const a = verifyArtifact(r.manifest, basename(f), readFileSync(f))
          if (!a.ok) { console.error(`REFUSED: ${basename(f)}: ${a.error}`); return 1 }
          console.log(`ok   ${basename(f)}`)
        }
        console.log(`VERIFIED ${r.manifest.channel} ${r.manifest.version} (seq ${r.manifest.seq}), ${r.signers.length} trusted signature(s), expires ${new Date(r.manifest.expires).toISOString()}`)
        if ((values.artifact ?? []).length === 0) console.log('note: no --artifact given, so no file was checked against the manifest')
        if (values.accept) {
          if ((values.artifact ?? []).length < r.manifest.artifacts.length) throw new Error('--accept needs every listed artifact to be passed with --artifact and verified')
          if (existsSync(values.data!)) { updates.accept(r.manifest); console.log('recorded: older releases on this channel will now be refused') }
          else console.log('note: data dir not found, rollback state was not recorded')
        }
      } finally { store.close() }
      return 0
    }
    console.error(USAGE)
    return 2
  } catch (e) {
    console.error(`error: ${(e as Error).message}`)
    return 1
  }
}
