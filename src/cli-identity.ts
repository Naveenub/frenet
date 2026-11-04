import { closeSync, existsSync, openSync, readFileSync, writeFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'
import { parseArgs } from 'node:util'
import { combineShares, createBackup, describeKey, installKey, MAX_SHARES, MIN_PASSPHRASE, openBackup, readKeyFile, splitSecret } from './recovery.js'

/**
 * `frenet identity | backup | restore | recovery split|restore`. Key material only ever moves through files, the
 * terminal and stdin here; it is deliberately not exposed on the HTTP API. Run these with the node stopped.
 */
export const IDENTITY_COMMANDS = ['identity', 'backup', 'restore', 'recovery']

const USAGE = `frenet identity [--data DIR]                         show peer ID and DID
frenet backup --out FILE [--data DIR] [--passphrase-file F]       write a passphrase-encrypted backup of the key
frenet restore FILE [--data DIR] [--passphrase-file F] [--force]   restore the key from a backup
frenet recovery split -k K -n N [--data DIR]                      split the key into N shares, any K recover it
frenet recovery restore [SHARE...] [--file F] [--data DIR] [--force]   rebuild the key from K shares (args, file, stdin, or prompt)`

const defaultData = (): string => process.env.FRENET_DATA ?? join(homedir(), '.frenet')

function promptHidden (q: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const stdin = process.stdin
    if (!stdin.isTTY) { reject(new Error('no terminal to prompt on: pass --passphrase-file (or pipe shares in)')); return }
    process.stderr.write(q)
    stdin.setRawMode(true); stdin.resume(); stdin.setEncoding('utf8')
    let buf = ''
    const done = (fn: () => void): void => { stdin.off('data', onData); stdin.setRawMode(false); stdin.pause(); process.stderr.write('\n'); fn() }
    const onData = (chunk: string): void => {
      for (const c of chunk) {
        if (c === '\r' || c === '\n' || c === '\u0004') return done(() => resolve(buf))
        if (c === '\u0003') return done(() => reject(new Error('cancelled')))
        buf = c === '\u007f' || c === '\b' ? buf.slice(0, -1) : buf + c
      }
    }
    stdin.on('data', onData)
  })
}

async function passphrase (file: string | undefined, confirm: boolean): Promise<string> {
  if (file) return readFileSync(file, 'utf8').replace(/\r?\n$/, '')
  const a = await promptHidden('Passphrase: ')
  if (confirm) {
    if ([...a].length < MIN_PASSPHRASE) throw new Error(`passphrase must be at least ${MIN_PASSPHRASE} characters`)
    if (a !== await promptHidden('Repeat passphrase: ')) throw new Error('passphrases do not match')
  }
  return a
}

export async function runIdentityCommand (cmd: string, argv: string[]): Promise<number> {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      data: { type: 'string', default: defaultData() },
      out: { type: 'string' },
      'passphrase-file': { type: 'string' },
      file: { type: 'string' },
      force: { type: 'boolean', default: false },
      k: { type: 'string', short: 'k' },
      n: { type: 'string', short: 'n' },
      help: { type: 'boolean', short: 'h', default: false }
    }
  })
  const data = values.data!
  try {
    if (values.help) { console.log(USAGE); return 0 }

    if (cmd === 'identity') {
      const i = describeKey(readKeyFile(data))
      console.log(`peer ID ${i.peerId}\nDID     ${i.did}`)
      return 0
    }

    if (cmd === 'backup') {
      if (!values.out) throw new Error('--out FILE is required')
      const key = readKeyFile(data)
      const text = await createBackup(key, await passphrase(values['passphrase-file'], !values['passphrase-file']))
      const fd = openSync(values.out, 'wx', 0o600)   // never overwrite an existing file
      try { writeFileSync(fd, text + '\n') } finally { closeSync(fd) }
      console.log(`Backup of ${describeKey(key).peerId} written to ${values.out}`)
      console.log('Anyone with this file AND the passphrase has your identity. Keep them apart; test the restore once.')
      return 0
    }

    if (cmd === 'restore') {
      const file = positionals[0]
      if (!file) throw new Error('usage: frenet restore FILE')
      if (!existsSync(file)) throw new Error(`no such file: ${file}`)
      const b = await openBackup(readFileSync(file, 'utf8'), await passphrase(values['passphrase-file'], false))
      report(installKey(data, b.protobuf, { force: values.force }), data)
      return 0
    }

    if (cmd === 'recovery') {
      const sub = positionals[0]
      if (sub === 'split') {
        const k = Number(values.k); const n = Number(values.n)
        if (!Number.isInteger(k) || !Number.isInteger(n)) throw new Error(`usage: frenet recovery split -k K -n N (2 <= K <= N <= ${MAX_SHARES})`)
        const key = readKeyFile(data)
        const shares = splitSecret(key, k, n)
        process.stderr.write(`Identity ${describeKey(key).peerId}: ${n} shares, any ${k} recover it. Fewer than ${k} reveal nothing.\n` +
          'Give each share to a different person or place. Do not keep them together, and do not send them over an untrusted channel.\n')
        for (const s of shares) console.log(s)
        return 0
      }
      if (sub === 'restore') {
        let shares = positionals.slice(1)
        if (values.file) shares = shares.concat(readFileSync(values.file, 'utf8').split(/\r?\n/))
        if (shares.length === 0 && !process.stdin.isTTY) shares = readFileSync(0, 'utf8').split(/\r?\n/)
        if (shares.length === 0) {
          for (;;) { const s = await promptHidden('Share (empty line to finish): '); if (s.trim() === '') break; shares.push(s) }
        }
        shares = shares.map((s) => s.trim()).filter((s) => s !== '' && !s.startsWith('#'))
        report(installKey(data, combineShares(shares), { force: values.force }), data)
        return 0
      }
    }
    console.error(USAGE)
    return 2
  } catch (e) {
    console.error(`error: ${(e as Error).message}`)
    return 1
  }
}

function report (r: { peerId: string, did: string, replaced: string | null, unchanged: boolean }, data: string): void {
  console.log(r.unchanged ? `Identity already present in ${data}: ${r.peerId}` : `Identity restored to ${data}: ${r.peerId}`)
  console.log(`DID ${r.did}`)
  if (r.replaced) console.log(`Previous key kept at ${r.replaced}`)
  console.log('Start the node: names and other data signed by this key work again. Messages, blocks and credentials stored in the old data directory are not part of the key and are not restored.')
}
