import { closeSync, existsSync, openSync, readFileSync, writeFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'
import { parseArgs } from 'node:util'
import { createArchive, isArchive, restoreArchive } from './archive.js'
import { didFromPublicKeyRaw } from './did.js'
import { loadOrCreateIdentity } from './identity.js'
import { verifyLog } from './identity-log.js'
import { normalizeHandle, signHandleProof, validHandle } from './webid.js'
import { combineShares, createBackup, describeKey, installKey, MAX_SHARES, MIN_PASSPHRASE, openBackup, readIdentityLog, readKeyFile, splitSecret } from './recovery.js'
import { initRotation, rotateIdentity } from './rotation.js'

/**
 * `frenet identity | backup | restore | recovery split|restore`. Key material only ever moves through files, the
 * terminal and stdin here; it is deliberately not exposed on the HTTP API. Run these with the node stopped.
 */
export const IDENTITY_COMMANDS = ['identity', 'backup', 'restore', 'recovery']

const USAGE = `frenet identity [--data DIR]                         show peer ID and DID(s)
frenet identity rotation-init --next-out FILE [--passphrase-file F]   make the identity rotatable (did:frenet); writes the offline NEXT-key backup
frenet identity rotate --next-key FILE --next-out FILE2 [--log F] [--passphrase-file F] [--next-passphrase-file F]   rotate to the next key (also the recovery path for a lost/stolen key)
frenet identity handle-proof alice@example.com [--data DIR]   print the entry to put in https://example.com/.well-known/frenet-names.json (signed by your did:key)
frenet identity log [--data DIR]                                  print the public key log (keep a copy with your next-key backup)
frenet backup --out FILE [--data DIR] [--passphrase-file F]       write a passphrase-encrypted backup of the key only
frenet backup --full --out FILE [--blocks] [--data DIR]           key + messages, files, file links, names, communities, credentials (+ own blocks with --blocks)
frenet restore FILE [--data DIR] [--passphrase-file F] [--force]   restore a key backup or a full archive (detected automatically)
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
      'next-passphrase-file': { type: 'string' },
      'next-out': { type: 'string' },
      'next-key': { type: 'string' },
      log: { type: 'string' },
      file: { type: 'string' },
      force: { type: 'boolean', default: false },
      full: { type: 'boolean', default: false },
      blocks: { type: 'boolean', default: false },
      k: { type: 'string', short: 'k' },
      n: { type: 'string', short: 'n' },
      help: { type: 'boolean', short: 'h', default: false }
    }
  })
  const data = values.data!
  try {
    if (values.help) { console.log(USAGE); return 0 }

    if (cmd === 'identity') {
      const sub = positionals[0]
      if (sub === 'rotation-init') {
        if (!values['next-out']) throw new Error('--next-out FILE is required (the offline backup of the next key)')
        process.stderr.write('Choose a passphrase for the NEXT key (the recovery key). Store its backup file OFF this machine.\n')
        const { state, nextBackup } = await initRotation(data, await passphrase(values['passphrase-file'], !values['passphrase-file']))
        writeNew(values['next-out'], nextBackup)
        console.log(`Identity is now rotatable.\nDID ${state.did}\nNext-key backup written to ${values['next-out']}`)
        console.log('Move that file (and a copy of `frenet identity log`) somewhere other than this machine. Anyone with the file and its passphrase can take over the identity on the next rotation; without it you cannot rotate.')
        console.log('Restart the node: credentials are now issued under the did:frenet.')
        return 0
      }
      if (sub === 'rotate') {
        if (!values['next-key'] || !values['next-out']) throw new Error('usage: frenet identity rotate --next-key FILE --next-out FILE2 [--log FILE]')
        const logEvents = values.log ? JSON.parse(readFileSync(values.log, 'utf8')) as unknown[] : undefined
        const pw = await passphrase(values['passphrase-file'], false)
        const pw2 = values['next-passphrase-file'] ? await passphrase(values['next-passphrase-file'], false) : values['passphrase-file'] ? pw : await (async () => { process.stderr.write('Choose a passphrase for the NEW next key.\n'); return await passphrase(undefined, true) })()
        const r = await rotateIdentity(data, readFileSync(values['next-key'], 'utf8'), pw, pw2, logEvents ? { logEvents } : {})
        writeNew(values['next-out'], r.nextBackup)
        console.log(`Rotated to key #${r.state.seq}. DID unchanged: ${r.did}\nNew peer ID: ${r.peerId}`)
        if (r.replaced) console.log(`Previous key kept at ${r.replaced}`)
        console.log(`New next-key backup written to ${values['next-out']}. The old next-key backup is now useless: destroy it.`)
        console.log('Start the node. Site names (<name>.<key>) belong to the old key and must be republished; peers learn of the rotation from the key log. If the old key was stolen, assume everything signed with it after the theft is suspect.')
        return 0
      }
      if (sub === 'handle-proof') {
        const handle = normalizeHandle(positionals[1] ?? '')
        if (!validHandle(handle)) throw new Error('usage: frenet identity handle-proof local@domain')
        const { key } = await loadOrCreateIdentity(data)
        const did = didFromPublicKeyRaw(key.publicKey.raw)
        const proof = await signHandleProof(key, handle, did)
        console.log(JSON.stringify({ v: 1, names: { [handle.split('@')[0]!]: { did, proof } } }, null, 2))
        console.log(`\nServe this (merge into an existing file) at https://${handle.split('@')[1]}/.well-known/frenet-names.json`, '\n')
        return 0
      }
      if (sub === 'log') {
        const ev = readIdentityLog(data)
        if (!ev) throw new Error('this identity has no key log (run: frenet identity rotation-init)')
        await verifyLog(ev)
        console.log(JSON.stringify(ev, null, 1))
        return 0
      }
      if (sub !== undefined) { console.error(USAGE); return 2 }
      const i = describeKey(readKeyFile(data))
      const ev = readIdentityLog(data)
      console.log(`peer ID ${i.peerId}`)
      if (ev) { const st = await verifyLog(ev); console.log(`DID     ${st.did}   (rotatable, key #${st.seq})\nkey DID ${i.did}`) } else console.log(`DID     ${i.did}   (fixed key: run \`frenet identity rotation-init\` to make it rotatable)`)
      return 0
    }

    if (cmd === 'backup') {
      if (!values.out) throw new Error('--out FILE is required')
      if (values.full) {
        const a = await createArchive(data, await passphrase(values['passphrase-file'], !values['passphrase-file']), { blocks: values.blocks })
        writeNew(values.out, a.bytes)
        console.log(`Full archive of ${a.peerId} written to ${values.out}: ${Object.entries(a.counts).filter(([, n]) => n > 0).map(([t, n]) => `${n} ${t}`).join(', ') || 'no data yet'}${values.blocks ? `, ${a.blocks} blocks` : ''}`)
        console.log('It holds your private key and your private data. Keep the file and the passphrase apart; test the restore once. File keys are included only for files uploaded with "remember".')
        return 0
      }
      const key = readKeyFile(data)
      const text = await createBackup(key, await passphrase(values['passphrase-file'], !values['passphrase-file']))
      writeNew(values.out, text + '\n')
      console.log(`Backup of ${describeKey(key).peerId} written to ${values.out}`)
      console.log('Anyone with this file AND the passphrase has your identity. Keep them apart; test the restore once.')
      return 0
    }

    if (cmd === 'restore') {
      const file = positionals[0]
      if (!file) throw new Error('usage: frenet restore FILE')
      if (!existsSync(file)) throw new Error(`no such file: ${file}`)
      const raw = readFileSync(file)
      if (isArchive(raw)) {
        const r = await restoreArchive(data, raw, await passphrase(values['passphrase-file'], false), { force: values.force })
        report(r, data)
        const rows = Object.entries(r.added).filter(([, n]) => n > 0).map(([t, n]) => `${n} ${t}`).join(', ')
        console.log(`Restored data: ${rows || 'nothing new (already present)'}${r.blocks ? `, ${r.blocks} blocks` : ''}${r.identityLog === 'written' ? '; key log restored' : ''}`)
        return 0
      }
      const b = await openBackup(raw.toString('utf8'), await passphrase(values['passphrase-file'], false))
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

/** Write a new file (0600) and never overwrite an existing one. */
function writeNew (file: string, data: string | Buffer): void {
  const fd = openSync(file, 'wx', 0o600)
  try { writeFileSync(fd, typeof data === 'string' && !data.endsWith('\n') ? data + '\n' : data) } finally { closeSync(fd) }
}

function report (r: { peerId: string, did: string, replaced: string | null, unchanged: boolean }, data: string): void {
  console.log(r.unchanged ? `Identity already present in ${data}: ${r.peerId}` : `Identity restored to ${data}: ${r.peerId}`)
  console.log(`DID ${r.did}`)
  if (r.replaced) console.log(`Previous key kept at ${r.replaced}`)
  console.log('Start the node: names and other data signed by this key work again. A key backup restores the key only; use a full archive (frenet backup --full) to carry messages, files, credentials and the rest.')
}
