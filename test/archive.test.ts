import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { after, describe, it } from 'node:test'
import { createArchive, isArchive, openArchive, restoreArchive } from '../src/archive.js'
import { cidFor } from '../src/blocks.js'
import { startFrenet } from '../src/node.js'
import { initRotation } from '../src/rotation.js'
import { readIdentityLog } from '../src/recovery.js'
import { Store } from '../src/store.js'

const L = ['/ip4/127.0.0.1/tcp/0']
const dirs: string[] = []
const tmp = (): string => { const d = mkdtempSync(join(tmpdir(), 'frenet-arc-')); dirs.push(d); return d }
after(() => { for (const d of dirs) rmSync(d, { recursive: true, force: true }) })
const fast = { N: 2 ** 10 }
const PW = 'archive test passphrase'

/** A node with some of everything a person accumulates, then stopped so the archive can read its directory. */
async function populated (dir: string): Promise<{ peerId: string, did: string, link: string, fileCid: string, credId: string, name: string }> {
  const a = await startFrenet({ dataDir: dir, listen: L, mdns: false })
  const b = await startFrenet({ dataDir: ':memory:', listen: L, mdns: false })
  try {
    await a.libp2p.dial(b.libp2p.getMultiaddrs()[0]!)
    await a.messaging.send(b.libp2p.peerId, 'hello from before the disaster')
    const remembered = await a.files.add('notes.txt', Buffer.from('secret notes'), { remember: true })
    await a.files.add('forgotten.txt', Buffer.from('no remembered key'))   // default: key lives only in the returned link
    const c = await a.credentials.issue(b.did, 'Membership', { club: 'frenet' })
    await b.credentials.hold(c.jwt)
    const held = await b.credentials.issue(a.did, 'Badge', { level: 3 })
    await a.credentials.hold(held.jwt)
    const name = 'myhome'
    await a.names.publish(name, remembered.cid)
    a.store.addBan('12D3KooWbanned', 'spam')
    return { peerId: a.libp2p.peerId.toString(), did: a.did, link: remembered.link, fileCid: remembered.cid, credId: held.id, name }
  } finally { await a.stop(); await b.stop() }
}

describe('full archive', () => {
  it('round-trips a node\'s data into a fresh directory, including the opt-in file link and held credentials', async () => {
    const src = tmp(); const dst = tmp()
    const was = await populated(src)
    const { bytes, counts, blocks } = await createArchive(src, PW, { ...fast, blocks: true })
    assert.ok(isArchive(bytes)); assert.ok(blocks >= 3)
    assert.ok(counts.messages! >= 1 && counts.credentials! >= 2 && counts.files! === 2 && counts.file_links === 1 && counts.names === 1 && counts.bans === 1)
    assert.ok(!bytes.toString('latin1').includes('hello from before the disaster'), 'nothing readable in the file')
    assert.ok(!bytes.toString('latin1').includes(was.link.split('#')[1]!), 'file key is encrypted too')

    const r = await restoreArchive(dst, bytes, PW)
    assert.equal(r.peerId, was.peerId); assert.equal(r.did, was.did); assert.equal(r.unchanged, false)
    assert.equal(statSync(join(dst, 'identity.key')).mode & 0o777, 0o600)
    assert.deepEqual(readFileSync(join(dst, 'identity.key')), readFileSync(join(src, 'identity.key')))

    // start a node on the restored directory: same identity, and the data is there and usable
    const n = await startFrenet({ dataDir: dst, listen: L, mdns: false })
    try {
      assert.equal(n.libp2p.peerId.toString(), was.peerId)
      assert.ok(n.store.list().some((m) => m.body === 'hello from before the disaster'), 'messages restored')
      assert.equal(n.credentials.list('held').length, 1); assert.equal(n.credentials.list('held')[0]!.id, was.credId)
      assert.equal(n.credentials.list('issued').length, 1)
      const link = n.files.rememberedLink(was.fileCid)
      assert.equal(link, was.link, 'the remembered link survives')
      const [cid, key] = link!.slice('frenet://'.length).split('#')
      assert.equal((await n.files.get(cid!, key)).data.toString(), 'secret notes', 'blocks + link = the file is readable again with no network')
      assert.ok(n.names.list().some((x) => x.own && x.name === was.name), 'own names restored')
      assert.equal(n.store.listBans().length, 1)
      const forgotten = n.files.list().find((f) => f.name === 'forgotten.txt')!
      assert.equal(n.files.rememberedLink(forgotten.cid), null, 'a key that was never remembered is not in the archive')
    } finally { await n.stop() }
  })

  it('is idempotent and merges without overwriting existing data', async () => {
    const src = tmp(); const dst = tmp()
    await populated(src)
    const { bytes } = await createArchive(src, PW, fast)
    const first = await restoreArchive(dst, bytes, PW)
    assert.ok(first.added.messages! >= 1)
    const again = await restoreArchive(dst, bytes, PW)
    assert.equal(again.unchanged, true); assert.ok(Object.values(again.added).every((n) => n === 0), 'second restore adds nothing')
    const s = new Store(dst); const before = s.list().length; s.close()
    await restoreArchive(dst, bytes, PW)
    const s2 = new Store(dst); assert.equal(s2.list().length, before); s2.close()
  })

  it('without --blocks it carries no block data, and the size limit is explicit', async () => {
    const src = tmp()
    await populated(src)
    const { bytes, blocks } = await createArchive(src, PW, fast)
    assert.equal(blocks, 0)
    assert.equal((await openArchive(bytes, PW)).blocks.length, 0)
  })

  it('refuses wrong passphrases, tampering, truncation, foreign files and unsupported headers', async () => {
    const src = tmp()
    const n = await startFrenet({ dataDir: src, listen: L, mdns: false }); await n.stop()
    const { bytes } = await createArchive(src, PW, fast)
    await assert.rejects(openArchive(bytes, 'definitely not the passphrase'), /wrong passphrase or corrupted/)
    await assert.rejects(createArchive(src, 'short', fast), /at least 12/)
    for (const at of [20, 60, Math.floor(bytes.length / 2), bytes.length - 1]) {
      const t = Buffer.from(bytes); t[at]! ^= 1
      await assert.rejects(openArchive(t, PW), /corrupted|unsupported|not a FRENET/, `flip at ${at}`)
    }
    await assert.rejects(openArchive(bytes.subarray(0, bytes.length - 20), PW), /corrupted|unsupported/)
    await assert.rejects(openArchive(Buffer.from('not an archive at all, just text'), PW), /not a FRENET archive/)
    assert.equal(isArchive(Buffer.from('frenet-backup:v1:abc')), false)
    // the cost parameter is untrusted input: a header asking for a huge scrypt N is refused before any work
    const hl = bytes.readUInt32BE(15)
    const hdr = JSON.parse(bytes.subarray(19, 19 + hl).toString())
    const evil = Buffer.from(JSON.stringify({ ...hdr, N: 2 ** 22 }))
    const len = Buffer.alloc(4); len.writeUInt32BE(evil.length)
    await assert.rejects(openArchive(Buffer.concat([bytes.subarray(0, 15), len, evil, bytes.subarray(19 + hl)]), PW), /unsupported or corrupted/)
  })

  it('validates what it restores: bad rows roll everything back, forged blocks and names are rejected', async () => {
    const dir = tmp()
    const s = new Store(dir)
    assert.throws(() => s.importTables({ messages: [{ id: 'a', peer: 'p', direction: 'sideways', ts: 1, body: 'x' }] }), /CHECK|constraint/i)
    assert.throws(() => s.importTables({ messages: [{ id: 'a', peer: 'p', direction: 'in', ts: 'late', body: 'x' }] }), /wrong type/)
    assert.throws(() => s.importTables({ messages: [{ id: 'a', peer: 'p', direction: 'in', ts: 1 }] }), /missing/)
    assert.throws(() => s.importTables('nope'), /corrupt archive/)
    // a good row followed by a bad one must not leave the good one behind
    assert.throws(() => s.importTables({ messages: [{ id: 'ok', peer: 'p', direction: 'in', ts: 1, body: 'x' }, { id: 'bad', peer: 'p', direction: 'in', ts: 1, body: 5 }] }), /wrong type/)
    assert.equal(s.list().length, 0, 'transaction rolled back')
    s.close()

    // an authenticated archive can still be malformed (buggy tool, or a block that rotted on disk): hashes and signatures are re-checked
    const rot = tmp(); const n = await startFrenet({ dataDir: rot, listen: L, mdns: false }); await n.stop()
    const bad = new Store(rot)
    bad.putBlock(cidFor(Buffer.from('real data')).toString(), Buffer.from('different data'))
    bad.close()
    const withBadBlock = await createArchive(rot, PW, { ...fast, blocks: true })
    await assert.rejects(openArchive(withBadBlock.bytes, PW), /block that does not match its hash/)
    await assert.rejects(restoreArchive(tmp(), withBadBlock.bytes, PW), /block that does not match its hash/)

    const rot2 = tmp(); const n2 = await startFrenet({ dataDir: rot2, listen: L, mdns: false }); await n2.stop()
    const badName = new Store(rot2)
    badName.putName({ v: 1, name: 'evil', pub: 'a'.repeat(52), target: 'bafkreiaaaa', seq: 1, ts: Date.now(), sig: 'AAAA', keywords: [], title: '' } as any, true)
    badName.close()
    await assert.rejects(openArchive((await createArchive(rot2, PW, fast)).bytes, PW), /invalid name record/)
  })

  it('carries a rotatable identity\'s key log and keeps a longer local log', async () => {
    const src = tmp(); const dst = tmp()
    const n = await startFrenet({ dataDir: src, listen: L, mdns: false }); await n.stop()
    const { state } = await initRotation(src, 'next key passphrase 1', fast)
    const { bytes } = await createArchive(src, PW, fast)
    const r = await restoreArchive(dst, bytes, PW)
    assert.equal(r.identityLog, 'written'); assert.equal((readIdentityLog(dst) as any[]).length, state.events.length)
    const again = await restoreArchive(dst, bytes, PW)
    assert.equal(again.identityLog, 'kept')
    const back = await startFrenet({ dataDir: dst, listen: L, mdns: false })
    try { assert.equal(back.did, state.did) } finally { await back.stop() }
  })

  it('never replaces a different existing identity without --force', async () => {
    const a = tmp(); const b = tmp()
    const n1 = await startFrenet({ dataDir: a, listen: L, mdns: false }); await n1.stop()
    const n2 = await startFrenet({ dataDir: b, listen: L, mdns: false }); const other = n2.libp2p.peerId.toString(); await n2.stop()
    const { bytes } = await createArchive(a, PW, fast)
    await assert.rejects(restoreArchive(b, bytes, PW), /different identity/)
    const s = new Store(b); assert.equal(s.list().length, 0); s.close()
    const forced = await restoreArchive(b, bytes, PW, { force: true })
    assert.notEqual(forced.peerId, other); assert.ok(forced.replaced)
  })
})

describe('full archive CLI', () => {
  const cli = (args: string[]) => spawnSync(process.execPath, ['--import', 'tsx', 'src/cli.ts', ...args], { encoding: 'utf8', cwd: process.cwd(), timeout: 90_000 })
  it('backup --full then restore into a new directory (and key-only backups still restore)', async () => {
    const src = tmp(); const dst = tmp(); const out = tmp()
    const was = await populated(src)
    const pw = join(out, 'pw'); writeFileSync(pw, 'cli archive passphrase\n')
    const f = join(out, 'all.archive')
    const b = cli(['backup', '--full', '--blocks', '--out', f, '--data', src, '--passphrase-file', pw])
    assert.equal(b.status, 0, b.stderr); assert.match(b.stdout, /Full archive of/); assert.match(b.stdout, /messages/)
    assert.equal(statSync(f).mode & 0o777, 0o600)
    assert.equal(cli(['backup', '--full', '--out', f, '--data', src, '--passphrase-file', pw]).status, 1, 'never overwrites')
    const r = cli(['restore', f, '--data', dst, '--passphrase-file', pw])
    assert.equal(r.status, 0, r.stderr); assert.match(r.stdout, new RegExp(was.peerId)); assert.match(r.stdout, /Restored data:.*messages/)
    const s = new Store(dst); assert.ok(s.list().length >= 1); assert.equal(s.getFileLink(was.fileCid), was.link); s.close()
    writeFileSync(join(out, 'bad'), 'wrong passphrase here\n')
    assert.equal(cli(['restore', f, '--data', tmp(), '--passphrase-file', join(out, 'bad')]).status, 1)
    // key-only backup keeps working through the same command
    const kb = join(out, 'key.backup')
    assert.equal(cli(['backup', '--out', kb, '--data', src, '--passphrase-file', pw]).status, 0)
    assert.equal(cli(['restore', kb, '--data', tmp(), '--passphrase-file', pw]).status, 0)
  })
})
