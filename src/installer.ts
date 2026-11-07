import { createHash, randomBytes } from 'node:crypto'
import { chmodSync, closeSync, copyFileSync, existsSync, fsyncSync, lstatSync, mkdirSync, openSync, readdirSync, readFileSync, realpathSync, renameSync, rmSync, statSync, unlinkSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { MAX_ARTIFACT_BYTES, MAX_ENVELOPE_BYTES, verifyArtifact, type UpdateEnvelope, type UpdateManifest, type Updates } from './updates.js'

/**
 * Update downloader and installer. Operator-initiated only: nothing here runs on a timer, from the API or from the
 * network, and nothing here executes, unpacks or restarts anything.
 *
 *   fetch    download the signed manifest and its artifacts over HTTPS, verify the manifest against the pinned trust
 *            roots (threshold signatures, expiry, rollback) and every artifact against the signed size and SHA-256,
 *            and only then keep them in a staging directory.
 *   install  verify the staged files AGAIN (they sit on disk between the two steps), save the files they replace into
 *            a backup directory, and put the new ones in a target directory with write-temp-then-rename, so a file is
 *            either the old version or the new one, never half of either. If any file fails, the ones already
 *            replaced are put back. Only after every file is in place is the manifest recorded as accepted, which is
 *            what makes older releases refuse from then on.
 *   rollback put the files of the latest install back from its backup.
 *
 * What it does not do: unpack archives, run installers or scripts, restart the node, pick the right artifact for your
 * platform, or sandbox anything. An artifact is a file; what it is and how to start it is up to the operator. The
 * only trust decision is the signature check, so the trust roots are pinned by you, out of band.
 */

const MAX_REDIRECTS = 5
const FETCH_TIMEOUT_MS = 10 * 60_000
const LOCAL_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]'])

const sha = (b: Uint8Array): string => createHash('sha256').update(b).digest('hex')

function checkUrl (u: URL): void {
  if (u.protocol === 'https:') return
  if (u.protocol === 'http:' && LOCAL_HOSTS.has(u.hostname)) return   // loopback only: nothing crosses a network
  throw new Error(`refusing ${u.protocol}//${u.hostname}: updates are fetched over https only (http works on localhost)`)
}

/** GET with a hard byte cap, a timeout, and https-only redirects. The cap is enforced while reading, not from Content-Length. */
export async function download (url: string, maxBytes: number, timeoutMs = FETCH_TIMEOUT_MS): Promise<Buffer> {
  let u = new URL(url)
  checkUrl(u)
  for (let hops = 0; ; hops++) {
    const res = await fetch(u, { redirect: 'manual', signal: AbortSignal.timeout(timeoutMs), headers: { 'user-agent': 'frenet-updater' } })
    if (res.status >= 300 && res.status < 400) {
      const loc = res.headers.get('location')
      await res.body?.cancel().catch(() => {})
      if (!loc || hops >= MAX_REDIRECTS) throw new Error(`too many redirects or no location fetching ${url}`)
      u = new URL(loc, u)
      checkUrl(u)   // a redirect may not downgrade to plain http
      continue
    }
    if (!res.ok) { await res.body?.cancel().catch(() => {}); throw new Error(`${u.href}: HTTP ${res.status}`) }
    const declared = Number(res.headers.get('content-length') ?? 0)
    if (declared > maxBytes) { await res.body?.cancel().catch(() => {}); throw new Error(`${u.href} is larger than the allowed ${maxBytes} bytes`) }
    const chunks: Buffer[] = []
    let n = 0
    if (!res.body) throw new Error(`${u.href}: empty response`)
    for await (const c of res.body as unknown as AsyncIterable<Uint8Array>) {
      n += c.byteLength
      if (n > maxBytes) throw new Error(`${u.href} is larger than the allowed ${maxBytes} bytes`)
      chunks.push(Buffer.from(c))
    }
    return Buffer.concat(chunks)
  }
}

const dirs = (dataDir: string): { root: string, staged: string, backups: string } => {
  const root = join(dataDir, 'updates')
  return { root, staged: join(root, 'staged'), backups: join(root, 'backups') }
}
const mk = (p: string): void => { mkdirSync(p, { recursive: true, mode: 0o700 }) }

/** Write a file so that it appears complete or not at all (temp file in the same directory, fsync, rename). */
function writeAtomic (path: string, data: Uint8Array, mode: number): void {
  const tmp = `${path}.frenet-tmp-${randomBytes(6).toString('hex')}`
  const fd = openSync(tmp, 'wx', mode)
  try {
    writeFileSync(fd, data)
    fsyncSync(fd)
  } catch (e) { closeSync(fd); try { unlinkSync(tmp) } catch { /* gone */ } throw e }
  closeSync(fd)
  try { chmodSync(tmp, mode); renameSync(tmp, path) } catch (e) { try { unlinkSync(tmp) } catch { /* gone */ } throw e }
}

/** Only one fetch/install/rollback at a time per data directory. */
function withLock<T> (dataDir: string, fn: () => Promise<T> | T): Promise<T> {
  const { root } = dirs(dataDir)
  mk(root)
  const lock = join(root, '.lock')
  let fd: number
  try { fd = openSync(lock, 'wx', 0o600) } catch { return Promise.reject(new Error(`another update operation is running (remove ${lock} if no other process is)`)) }
  closeSync(fd)
  return Promise.resolve().then(fn).finally(() => { try { unlinkSync(lock) } catch { /* gone */ } })
}

export interface FetchResult { dir: string, manifest: UpdateManifest, signers: string[], files: string[] }

/**
 * Download and verify a release. `baseUrl` is a directory URL holding `manifest.json` (the signed envelope) and the
 * artifacts under their listed names. Nothing is staged unless the manifest verified and every artifact matched.
 */
export async function fetchUpdate (o: { baseUrl: string, dataDir: string, updates: Updates, channel?: string, maxArtifactBytes?: number }): Promise<FetchResult> {
  const base = new URL(o.baseUrl.endsWith('/') ? o.baseUrl : `${o.baseUrl}/`)
  checkUrl(base)
  const channel = o.channel ?? 'stable'
  return withLock(o.dataDir, async () => {
    const envBytes = await download(new URL('manifest.json', base).href, MAX_ENVELOPE_BYTES * 2)
    let envelope: UpdateEnvelope
    try { envelope = JSON.parse(envBytes.toString('utf8')) } catch { throw new Error('manifest.json is not JSON') }
    const r = await o.updates.check(envelope, channel)
    if (!r.ok) throw new Error(`manifest refused: ${r.error}`)
    const cap = Math.min(o.maxArtifactBytes ?? MAX_ARTIFACT_BYTES, MAX_ARTIFACT_BYTES)
    const verified: Array<{ name: string, bytes: Buffer }> = []
    for (const a of r.manifest.artifacts) {
      if (a.size > cap) throw new Error(`${a.name}: signed size ${a.size} exceeds the allowed ${cap}`)
      const bytes = await download(new URL(encodeURIComponent(a.name), base).href, a.size)   // never reads more than the signed size
      const v = verifyArtifact(r.manifest, a.name, bytes)
      if (!v.ok) throw new Error(`${a.name}: ${v.error}`)
      verified.push({ name: a.name, bytes })
    }
    const { staged } = dirs(o.dataDir)
    const dir = join(staged, `${r.manifest.channel}-${r.manifest.version}-seq${r.manifest.seq}`)
    mk(staged)
    rmSync(dir, { recursive: true, force: true })
    mk(dir)
    for (const f of verified) writeAtomic(join(dir, f.name), f.bytes, 0o600)
    writeAtomic(join(dir, 'manifest.json'), Buffer.from(JSON.stringify(envelope, null, 2) + '\n'), 0o600)
    return { dir, manifest: r.manifest, signers: r.signers, files: verified.map((f) => f.name) }
  })
}

interface BackupRecord { version: string, seq: number, channel: string, ts: number, files: Array<{ name: string, existed: boolean, installedSha256: string }> }

export interface InstallResult { version: string, seq: number, installed: string[], replaced: string[], backup: string }

function readStaged (dir: string, m: UpdateManifest): Map<string, Buffer> {
  const out = new Map<string, Buffer>()
  for (const a of m.artifacts) {
    const p = join(dir, a.name)
    const st = lstatSync(p)
    if (!st.isFile()) throw new Error(`${a.name}: staged entry is not a regular file`)
    if (st.size !== a.size) throw new Error(`${a.name}: staged size ${st.size} does not match signed size ${a.size}`)
    const bytes = readFileSync(p)
    const v = verifyArtifact(m, a.name, bytes)
    if (!v.ok) throw new Error(`${a.name}: ${v.error}`)
    out.set(a.name, bytes)
  }
  return out
}

/** Install a staged release into `target`. Re-verifies everything first; all-or-nothing; records acceptance last. */
export async function installStaged (o: { stagedDir: string, target: string, dataDir: string, updates: Updates, channel?: string }): Promise<InstallResult> {
  return withLock(o.dataDir, async () => {
    const stagedRoot = existsSync(o.stagedDir) ? realpathSync(o.stagedDir) : null
    if (!stagedRoot) throw new Error(`no such staged directory: ${o.stagedDir}`)
    if (!existsSync(o.target) || !statSync(o.target).isDirectory()) throw new Error(`target must be an existing directory: ${o.target}`)
    const target = realpathSync(o.target)
    if (target === stagedRoot) throw new Error('target must not be the staging directory')
    let envelope: UpdateEnvelope
    try { envelope = JSON.parse(readFileSync(join(stagedRoot, 'manifest.json'), 'utf8')) } catch { throw new Error('staged directory has no readable manifest.json') }
    const r = await o.updates.check(envelope, o.channel ?? 'stable')   // signatures, expiry, rollback and downgrade, again
    if (!r.ok) throw new Error(`manifest refused: ${r.error}`)
    const files = readStaged(stagedRoot, r.manifest)

    const { backups } = dirs(o.dataDir)
    const backup = join(backups, `${new Date().toISOString().replace(/[:.]/g, '-')}-${r.manifest.version}`)
    mk(backups); mk(backup)
    const rec: BackupRecord = { version: r.manifest.version, seq: r.manifest.seq, channel: r.manifest.channel, ts: Date.now(), files: [] }
    const done: string[] = []
    try {
      for (const a of r.manifest.artifacts) {
        const dest = join(target, a.name)
        let mode = 0o644
        let existed = false
        if (existsSync(dest) || lstatIsLink(dest)) {
          const st = lstatSync(dest)
          if (!st.isFile()) throw new Error(`${a.name}: the existing entry in the target is not a regular file; refusing to replace it`)
          existed = true
          mode = st.mode & 0o777
          copyFileSync(dest, join(backup, a.name))
        }
        rec.files.push({ name: a.name, existed, installedSha256: a.sha256 })
        writeFileSync(join(backup, 'backup.json'), JSON.stringify(rec))   // written before the first replace so a crash can still be rolled back by hand
        writeAtomic(dest, files.get(a.name)!, mode)
        done.push(a.name)
      }
    } catch (e) {
      restore(rec, backup, target, done)   // put back what was already replaced
      throw new Error(`install failed and was rolled back: ${(e as Error).message}`)
    }
    o.updates.accept(r.manifest)
    return { version: r.manifest.version, seq: r.manifest.seq, installed: done, replaced: rec.files.filter((f) => f.existed).map((f) => f.name), backup }
  })
}

function lstatIsLink (p: string): boolean { try { return lstatSync(p).isSymbolicLink() } catch { return false } }

function restore (rec: BackupRecord, backup: string, target: string, names: string[]): string[] {
  const restored: string[] = []
  for (const f of rec.files) {
    if (!names.includes(f.name)) continue
    const dest = join(target, f.name)
    if (f.existed) writeAtomic(dest, readFileSync(join(backup, f.name)), statSync(join(backup, f.name)).mode & 0o777)
    else if (existsSync(dest)) unlinkSync(dest)
    restored.push(f.name)
  }
  return restored
}

/** Put the files of the most recent install back from its backup. Does not lower the recorded release sequence. */
export async function rollbackLast (o: { target: string, dataDir: string }): Promise<{ version: string, restored: string[], skipped: string[] }> {
  return withLock(o.dataDir, () => {
    const { backups } = dirs(o.dataDir)
    const names = existsSync(backups) ? readdirSync(backups).filter((n) => !n.endsWith('.rolled-back') && existsSync(join(backups, n, 'backup.json'))).sort() : []
    const last = names[names.length - 1]
    if (!last) throw new Error('no install to roll back')
    const dir = join(backups, last)
    const rec = JSON.parse(readFileSync(join(dir, 'backup.json'), 'utf8')) as BackupRecord
    const target = realpathSync(o.target)
    const skipped: string[] = []
    const ok: string[] = []
    for (const f of rec.files) {
      const dest = join(target, f.name)
      // Only touch a file that is still exactly what the install put there; anything newer is the operator's.
      if (existsSync(dest) && sha(readFileSync(dest)) !== f.installedSha256) { skipped.push(f.name); continue }
      ok.push(f.name)
    }
    const restored = restore(rec, dir, target, ok)
    renameSync(dir, `${dir}.rolled-back`)   // so the next rollback goes one install further back
    return { version: rec.version, restored, skipped }
  })
}
