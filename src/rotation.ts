import { generateKeyPair, privateKeyFromProtobuf, privateKeyToProtobuf } from '@libp2p/crypto/keys'
import { createInception, createRotation, keyDigest, verifyLog, type IdentityState } from './identity-log.js'
import { createBackup, installKey, openBackup, readIdentityLog, readKeyFile, writeIdentityLog } from './recovery.js'

/**
 * Setting up and performing key rotation (see identity-log.ts for the model). Both operations are offline file
 * operations for the CLI, with the node stopped.
 *
 * The *next key* is the recovery key: it is generated here, sealed under its own passphrase and handed back as a backup
 * text for the caller to store OFF the machine. It is never written into the data directory.
 */

/** Turn the current key into the inception of a did:frenet identity and mint its first pre-committed next key. */
export async function initRotation (dataDir: string, passphrase: string, opts: { N?: number } = {}): Promise<{ state: IdentityState, nextBackup: string }> {
  if (readIdentityLog(dataDir)) throw new Error('this identity already has a key log (did:frenet); rotate it instead')
  const current = privateKeyFromProtobuf(readKeyFile(dataDir))
  const next = await generateKeyPair('Ed25519')
  const nextBackup = await createBackup(privateKeyToProtobuf(next), passphrase, opts)   // also validates the passphrase
  const state = await createInception(current, next.publicKey)
  writeIdentityLog(dataDir, state.events)
  return { state, nextBackup }
}

/**
 * Rotate to the pre-committed next key. Works even if the current key is lost or stolen, as long as the log is
 * available (data dir, or `logEvents` exported earlier or fetched from a running node via /api/identity/log).
 * Installs the next key as the node's key (the old one is kept as identity.key.replaced-*), appends the rotation to the
 * log, and returns a backup of the *new* next key. The peer ID changes; the DID does not.
 */
export async function rotateIdentity (dataDir: string, nextKeyBackup: string, passphrase: string, newNextPassphrase: string, opts: { logEvents?: unknown[], N?: number } = {}):
Promise<{ state: IdentityState, nextBackup: string, peerId: string, did: string, replaced: string | null }> {
  const events = opts.logEvents ?? readIdentityLog(dataDir)
  if (!events) throw new Error('no identity log: pass the exported log (frenet identity log, or GET /api/identity/log) or run rotation-init first')
  const before = await verifyLog(events)
  const opened = await openBackup(nextKeyBackup, passphrase)
  const newKey = privateKeyFromProtobuf(opened.protobuf)
  if (keyDigest(newKey.publicKey.raw) !== before.next) throw new Error('this backup is not the pre-committed next key for this identity (wrong file, or an older generation)')
  const next2 = await generateKeyPair('Ed25519')
  const nextBackup = await createBackup(privateKeyToProtobuf(next2), newNextPassphrase, opts)
  const state = await createRotation(before, newKey, next2.publicKey)
  const installed = installKey(dataDir, opened.protobuf, { force: true })
  writeIdentityLog(dataDir, state.events)
  return { state, nextBackup, peerId: installed.peerId, did: state.did, replaced: installed.replaced }
}
