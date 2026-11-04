import { generateKeyPair, privateKeyFromProtobuf, privateKeyToProtobuf } from '@libp2p/crypto/keys'
import type { PrivateKey } from '@libp2p/interface'
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

/**
 * Ed25519 identity. The private key lives only in <dataDir>/identity.key (mode 0600)
 * and is never sent over the network or to any server.
 */
export async function loadOrCreateIdentity (dataDir: string): Promise<{ key: PrivateKey, created: boolean }> {
  mkdirSync(dataDir, { recursive: true, mode: 0o700 })
  const file = join(dataDir, 'identity.key')
  if (existsSync(file)) {
    return { key: privateKeyFromProtobuf(readFileSync(file)), created: false }
  }
  const key = await generateKeyPair('Ed25519')
  writeFileSync(file, privateKeyToProtobuf(key), { mode: 0o600 })
  chmodSync(file, 0o600)
  return { key, created: true }
}
