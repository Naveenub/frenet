// Helper for scripts/crosscheck-shamir.py.
//   node --import tsx scripts/shamir-vectors.ts            -> JSON: random secrets with their shares
//   node --import tsx scripts/shamir-vectors.ts combine    -> reads [[share,...],...] on stdin, prints each recovered secret (hex)
import { randomBytes } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { combineShares, splitSecret } from '../src/recovery.js'

if (process.argv[2] === 'combine') {
  const sets = JSON.parse(readFileSync(0, 'utf8')) as string[][]
  console.log(JSON.stringify(sets.map((s) => Buffer.from(combineShares(s)).toString('hex'))))
} else {
  const out = []
  for (const [k, n, len] of [[2, 2, 36], [2, 3, 1], [3, 5, 68], [5, 7, 68], [4, 4, 200], [7, 20, 68], [2, 32, 36], [16, 32, 68]] as const) {
    const secret = randomBytes(len)
    out.push({ k, n, secret: secret.toString('hex'), shares: splitSecret(secret, k, n) })
  }
  console.log(JSON.stringify(out))
}
