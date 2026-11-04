# Security
- Crypto: Noise (XX), Ed25519 and AES-256-GCM via libp2p / `@libp2p/crypto` / Node `crypto`; scrypt for backup passphrases; Shamir secret sharing over GF(2^8) for recovery shares (a textbook construction, ~60 lines in `src/recovery.ts`, covered by tests, **not independently reviewed**). No custom ciphers or signature schemes.
- Private keys never leave `<data>/identity.key` (0600) except through the explicit recovery commands below. The HTTP API never returns key material.
- This is unaudited pre-release software. Do not rely on it for high-risk use.
- Report vulnerabilities privately to the maintainers before disclosure.

## Identity, credentials and recovery
Your Ed25519 key is your account: peer ID, `did:key`, your `<name>.<pub>` addresses and the credentials you issue are all derived from it.

**Back it up before you need it** (stop the node first):
```bash
frenet backup --out ~/frenet.backup           # passphrase-encrypted (scrypt + AES-256-GCM), min 12 chars
frenet recovery split -k 3 -n 5               # 5 shares, any 3 rebuild the key, 2 reveal nothing
frenet restore ~/frenet.backup                # or: frenet recovery restore SHARE SHARE SHARE
```
- A backup file alone is useless without its passphrase; a passphrase alone is useless without the file. Keep them apart. Shares: give each to a different person or place and never keep k of them together, because **k shares are the whole key**. Test a restore into a scratch directory (`--data`) once.
- Restoring a key restores the *same* identity: same peer ID, DID and names. It does not restore messages, stored blocks, held credentials (export them with `GET /api/credentials` and keep the JWTs) or file links/keys, which the node never stores.
- Restore never overwrites a different existing key unless you pass `--force`, and then keeps the old key as `identity.key.replaced-<time>`.

**What recovery cannot fix.**
- **A stolen key.** Whoever holds the key is you. A `did:key` cannot be rotated or revoked, so there is no way to tell peers "the old key is dead". If the key may be compromised, treat the identity as burned: create a new one and re-announce it out of band.
- **Backup passphrase strength.** An offline attacker with the backup file can guess passphrases at scrypt N=2^17 speed; use a long random passphrase.
- Share arithmetic uses table lookups (not constant time). Run split/restore on a machine you control.
- Running split/restore with a node live on the same data directory is unsupported.

**Credentials.** VC-JWTs are verified offline against the issuer's DID, with `alg` pinned to EdDSA. Expiry and issuer-signed revocation statements are honoured, but revocation is pull-only: a verifier only knows about revocations it has imported, and there is no revocation distribution network yet. A credential proves what the issuer signed, not that the issuer is trustworthy; deciding which DIDs to trust is the verifier's job. Presentations are only replay-safe if the verifier supplies a fresh nonce per request.
