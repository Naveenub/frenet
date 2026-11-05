# Security
- Crypto: Noise (XX), Ed25519 and AES-256-GCM via libp2p / `@libp2p/crypto` / Node `crypto`; scrypt for backup passphrases; Shamir secret sharing over GF(2^8) for recovery shares (a textbook construction, ~60 lines in `src/recovery.ts`). It is cross-checked against the SLIP-39 reference library (`python3 -I scripts/crosscheck-shamir.py`) and against a table-free second implementation in the test suite, but it has **not had an independent review**. No custom ciphers or signature schemes.
- Private keys never leave `<data>/identity.key` (0600) except through the explicit recovery commands below. The HTTP API never returns key material.
- This is unaudited pre-release software. Do not rely on it for high-risk use.
- Report vulnerabilities privately to the maintainers before disclosure.

## Identity, credentials and recovery
Your Ed25519 key is your account: peer ID, DID, your `<name>.<pub>` addresses and the credentials you issue are all derived from it. Do these once, now, with the node stopped:
```bash
frenet backup --full --out ~/frenet.archive     # key + messages, files, remembered file links, names, communities, credentials (add --blocks for your own blocks, <= 128 MiB)
frenet recovery split -k 3 -n 5                 # 5 shares, any 3 rebuild the KEY, 2 reveal nothing
frenet identity rotation-init --next-out ~/next-key.backup   # make the identity rotatable (did:frenet) and mint the offline recovery key
frenet restore ~/frenet.archive                 # also accepts a key-only backup (frenet backup --out) or: frenet recovery restore SHARE SHARE SHARE
```
- **Archives and backups are encrypted** (scrypt N=2^17 + AES-256-GCM, header authenticated, passphrase >= 12 chars). The archive holds your private key *and* your private data: keep the file and the passphrase apart and test a restore into a scratch directory (`--data`).
- **Shares:** give each to a different person or place; k shares are the whole key. They protect the key, not your data (use the archive for data).
- Restore never replaces a different existing identity without `--force` (the old key is kept as `identity.key.replaced-<time>`) and is safe to re-run. Rows are merged, existing data wins, bad rows roll the whole restore back.
- **What the archive cannot contain:** replicas of other people's blocks and cached foreign names (the network re-serves them); file decryption keys, unless the file was uploaded with *remember* (otherwise the node never stores a key: lose the link, lose the file); archives above the 128 MiB block limit (use one without `--blocks`).

**Lost or stolen key: rotation.** `rotation-init` turns the current key into the inception of a `did:frenet` identity, a hash-chained, publicly verifiable key event log, and commits to the *hash* of a *next* key that lives only in an encrypted file you keep off the machine. Whoever steals only the current key cannot rotate, truncate or fork the log. If the key is lost or stolen, `frenet identity rotate --next-key FILE --next-out FILE2` (works with no access to the old data directory if you kept a copy of `frenet identity log`, or fetched it from any node via `GET /api/identity/log?id=`) installs the next key and appends the rotation; the DID stays, peers follow the log over the network, and a fresh next-key backup replaces the spent one.
- Rotation changes the peer ID and the `<name>.<pub>` addresses (names belong to a key): republish names, and expect peers to re-learn your address.
- **Backdating:** a signature by a superseded key is accepted only if its `iat` is earlier than the rotation, but `iat` is signer-claimed, so someone holding the *old* key can backdate. After a theft, re-issue what matters and have verifiers use `strict` (refuses every superseded key).
- If the current key **and** the next-key backup are both stolen, there is no recovery. A plain `did:key` identity (no `rotation-init` before the theft) still cannot be recovered from a stolen key.
- Verifiers that have not seen a rotation yet accept the old key until they look again (the key log is re-checked on the network at most every 15 s while verifying, and whenever a signature names a newer key).

**Credentials.** VC-JWTs are verified offline against the issuer's DID (or key log), with `alg` pinned to EdDSA, expiry honoured, and presentations bound to a verifier-supplied nonce. A credential proves what the issuer signed, not that the issuer is trustworthy: which DIDs to trust is the verifier's job.
- **Revocation** is signed by the issuer, pushed to connected peers when issued, announced as DHT provider records, and pulled by verifiers (`verify` looks for it unless `offline`). *Absence is not proof:* a verifier that cannot reach a provider learns nothing, so "valid" means "not known revoked". The lookup tells DHT neighbours which credential you are checking; use `offline` to avoid that.
- Share arithmetic uses table lookups (not constant time). Run split/restore on a machine you control. Running any of these with a node live on the same data directory is unsupported.

## Known limits
- **Unaudited crypto code:** the Shamir code and the key log have not been independently audited. That is a Phase 4 item (`docs/ROADMAP.md`, `docs/AUDIT.md`).
- **Lost keys:** if you lose both the current key and the pre-committed next key, there is no recovery. A plain `did:key` without `rotation-init` still cannot be recovered from theft.
- **Stolen-key signatures:** a stolen old key can still sign things dated before the rotation (`iat` is signer-claimed). Verifiers should use the `strict` option.
- **Revocation lookup:** failing to find a revocation is not proof that none exists, and the lookup tells DHT neighbours which credential you are checking (use `offline` to avoid that).
- **Names:** names and the peer ID change after a rotation, so names must be republished.
- **File links:** file keys are only kept for files you chose to remember. Lose the link to any other file and the file is gone.
