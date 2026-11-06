# Security
- Crypto: Noise (XX), Ed25519 and AES-256-GCM via libp2p / `@libp2p/crypto` / Node `crypto`; scrypt for backup passphrases; Shamir secret sharing over GF(2^8) for recovery shares (a textbook construction, ~60 lines in `src/recovery.ts`, covered by tests, **not independently reviewed**). No custom ciphers or signature schemes.
- Private keys never leave `<data>/identity.key` (0600) except through the explicit recovery commands below. The HTTP API never returns key material.
- **No independent security audit has been done.** `docs/AUDIT.md` lists scope, threat model and open questions for whoever is commissioned to do one.
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

## Abuse, Sybil and update security (Phase 4)
- **Fake identities.** Anyone can create unlimited peer IDs. `--min-identity-bits`, the per-subnet limit and local reputation raise the cost and visibility of that; they do not stop a well-funded attacker (cloud IPs across many ranges, or a botnet). Treat the network as untrusted regardless: every message, block, name record and credential is verified end to end and none of that depends on reputation.
- **Reputation is a local heuristic.** It only reacts to misbehaviour this node verified, and an attacker can cause *you* to block a peer only by making it misbehave toward you, because nothing is taken on hearsay.
- **Updates.** Verify releases with `frenet update verify --artifact FILE`, with trust roots you obtained out of band (project website over HTTPS *and* a second channel, compare the key fingerprints). Do not accept roots from the same place as the download. Until the maintainers publish release keys, there is nothing to verify against and unsigned builds must be built from source you reviewed.
- **QUIC** is third-party native code (`@chainsafe/libp2p-quic`); disable with `--no-quic` if you do not want it.

## Abusive content (not a vulnerability)
This node stores and serves content published by others. To report abusive content you found, use **Content Safety** in the dashboard: it records a signed local report and can block the content on your node (see README, "Content safety"). That is separate from reporting a vulnerability, which goes to the maintainers privately (above). Blocking is local and by exact hash; it does not remove content from other nodes. For an encrypted file, paste the whole link (it includes the key) when you block, so every chunk can be listed and blocked; the key is used once in memory and never saved, and it can be added later to an existing block (the manifest is then fetched from a peer, read once and not stored). Illegal content, child sexual abuse material above all, should also go to your national hotline (see inhope.org) and to the authorities where the law requires it.
