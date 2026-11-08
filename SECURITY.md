# Security
- Crypto: Noise (XX), Ed25519 and AES-256-GCM via libp2p / `@libp2p/crypto` / Node `crypto`; scrypt for backup passphrases; Shamir secret sharing over GF(2^8) for recovery shares (a textbook construction, ~60 lines in `src/recovery.ts`, covered by tests and cross-checked against SLIP-39's reference arithmetic, **not independently reviewed**). Its field arithmetic is table-free and branch-free on secret values (see below). No custom ciphers or signature schemes.
- Private keys never leave `<data>/identity.key` (0600) except through the explicit recovery commands below. The HTTP API never returns key material.
- **No independent security audit has been done.** `docs/AUDIT.md` lists scope, threat model and open questions for whoever is commissioned to do one.
- This is unaudited pre-release software. Do not rely on it for high-risk use.
- **Reporting a vulnerability: see "Reporting a vulnerability" below.** Please do not open a public issue for a security bug.

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
- **A stolen key.** Whoever holds the key is you. A plain `did:key` cannot be rotated or revoked, so there is no way to tell peers "the old key is dead"; if that key may be compromised, treat the identity as burned: create a new one and re-announce it out of band. If you ran `frenet identity rotation-init` beforehand (a `did:frenet`), rotate with the offline next-key backup instead: the DID stays, the old key stops being current.
- **Backup passphrase strength.** An offline attacker with the backup file can guess passphrases at scrypt N=2^17 speed; use a long random passphrase.
- Share arithmetic (`gfMul`, `gfDiv` in `src/recovery.ts`) uses no lookup tables and no branches on secret bytes: multiplication is a fixed 8-step shift/AND/XOR loop and inversion is a fixed `a^254` chain, so no memory index or branch depends on a share or key byte. This is a software property of the source, **not a guarantee about the running code**: JavaScript engines may recompile, and nobody has measured timing on real hardware. Run split/restore on a machine you control.
- Running split/restore with a node live on the same data directory is unsupported.

**Credentials.** VC-JWTs are verified offline against the issuer's DID, with `alg` pinned to EdDSA. Expiry and issuer-signed revocation statements are honoured, but revocation is pull-only: a verifier only knows about revocations it has imported, and there is no revocation distribution network yet. A credential proves what the issuer signed, not that the issuer is trustworthy; deciding which DIDs to trust is the verifier's job. Presentations are only replay-safe if the verifier supplies a fresh nonce per request.

**Zero-knowledge membership (`src/zkauth.ts`).** A linkable ring signature (LSAG) over Ed25519, made non-interactive with Fiat-Shamir: it proves knowledge of the secret behind *one* key in a ring, and of a tag `x*H(scope)`, without revealing which key. The proof is bound to the scope, a verifier-issued single-use nonce (2-minute lifetime), an optional audience and the exact ring, so it cannot be replayed, redirected to another verifier, or used against a different ring. Group operations come from `@noble/curves`; no new primitive or key is introduced, and the secret key never leaves the process. Verifiers reject non-canonical encodings and scalars, the identity element and any point outside the prime-order subgroup (closing the small-order tag-malleability trick that defeats one-per-scope checks on a cofactor-8 curve).
- **What it hides:** which ring member signed. Tags in different scopes are unlinkable (under DDH on Ed25519).
- **What it deliberately reveals:** the tag, which is stable per member *within* a scope; that is what makes "once per scope" enforceable. Do not reuse one scope for things that must stay unlinkable.
- **Anonymity is only as large as the ring.** The verifier chooses the ring; a ring padded with keys that belong to no real user shrinks the set. Mitigations in code: `ZkAuth` refuses rings under 5 members unless you lower `minRing` on purpose, and both sides can pin the ring's fingerprint (`ringId`, shown by the dashboard, `frenet zk ring` and the API) so a padded or swapped ring is refused. Nothing in code can tell whether the members are real, distinct people, so compare the fingerprint with the verifier and judge the membership yourself.
- **did:frenet members** count by their *current* key, resolved offline from the local key log; a member who rotates after you looked is not in your ring until you re-resolve.
- **Not covered:** this is not a general zero-knowledge system (no SNARKs, no range proofs, no proving facts about credential contents; presentations still disclose what they contain), proof size and time grow linearly with the ring (max 1024), the stored `once` tags are capped at the newest 100,000 and live in SQLite on the verifier, outstanding challenges are held in memory (lost on restart, which only makes pending proofs fail), and the implementation has not been independently audited and is not constant-time beyond what `@noble/curves` provides.

## Abuse, Sybil and update security (Phase 4)
- **Fake identities.** Anyone can create unlimited peer IDs. `--min-identity-bits`, the per-subnet limit and local reputation raise the cost and visibility of that; they do not stop a well-funded attacker (cloud IPs across many ranges, or a botnet). Treat the network as untrusted regardless: every message, block, name record and credential is verified end to end and none of that depends on reputation.
- **Reputation is a local heuristic.** It only reacts to misbehaviour this node verified, and an attacker can cause *you* to block a peer only by making it misbehave toward you, because nothing is taken on hearsay.
- **Updates.** Verify releases with `frenet update verify --artifact FILE`, with trust roots you obtained out of band (project website over HTTPS *and* a second channel, compare the key fingerprints). Do not accept roots from the same place as the download. `frenet update fetch` and `install` do the download and the file replacement for you, but only after the same verification, and never on their own; restart the node afterwards. Until the maintainers publish release keys, there is nothing to verify against and unsigned builds must be built from source you reviewed.
- **Remote administration** is off unless you start the node with `--admin-peer ID`. A listed admin can ban, unban, disconnect, sweep, re-announce and edit the content blocklist on your node, and read its stats; it cannot read keys, messages or files. Requests are signed, replay-protected, rate-limited and logged. List only peers whose machines you trust: the admin's node key is the credential. This module has not been independently audited.
- **QUIC** is third-party native code (`@chainsafe/libp2p-quic`); disable with `--no-quic` if you do not want it.

## Abusive content (not a vulnerability)
This node stores and serves content published by others. To report abusive content you found, use **Content Safety** in the dashboard: it records a signed local report and can block the content on your node (see README, "Content safety"). That is separate from reporting a vulnerability, which goes to the maintainers privately (above). Blocking is local and by exact hash; it does not remove content from other nodes. For an encrypted file, paste the whole link (it includes the key) when you block, so every chunk can be listed and blocked; the key is used once in memory and never saved, and it can be added later to an existing block (the manifest is then fetched from a peer, read once and not stored). Illegal content, child sexual abuse material above all, should also go to your national hotline (see inhope.org) and to the authorities where the law requires it.

## Reporting a vulnerability
**Contact:** `TODO-maintainers: publish a monitored address here` (the maintainers must replace this line before the first public release; until then there is **no working security contact**, and the README says so). Prefer GitHub's private vulnerability reporting ("Security" tab, "Report a vulnerability") once it is enabled on the repository, or an encrypted email if a PGP key is published here.

- Send what you found, the commit or version, and how to reproduce it. A proof of concept is welcome; please do not test against nodes you do not run.
- **Response targets:** acknowledgement within 3 working days, an initial assessment within 10, and a fix or a mitigation plan within 90 days of the report. These are targets for a volunteer project, not a service level.
- **Disclosure:** coordinated. We will agree a date with you, normally when a fix is released or after 90 days, whichever is first; if a fix needs longer we will say why. Reporters are credited unless they ask not to be.
- **In scope:** this repository, including the wire protocols and the loopback API. **Out of scope:** third-party libraries (report those upstream; tell us too if FRENET's use of them makes it worse), a compromised host, traffic analysis by a global observer, and denial of service by sheer volume.
- **Good faith:** research that follows this policy, touches only your own nodes and data, and stops at proof of impact will not be treated as hostile by the maintainers.
- Fuzzing: `npm run test:fuzz` runs the built-in fuzz pass; reports from it include the seed (`FRENET_FUZZ_SEED`) so any failure replays exactly.

