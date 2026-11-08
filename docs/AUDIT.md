# Independent audit: preparation package

**Status: no independent audit has been performed.** Nothing in this repository was reviewed by a third party, and this document does not change that. It exists so that a reviewer can start quickly and so that the maintainers can state exactly what was and was not covered. Do not describe FRENET as "audited" until a named firm or reviewer has published a report for a specific commit.

## What to commission
1. **Protocol and cryptography review** of the signed wire formats and key handling: `src/messaging.ts`, `calls.ts`, `groups.ts`, `names.ts`, `channel.ts` (domain-separated Ed25519 signatures, replay/skew windows), `credentials.ts` and `did.ts` (VC-JWT, algorithm pinning), `zkauth.ts` (linkable ring proof: soundness and zero-knowledge argument, subgroup/small-order checks, challenge binding, tag unlinkability across scopes; the construction is textbook LSAG over Ed25519 but this implementation is new), `recovery.ts` (scrypt backup, hand-written Shamir over GF(2^8); field arithmetic is table-free and branch-free on secret bytes since the constant-time rewrite, but only the source was reviewed by its author, nothing was measured; `scripts/crosscheck-shamir.py` compares the maths with SLIP-39's reference), `updates.ts` (threshold signatures, rollback/freeze rules).
2. **Network abuse and denial of service**: rate limiters, frame caps, store growth caps (names 5000, reputation 10,000, invitations 50), the connection gater (`node.ts`), reputation, subnet limits and proof-of-work (`sybil.ts`, `reputation.ts`). Include an eclipse-attack and Sybil analysis of the DHT usage (provider records only, no value store).
3. **Local attack surface**: the loopback HTTP API and dashboard (`api.ts`, `web/`) for DNS rebinding, CSRF, XSS; the site gateway (`gateway.ts`, `sites.ts`) for origin isolation, CSP and path handling; the content blocklist (`moderation.ts`) for paths that store, fetch, serve, announce or render blocked content despite an entry, and for manifest-driven cascade bounds.
4. **Dependency and supply-chain review**, notably the native QUIC module `@chainsafe/libp2p-quic`, `libp2p` and its transports, `@noble/curves` (group arithmetic and hash-to-curve for `zkauth.ts`), and `node:sqlite`.
5. **Build and release process** once release signing keys exist (key ceremony, who holds what, reproducible builds).

## Suggested package for the reviewer
- Commit hash, `npm ci` lockfile, Node >= 22.13, `npm test` (all suites), `npm run typecheck`, `npm audit`.
- `docs/ARCHITECTURE.md` (every section ends with its limits) and `SECURITY.md`.
- Threat model summary: attacker controls any number of peers and the network path; does not control the local machine or the user's key. Out of scope by design: a compromised host, traffic analysis by a global observer, anonymity (FRENET is not Tor), and availability guarantees.

## Known gaps a reviewer should expect to confirm (self-assessed, not verified)
- Constant-time behaviour of the Shamir implementation: the source avoids secret-indexed tables and secret-dependent branches, but JIT-compiled JavaScript offers no guarantee and no timing measurement has been made. A reviewer should confirm or, better, replace it with a vetted library. Noise/QUIC are the upstream libraries' responsibility.
- Fuzzing is random and structure-aware, not coverage-guided; a reviewer should run a real coverage-guided fuzzer (e.g. Jazzer.js) against the entry points listed in `test/fuzz.test.ts`.
- The optional WebRTC node transport (`--webrtc`, `@libp2p/webrtc` over native `node-datachannel`) is tested on loopback only (`/webrtc-direct`); `/webrtc` via relay and real NATs are untested. Real browser WebRTC media is untested. NAT traversal and QUIC behind NATs are tested only in a Linux network-namespace lab (see `docs/ARCHITECTURE.md`); hole punching does not work; real routers, CGNAT and UDP-blocking firewalls are untested.
- Reputation thresholds and proof-of-work levels are untuned guesses.
- Equivocation by a community owner (different rosters to different members) is not detected.
- Update trust roots cannot be rotated. The installer (`src/installer.ts`) replaces files atomically but does not unpack or run anything; its path handling, backup/rollback and https-only fetching are new and unreviewed.
- Remote administration (`src/admin.ts`) is new: signed requests, replay window and the command allow-list need review; admin peers bypass auto-blocking by design.
- A `did:key` cannot be rotated or revoked (use `did:frenet`).
- `did:web` and handles (`src/webid.ts`) trust DNS and TLS; they fetch attacker-influenced URLs (SSRF guard in `isNonPublicAddress`/`httpsJson`, no live-network test: handle pins are per node (TOFU); review the DNS-rebinding window between lookup and connect, which is closed by connecting to the vetted IP).

## Before and during the engagement
- Freeze a commit; run `npm audit`, the full test suite, and `FRENET_FUZZ_ITERS=1000000 npm run test:fuzz` (the built-in fuzz pass over every `parse`/`validate`/`verify` function that takes untrusted input).
- Publish a monitored vulnerability-reporting address: the policy, response targets and a 90-day disclosure window are in `SECURITY.md`, but its contact line is still a placeholder.
- Publish the final report and the fixed commit, and keep the list of unresolved findings public.
