# FRENET

Decentralized, privacy-first peer-to-peer internet. This repo is the **Phase 1 MVP node**: a real libp2p peer with a local dashboard.

## Stack (as built)

This is the actual stack. It differs from the original spec, which assumed Next.js/React/TypeScript/Tailwind for the frontend and Go or Rust for the backend.

| Layer | What is used | Not used (despite the spec) |
|---|---|---|
| Frontend (`web/`) | Plain JavaScript ES modules (`web/app.js`), hand-written HTML and CSS, no framework, no bundler, no build step (`scripts/copy-web.mjs` only copies the files into `dist/`). Talks to the node over loopback HTTP + SSE. | Next.js, React, TypeScript, Tailwind |
| Backend (`src/`) | Node.js >= 22.13 + strict TypeScript (ESM, `tsc`, run with `tsx`), js-libp2p, `node:sqlite` | Go, Rust |

The one Rust component is a dependency, not our code: the QUIC transport `@chainsafe/libp2p-quic` is a native binding over `quinn`. All FRENET source is TypeScript.

## Status (what is real)

| Feature | State |
|---|---|
| Ed25519 identity, key stored locally (0600), never transmitted | working |
| TCP + Noise (forward-secret) + yamux via libp2p | working |
| Peer discovery: mDNS (LAN) + bootstrap list + manual dial | working (mDNS untested across hosts) |
| Kademlia DHT (`/frenet/kad/1.0.0`) provider records | working, tested (3 nodes, A<->B<->C) |
| Content-addressed blocks (sha256 CIDs, <=1 MB, hash-verified fetch, replicate-on-fetch) | working; raw blocks are readable by CID holders |
| Files: 256 KB chunks, AES-256-GCM client-side encryption, encrypted manifest, key only in the share link | working, tested (<= 16 MB/file) |
| Retention: per-file TTL, replicas expire (default 7 d), byte quota (default 1 GiB), sweeper, local delete | working, tested |
| Dashboard: Distributed Storage (add, share link, download, delete) | working |
| Direct encrypted messaging, local SQLite storage | working |
| Replay protection, per-peer rate limit, size caps | working, tested |
| Dashboard: overview, peers, messages, identity, privacy, security | working (live data only) |
| Decentralized sites: publish a static folder (<= 64 files, 32 MB), content-addressed, served by a local gateway on an isolated per-site origin (`<site-id>.localhost`) with a no-third-party CSP; dashboard Browser view | working, tested (publish on A, serve via B over the DHT) |
| Voice/video: WebRTC calls from the dashboard, signed signalling over `/frenet/call/1.0.0` (ephemeral, rate limited, accept/decline) | signalling tested on two real nodes; dashboard call flow tested only with a stubbed WebRTC stack, so **real camera/microphone media across browsers and NATs is untested** |
| Communities + group chat: owner-managed signed rosters, invitations need explicit join, signed messages fanned out to members (`/frenet/group/1.0.0`) | working, tested (3 nodes); no history sync, no store-and-forward |
| Governance: signed proposals and one-member-one-vote ballots, frozen electorate, quorum, tally verifiable by any node | working, tested; **advisory only**, nothing enforces outcomes |
| Node operator tools: persistent peer ban list enforced at the connection gater, disconnect, retention sweep, resource and rejected-traffic stats | working, tested; local dashboard only, no remote administration |
| NAT traversal: circuit-relay v2 client + server, AutoNAT, DCUtR hole punching, UPnP port mapping | working: relayed delivery tested on loopback; hole punching and UPnP depend on your NAT/router and are untested here |
| Names + updates: `<name>.<publisher-key>`, signed by your identity key, higher `seq` replaces lower, so a site keeps its address when you republish | working, tested (publish on A, resolve + serve on B, update, forged/stale/tampered records rejected) |
| Search: keyword search over names/titles/keywords that publishers announce on the DHT, every record signature-checked | working, tested; opt-in per site, unranked, spammable (see limits) |
| DIDs: your identity key is also a `did:key` (Ed25519); resolves offline; any Ed25519 peer ID maps to a DID | working, tested (spec test vector) |
| Verifiable credentials: issue/verify W3C VC-JWTs signed by your identity key, holder presentations bound to a verifier nonce, issuer-signed revocation | working, tested (tamper, alg-confusion, replay, wrong-holder cases); revocation is pull-only, no trust registry |
| Account recovery: passphrase-encrypted key backup and k-of-n Shamir recovery shares, CLI only | working, tested end to end; recovers the *same* key, cannot help if the key is stolen (see SECURITY.md) |
| QUIC transport (`/udp/…/quic-v1`) next to TCP, on by default (`--no-quic` to disable); ban list and all other gating apply to it | working, tested on loopback (connect, messaging, ban); behaviour behind real NATs/firewalls untested; depends on the third-party native module `@chainsafe/libp2p-quic` |
| Sybil resistance: optional identity proof-of-work (`--min-identity-bits N`, `frenet identity mine`), per-subnet peer limits, cluster flagging | working, tested; **raises the cost of fake identities, does not prevent them** (see ARCHITECTURE.md) |
| Node reputation and malicious-node detection: local scores from verified misbehaviour (bad signatures, corrupt blocks, forged records, floods), automatic escalating blocks, dashboard/API view | working, tested; local only, nothing is shared between nodes, a rotated peer ID starts fresh |
| Secure software updates: threshold-signed release manifests, expiry, rollback/downgrade protection, artifact hash check (`frenet update …`) | verification and signing tools working, tested; **the node never downloads or installs updates itself**, no trust roots are shipped (you pin them), root-key rotation not built |
| Independent audits | **not done.** `docs/AUDIT.md` is the preparation package; no third party has reviewed this code |
| Human-memorable global names, key rotation | **not built** |

Nothing in the dashboard is simulated. Empty states mean there is no data.

## Scope: deliberately not built

These are **not in the spec's feature list**, so their absence is not a gap or a to-do:

- **General web browsing.** The Decentralized Browser section is only the gateway for FRENET sites (`<site-id>.localhost`, `<name>.<publisher-key>.localhost`). It does not browse the public web, so there is no HTTPS browsing, no tracker blocking and no permission manager. (Published sites are already locked down by a no-third-party CSP and a deny-all `Permissions-Policy`; that is site hardening, not a browser feature.)
- **Encrypted group messaging.** Community chat is signed by its author and travels over the Noise-encrypted link to each member, but there is no group key and no end-to-end encryption beyond that link. Stored events stay signed and plaintext on each member's device.

## Run

```bash
npm install
npm run build && node dist/cli.js          # or: npm start
# dashboard: http://127.0.0.1:7777
```

Two nodes on one machine:

```bash
npm start -- --data /tmp/a --listen /ip4/127.0.0.1/tcp/4101 --api-port 7801 --no-mdns
npm start -- --data /tmp/b --listen /ip4/127.0.0.1/tcp/4102 --api-port 7802 --no-mdns
# in A's dashboard: Connected Peers -> paste B's address (printed at startup)
```

### Sites

Publish a folder from the dashboard (**Decentralized Browser**) or via `POST /api/sites`, then share the `frenet-site://<id>` link.
Sites are **public**: no encryption, anyone with the ID can read them. The ID is the hash of the site manifest, so the content cannot be swapped.
Open `http://<site-id>.localhost:7778/` (the gateway fetches from peers and verifies hashes). Sites can only load their own files (no third-party requests, no framing)
and each has its own browser origin. `--gateway-port N` / `--no-gateway`. Limits: static files only.

### Names, updates and search

A site ID is a hash, so an update used to mean a new ID. Give the site a **name** and it keeps one address:

```bash
# publish (first time) and update (same name again) via the dashboard, or:
curl -s localhost:7777/api/sites -H 'content-type: application/json' -d '{
  "name": "my-blog", "title": "My blog", "keywords": ["writing","notes"],
  "files": [{"path": "index.html", "data": "<base64>"}] }'
# -> name.link = frenet-name://my-blog.<your-publisher-key>, url = http://my-blog.<key>.localhost:7778/
```

- A name is `<label>.<publisher-key>`: label `a-z0-9-` (1-63 chars), key = your Ed25519 public key (base32, 52 chars). The record `{name, target site ID, seq, ts, keywords, title}` is signed with your identity key, so **only you can create or update your names**, there is nothing to register, and nobody can squat or take over a name. The price is that names are not globally human-memorable: the key is part of the address.
- **Updates:** publishing again under the same name signs a record with `seq + 1`; resolvers take the highest valid `seq`. The immutable `frenet-site://<id>` link of each version keeps working.
- **Search:** keywords you attach are announced on the DHT; `GET /api/search?q=vegan+recipes` (or the dashboard) asks the network, verifies each record's signature and that it really carries the keyword, and returns names matching *all* query words. Names without keywords are not searchable.
- Resolution: `GET /api/names/resolve?name=…&pub=…`; your names: `GET /api/names`. A name page runs on its own origin (`<name>.<key>.localhost`) that stays the same across versions.

Limits: no global human-memorable names (key is in the address); a malicious provider can serve an *older* valid record (resolvers ask up to 8 providers and take the highest `seq`, but a rollback is possible if only stale holders are reachable); search is unranked and anyone can publish spam under any keyword (per-peer reputation and Sybil limits exist, but search results are not ranked by them); full-text search of page contents is not built; own names are re-announced every 6 h, but file and site blocks are not re-announced automatically yet, so keep the publishing node online; there is no name transfer or revocation (publish a new record pointing elsewhere).

### Identity, credentials and recovery

```bash
frenet identity                              # peer ID + DID (did:key:z6Mk...)
frenet backup --out ~/frenet.backup          # passphrase-encrypted key backup (node stopped)
frenet recovery split -k 3 -n 5              # 5 shares, any 3 recover the key
frenet restore ~/frenet.backup               # or: frenet recovery restore SHARE SHARE SHARE
```

Back the key up **now**: losing it loses the identity, and a stolen key cannot be revoked (see `SECURITY.md`).
Credentials go through the local API; subjects are DIDs or peer IDs:

```bash
curl -s localhost:7777/api/credentials/issue -H 'content-type: application/json' \
  -d '{"subject":"<did or peer id>","type":"Membership","claims":{"club":"frenet"},"ttlDays":365}'   # -> {id, jwt}
# holder: POST /api/credentials/import {jwt}; present: POST /api/presentations/create {credentials:[id], nonce, audience}
# verifier: POST /api/credentials/verify {jwt}  and  POST /api/presentations/verify {jwt, nonce, audience}
# issuer revokes: POST /api/credentials/revoke {id} -> {jwt}; verifiers import it with POST /api/credentials/revocations {jwt}
```

Behind NAT (home router, CGNAT)? Point the node at a relay that has a public address:

```bash
# on a publicly reachable host (VPS, forwarded port)
npm start -- --relay-server --listen /ip4/0.0.0.0/tcp/4001
# on the NATed node(s): reserve a slot on that relay
npm start -- --relay /ip4/<relay-ip>/tcp/4001/p2p/<relay-peer-id>
```

The node then advertises a `/p2p-circuit` address that other peers can dial. Relayed links are
capacity-limited (relay default: 2 min / 2 MiB per connection); peers try to upgrade to a direct
connection with DCUtR hole punching, and UPnP opens a port when the router allows it.
Use `--announce MULTIADDR` for a manually forwarded port or DNS name, `--no-nat` to disable all of this.

Flags: `--ice-server stun:HOST[:PORT]` (repeatable; for calls across NATs, none by default so no third party learns your IP), `--relay MULTIADDR` (repeatable), `--relay-server`, `--announce MULTIADDR` (repeatable), `--no-nat`, `--gateway-port N`, `--no-gateway`, `--data DIR` (default `~/.frenet`), `--listen MULTIADDR`, `--bootstrap MULTIADDR`, `--api-port N`, `--quota-mb N` (1024), `--replica-ttl-days N` (7), `--no-mdns`.

## Test

```bash
npm test        # spins up real libp2p nodes over loopback
npm run typecheck
```

## Dependencies

Node >= 22.13 (built-in `node:sqlite`), libp2p 3.x and its `@libp2p/*` modules, `@chainsafe/libp2p-noise`, `@chainsafe/libp2p-yamux`, `@multiformats/multiaddr`. No custom cryptography. Full list: `package.json`.

## Docs

`docs/ARCHITECTURE.md`, `docs/ROADMAP.md`, `SECURITY.md`.

## License

Apache-2.0
