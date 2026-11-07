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
| Peer discovery: mDNS (LAN) + bootstrap list + manual dial | working; mDNS tested between two hosts on a LAN in the namespace lab (`npm run test:natlab`), real LANs and Wi-Fi with multicast filtering untested |
| Kademlia DHT (`/frenet/kad/1.0.0`) provider records | working, tested (3 nodes, A<->B<->C) |
| Content-addressed blocks (sha256 CIDs, <=1 MB, hash-verified fetch, replicate-on-fetch) | working; blocks added through the API are encrypted by default (key returned once, never stored); `public: true` stores plaintext. The network layer still serves any block to anyone who asks for its CID, which is how content addressing works, so what protects a block is its encryption |
| Files: 256 KB chunks, AES-256-GCM client-side encryption, encrypted manifest, key only in the share link | working, tested (<= 1 GiB/file). Upload and download stream chunk by chunk (`PUT /api/files/stream`, `POST /api/files/download`), so memory does not grow with file size. Files over 64 blocks are announced to the DHT in the background. The older JSON/base64 routes remain for small files (<= 16 MB): they buffer the whole file in memory, so the cap stays; use the streaming routes for anything bigger |
| Retention: per-file TTL, replicas expire (default 7 d), byte quota (default 1 GiB), sweeper, local delete | working, tested |
| Re-announcement: every block held locally (own files and sites first, then replicas) is announced on the DHT again at start-up and every 12 h (`--reannounce-hours`), so content stays findable across restarts and while its publisher is offline | working, tested (restart, schedule, blocked/expired skipped); only helps while some node still holds the content |
| Content safety: signed local content reports, operator blocklist for content IDs, names and publisher keys, purge of local copies, refusal to store/fetch/serve/announce/render blocked content (HTTP 451 at the gateway), dashboard view | working, tested; **local to each node**: nothing is shared or scanned automatically, matching is by exact hash (see Content safety) |
| Dashboard: Distributed Storage (add, share link, download, delete) | working |
| Direct encrypted messaging, local SQLite storage | working. A message to an unreachable peer is kept in a persistent sender-side outbox and retried when the peer connects and on a backoff timer, for up to 7 days (`queued: true` in the API). No relay holds mail, so the **sender's node must be online** when the recipient returns; the outbox is capped (200 per peer, 2000 total) |
| Replay protection, per-peer rate limit, size caps | working, tested |
| Dashboard: overview, peers, messages, identity, privacy, security | working (live data only) |
| Decentralized sites: publish a static folder (<= 64 files, 2 GiB total, 1 GiB per file; files over a few MB go in through `PUT /api/files/stream?encrypt=false` and are referenced by `cid` in `POST /api/sites`, and the gateway streams them), content-addressed, served by a local gateway on an isolated per-site origin (`<site-id>.localhost`) with a no-third-party CSP; dashboard Browser view | working, tested (publish on A, serve via B over the DHT) |
| Voice/video: WebRTC calls from the dashboard, signed signalling over `/frenet/call/1.0.0` (ephemeral, rate limited, accept/decline) | signalling tested on two real nodes; dashboard call flow tested only with a stubbed WebRTC stack, so **real camera/microphone media across browsers and NATs is untested**. `--ice-server turn:HOST` with `--turn-username` / `--turn-credential` (or `FRENET_TURN_CREDENTIAL`) hands a TURN server to the dashboard; the config is validated and tested, **relayed media through a real TURN server is not**, and FRENET does not run a TURN server. No group calls |
| Communities + group chat: owner-managed signed rosters, invitations need explicit join, signed messages fanned out to members (`/frenet/group/1.0.0`), **end-to-end encrypted** to the roster at send time (per-message key wrapped for each member) | working, tested (3 nodes). Chat messages and roster invitations for members who were unreachable are queued on the sender's node and retried for up to 7 days (a queued chat message is dropped if the member has since left or been removed); governance events are **not** queued because their deadlines depend on the clock window. Missed chat is recovered by **history sync** (`/frenet/group-sync/1.0.0`): on connect, and via `POST /api/communities/sync`, a member asks other members for chat sealed to them that they lack (7 days, 200 messages). Governance events are not synced, so a member who was offline can still miss them. Not tested across real networks; no forward secrecy (a stolen identity key opens every message addressed to it); a member added later cannot read earlier chat |
| Governance: signed proposals, one-member-one-vote ballots, frozen electorate, quorum, tally verifiable by any node; transitive delegated voting; discussion period, comments, withdrawal; **binding** proposals (rename, add or remove members) applied only after every node re-verifies the signed ballots | working, tested (including across real peers). Advisory proposals still change nothing; no history sync, so a node that missed events can disagree; the owner stays a trusted party for invitations; weighted voting, secret ballots and a community-wide governance charter are not built |
| Node operator tools: persistent peer ban list enforced at the connection gater, disconnect, retention sweep, resource and rejected-traffic stats | working, tested; local dashboard only, no remote administration |
| NAT traversal: circuit-relay v2 client + server, AutoNAT, DCUtR hole punching, UPnP port mapping | circuit-relay v2 (TCP and QUIC, cone and symmetric NAT, mobile profile), AutoNAT v2 and UPnP mapping: tested in a Linux network-namespace lab behind netfilter NAT (`npm run test:natlab`, root + miniupnpd). **DCUtR hole punching does not yet produce a direct link** (known todo: Node cannot dial from a port that has a live listener, so `@libp2p/tcp` and the QUIC client punch from an unannounced port; needs an upstream or native-transport fix), so NATed pairs stay on the relay. Real routers, CGNAT and UDP-blocking firewalls untested |
| Names + updates: `<name>.<publisher-key>`, signed by your identity key, higher `seq` replaces lower, so a site keeps its address when you republish | working, tested (publish on A, resolve + serve on B, update, forged/stale/tampered records rejected) |
| Search: keyword search over names/titles/keywords that publishers announce on the DHT, every record signature-checked | working, tested; opt-in per site, unranked, spammable (see limits) |
| DIDs: your identity key is also a `did:key` (Ed25519); resolves offline; any Ed25519 peer ID maps to a DID | working, tested (spec test vector) |
| Verifiable credentials: issue/verify W3C VC-JWTs signed by your identity key, holder presentations bound to a verifier nonce, issuer-signed revocation | working, tested (tamper, alg-confusion, replay, wrong-holder cases); revocation is pull-only, no trust registry |
| Zero-knowledge authentication: prove "I am one of these N identities" without saying which (linkable ring proof over the same Ed25519 keys, `@noble/curves`), bound to a verifier challenge, scope and audience; a per-scope tag lets a verifier allow each anonymous member one action (a vote, a claim) | working, tested (every signer position, replay, tamper, forged/small-order tags, one-per-scope, two nodes over the API); anonymity set = the ring (O(n), max 1024; default minimum 5, optional `ringId` fingerprint pin against padded rings); dashboard view **Anonymous Auth** and `frenet zk` CLI; **not a general-purpose zk-SNARK, not independently audited** |
| Account recovery: passphrase-encrypted key backup and k-of-n Shamir recovery shares, CLI only | working, tested end to end; recovers the *same* key, cannot help if the key is stolen (see SECURITY.md) |
| QUIC transport (`/udp/…/quic-v1`) next to TCP, on by default (`--no-quic` to disable); ban list and all other gating apply to it | working, tested on loopback (connect, messaging, ban) and from behind a NAT in the namespace lab (outbound dial, two-way messaging, relay); real routers and UDP-blocking firewalls untested; depends on the third-party native module `@chainsafe/libp2p-quic` |
| Sybil resistance: optional identity proof-of-work (`--min-identity-bits N`, `frenet identity mine`), per-subnet peer limits, cluster flagging | working, tested; **raises the cost of fake identities, does not prevent them** (see ARCHITECTURE.md) |
| Node reputation and malicious-node detection: local scores from verified misbehaviour (bad signatures, corrupt blocks, forged records, floods), automatic escalating blocks, dashboard/API view | working, tested; local only, nothing is shared between nodes, a rotated peer ID starts fresh |
| Secure software updates: threshold-signed release manifests, expiry, rollback/downgrade protection, artifact hash check (`frenet update …`) | verification and signing tools working, tested; **the node never downloads or installs updates itself**, no trust roots are shipped (you pin them), root-key rotation not built |
| Independent audits | **not done.** `docs/AUDIT.md` is the preparation package; no third party has reviewed this code |
| Human-memorable global names, key rotation | **not built** |

Nothing in the dashboard is simulated. Empty states mean there is no data.

## Scope: deliberately not built

These are **not in the spec's feature list**, so their absence is not a gap or a to-do:

- **General web browsing.** The Decentralized Browser section is only the gateway for FRENET sites (`<site-id>.localhost`, `<name>.<publisher-key>.localhost`). It does not browse the public web, so there is no HTTPS browsing, no tracker blocking and no permission manager. (Published sites are already locked down by a no-third-party CSP and a deny-all `Permissions-Policy`; that is site hardening, not a browser feature.)

## Privacy and data ownership

- **Local-first.** Messages, blocks, names and node state live in a local SQLite database in the data directory. Nothing is sent to a server we run, and there is no telemetry or analytics.
- **Key custody.** The Ed25519 identity key is stored locally (`identity.key`, mode 0600), is never transmitted and is never returned by the HTTP API. It leaves the data directory only through the explicit backup and recovery commands (see SECURITY.md).
- **Private by default.** The control API is loopback-only, blocks and files are encrypted by default, and links to encrypted content carry the key. Published sites are the exception: they are public by design.
- **Anonymous authentication.** Beyond signatures and VC presentations, a linkable ring proof (`src/zkauth.ts`, `frenet zk`, dashboard **Anonymous Auth**) proves "I am one of these N identities" without revealing which, with one stable tag per scope. It is not a general zero-knowledge system (no SNARKs, no range proofs), VC presentations still disclose what they contain, anonymity is only as large as the ring, and it has not been independently audited.

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

Limits: no global human-memorable names (key is in the address); a malicious provider can serve an *older* valid record (resolvers ask up to 8 providers and take the highest `seq`, but a rollback is possible if only stale holders are reachable); search is unranked and anyone can publish spam under any keyword (per-peer reputation and Sybil limits exist, but search results are not ranked by them); full-text search of page contents is not built; own names are re-announced every 6 h and stored blocks every 12 h, but name records are announced only by their publisher (nodes that merely resolved a name keep a copy but do not announce it), so a *named* site's name needs its publisher online even though the site's files can live on in replicas; there is no name transfer or revocation (publish a new record pointing elsewhere).

### Content safety (reports and blocking)

A node stores and serves other people's data, and there is no central operator who can take anything down, so the tools are per node. Dashboard: **Content Safety** (or **Report** on a search result); API: `/api/moderation/*`.

```bash
# file a report (stored locally, signed by your node identity); add "block": true to block at the same time
curl -s localhost:7777/api/moderation/report -H 'content-type: application/json' \
  -d '{"kind":"cid","target":"frenet-site://bafk...","category":"phishing","note":"fake bank login","block":true}'
# or block directly: kind is cid (a file, site or block), name (frenet-name://label.key) or publisher (a 52-char key)
curl -s localhost:7777/api/moderation/block   -H 'content-type: application/json' -d '{"kind":"publisher","target":"<key>","reason":"repeat abuse"}'
curl -s localhost:7777/api/moderation/unblock -H 'content-type: application/json' -d '{"kind":"publisher","target":"<key>"}'
curl -s localhost:7777/api/moderation                      # blocklist + reports; GET /api/moderation, POST .../resolve {id, action: block|dismiss}
# an encrypted file: paste the whole link (frenet://<cid>#<key>) as the target, or send the key as "key": "<43 characters>"
curl -s localhost:7777/api/moderation/block   -H 'content-type: application/json' -d '{"kind":"cid","target":"frenet://bafk...#<key>","reason":"abuse"}'
```

- **Blocking** deletes this node's copies, stops advertising them, and then refuses to store, fetch, serve, announce or render the same content again. The gateway answers **451**. Blocking a site also blocks its files and chunks that this node holds or can read from a held manifest; blocking a name also blocks the site it points to; blocking a publisher blocks all its names and their sites. Unblocking lifts an entry and everything it pulled in (deleted data is not restored).
- **Blocking an encrypted file completely needs its key.** A node that only holds a replica of an encrypted file sees ciphertext and cannot read the manifest that lists the chunks, so without the key only the manifest is blocked and the chunks sit there until the replica TTL removes them. If you have the file's link, paste it as the target (or put the key in `key`, or paste it into the prompt that **Block** shows on an open report): the key opens the manifest once, in memory, to list the chunks, and every chunk is blocked and purged with it. If this node no longer has the manifest (you blocked it earlier, or never held it), that one small block is fetched from a peer for this purpose only: it is checked against its ID, read once and **never stored**; the chunks themselves are never downloaded. The key is never written to disk or to the blocklist, never put in a report, and never echoed back; a wrong or malformed key is rejected with an error before anything changes. The response says what happened in `keyStatus`: `used` (the key opened the manifest), `not-needed` (the node could already list the chunks: a public file or site, one it published itself), `manifest-not-held` (a key was given but no peer that holds the manifest could be reached, so the chunks could not be listed), or `key-needed` (no key was given and the block this node holds could not be read without one: if it is an encrypted file, only the manifest is blocked and the chunks stay stored). The dashboard shows a note for `key-needed` and `manifest-not-held`, and every blocklist entry for a content ID has an **Add key** button: blocking the same ID again with the key blocks and purges the chunks, so a missing key can be supplied later, as long as some reachable peer still has the manifest.
- **Reports** hold identifiers, a category and a short note (max 500 chars), never content bytes and never a file's `#key` (it is stripped from links). Each is signed with the node identity (`verifyReport` in `src/moderation.ts` checks one), so you can hand it to a hotline, a publisher or another operator and they can confirm it is genuine and unaltered. Categories: illegal, child-safety, malware, phishing, harassment, spam, other.
- **If you find illegal content, child sexual abuse material above all,** also report it to your national hotline (see inhope.org) and to the authorities where the law requires it, and do not copy or forward the content. This tool records and blocks on your node; it does not notify anyone.

**Why nothing is sent to a hotline and nothing is scanned.** Both are possible to build and deliberately left out, because the part that makes them work is an agreement with an organisation, not code. Reporting channels such as the NCMEC CyberTipline API are for registered providers: they require an application and approval, and they issue credentials that identify the reporting company, so there is no endpoint a self-hosted node could call on its own. INHOPE member hotlines, which cover many countries, take reports from the public through each national hotline's own website, and the right hotline depends on where you are, so that step stays with a person. Matching content by similarity, as opposed to exact hash, is done with hash lists such as PhotoDNA. Those are licensed to vetted organisations under their terms, and a node that fetched, stored and compared such material would be handling it, which each operator should decide for themselves with legal advice. A tool that appeared to report or scan but did neither reliably would be worse than one that says it does not. The signed reports are the hand-off: they hold identifiers only and anyone can verify one with `verifyReport`.

Limits: local only (nothing is sent anywhere, no shared or gossiped blocklists, no automatic scanning or detection); matching is by **exact hash**, so a copy with one byte changed is a different CID and needs its own entry; an encrypted file is fully blocked only when you have its key (see above; each upload gets a new key and new chunk IDs, so a re-upload is a different file), and adding a key later needs some reachable peer that still holds the manifest; blocking does not remove copies on other nodes, and their provider records for it live up to 48 h; `block`, `unblock` and `resolve` act on this node's own state only and are loopback-only like the rest of the API. This is a safeguard for operators, not legal advice or a compliance programme.

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

Anonymous membership (zero-knowledge): the verifier names the ring (DIDs or peer IDs), asks for a challenge, and the prover answers with a proof that hides which member it is:

```bash
curl -s -XPOST localhost:7777/api/zk/challenge -H 'content-type: application/json' -d '{}'          # verifier -> {nonce, expires}
curl -s localhost:7777/api/zk/prove  -H 'content-type: application/json' \
  -d '{"ring":["did:key:z6Mk...","did:key:z6Mk..."],"scope":"vote:42","nonce":"<nonce>","audience":"<verifier>"}'   # prover -> {proof, tag}
curl -s localhost:7777/api/zk/verify -H 'content-type: application/json' \
  -d '{"ring":[...same ring...],"scope":"vote:42","nonce":"<nonce>","audience":"<verifier>","proof":"<proof>","once":true}'   # verifier -> {valid, tag}
```

Terminal (offline, no node needed): `frenet zk challenge | ring --ring FILE | tag --scope S | prove --ring FILE --scope S --nonce N | verify --ring FILE --scope S --nonce N --proof FILE` (ring file = one DID or peer ID per line; CLI verify is stateless, the node's API is what tracks nonces and tags). The dashboard's **Anonymous Auth** section does the same with a fingerprint and size check on the ring.

`once: true` records the tag so the same member cannot act twice in that scope, without learning who they are. Tags in different scopes cannot be linked. See SECURITY.md for what this does not hide.

Behind NAT (home router, CGNAT)? Point the node at a relay that has a public address:

```bash
# on a publicly reachable host (VPS, forwarded port)
npm start -- --relay-server --listen /ip4/0.0.0.0/tcp/4001
# on the NATed node(s): reserve a slot on that relay
npm start -- --relay /ip4/<relay-ip>/tcp/4001/p2p/<relay-peer-id>
```

The node then advertises a `/p2p-circuit` address that other peers can dial. Relayed links are
capacity-limited (relay default: 2 min / 2 MiB per connection); peers try to upgrade to a direct
connection with DCUtR hole punching (currently not succeeding in the lab, so expect relay-only between two NATed peers), and UPnP opens a port when the router allows it.
Use `--announce MULTIADDR` for a manually forwarded port or DNS name, `--no-nat` to disable all of this.

Flags: `--ice-server stun:HOST[:PORT]` (repeatable; for calls across NATs, none by default so no third party learns your IP), `--relay MULTIADDR` (repeatable), `--relay-server`, `--announce MULTIADDR` (repeatable), `--no-nat`, `--gateway-port N`, `--no-gateway`, `--data DIR` (default `~/.frenet`), `--listen MULTIADDR`, `--bootstrap MULTIADDR`, `--api-port N`, `--quota-mb N` (1024), `--replica-ttl-days N` (7), `--reannounce-hours N` (12, 0 = never), `--no-mdns`.

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
