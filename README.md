# FRENET

Decentralized, privacy-first peer-to-peer internet. This repo is the **Phase 1 MVP node**: a real libp2p peer with a local dashboard.

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
| Voice/video, governance, node operator tools | **not built** (Phase 3) |
| NAT traversal: circuit-relay v2 client + server, AutoNAT, DCUtR hole punching, UPnP port mapping | working: relayed delivery tested on loopback; hole punching and UPnP depend on your NAT/router and are untested here |
| Names + updates: `<name>.<publisher-key>`, signed by your identity key, higher `seq` replaces lower, so a site keeps its address when you republish | working, tested (publish on A, resolve + serve on B, update, forged/stale/tampered records rejected) |
| Search: keyword search over names/titles/keywords that publishers announce on the DHT, every record signature-checked | working, tested; opt-in per site, unranked, spammable (see limits) |
| QUIC, DIDs, Sybil resistance, human-memorable global names | **not built** (Phase 2+) |

Nothing in the dashboard is simulated. Empty states mean there is no data.

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

Limits: no global human-memorable names (key is in the address); a malicious provider can serve an *older* valid record (resolvers ask up to 8 providers and take the highest `seq`, but a rollback is possible if only stale holders are reachable); search is unranked and anyone can publish spam under any keyword (no reputation / Sybil resistance yet); full-text search of page contents is not built; own names are re-announced every 6 h, but file and site blocks are not re-announced automatically yet, so keep the publishing node online; there is no name transfer or revocation (publish a new record pointing elsewhere).

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

Flags: `--relay MULTIADDR` (repeatable), `--relay-server`, `--announce MULTIADDR` (repeatable), `--no-nat`, `--gateway-port N`, `--no-gateway`, `--data DIR` (default `~/.frenet`), `--listen MULTIADDR`, `--bootstrap MULTIADDR`, `--api-port N`, `--quota-mb N` (1024), `--replica-ttl-days N` (7), `--no-mdns`.

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
