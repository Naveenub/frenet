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
| QUIC, DIDs, Sybil resistance, site naming / search | **not built** (Phase 2+) |

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
and each has its own browser origin. `--gateway-port N` / `--no-gateway`. Limits: static files only, no naming (IDs are hashes), no search, no updates (republish = new ID).

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
