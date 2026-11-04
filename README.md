# FRENET

Decentralized, privacy-first peer-to-peer internet. This repo is the **Phase 1 MVP node**: a real libp2p peer with a local dashboard.

## Status (what is real)

| Feature | State |
|---|---|
| Ed25519 identity, key stored locally (0600), never transmitted | working |
| TCP + Noise (forward-secret) + yamux via libp2p | working |
| Peer discovery: mDNS (LAN) + bootstrap list + manual dial | working (mDNS untested across hosts) |
| Kademlia DHT (`/frenet/kad/1.0.0`) provider records | working, tested (3 nodes, A<->B<->C) |
| Content-addressed blocks (sha256 CIDs, <=1 MB, hash-verified fetch, replicate-on-fetch) | working; **unencrypted, CID holders can read; client-side encryption not yet** |
| Direct encrypted messaging, local SQLite storage | working |
| Replay protection, per-peer rate limit, size caps | working, tested |
| Dashboard: overview, peers, messages, identity, privacy, security | working (live data only) |
| Storage, browser, voice/video, governance, node operator tools | **not built** (Phases 2-3) |
| NAT traversal / relays, WebRTC, QUIC, DIDs, Sybil resistance | **not built** (Phase 2+) |

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

Flags: `--data DIR` (default `~/.frenet`), `--listen MULTIADDR`, `--bootstrap MULTIADDR`, `--api-port N`, `--no-mdns`.

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
