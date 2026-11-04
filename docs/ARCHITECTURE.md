# Architecture (Phase 1)

```
web/ (dashboard)  <--HTTP+SSE, loopback only-->  src/api.ts
                                                    |
                              src/node.ts  (libp2p: tcp, circuit-relay v2, noise, yamux, mdns, bootstrap, kad-dht, identify, ping, autonat, dcutr, upnp)
                               |-- src/identity.ts   Ed25519 key file, 0600
                               |-- src/messaging.ts  /frenet/msg/1.0.0, one JSON message per stream
                               `-- src/store.ts      SQLite (node:sqlite), local only
```

## Messaging protocol `/frenet/msg/1.0.0`
- One stream per message: `{v:2,id,ts,to,body,sig}` JSON, closed by sender. `sig` is Ed25519 (base64) over `frenet-msg/v2\nfrom\nto\nid\nts\nbody`, so it binds sender, recipient, id and timestamp, not just the body.
- Sender identity = `connection.remotePeer` (authenticated by Noise). Claimed identity is never read from the payload.
- Receiver checks: size <= 32 KB frame / 16 KB body, schema, timestamp within 5 min, unseen `(peer,id)`, token-bucket rate limit (burst 20, 2/s).
- Signed per message: the sender is `remotePeer` and the signature must verify under that peer's key (the public key is embedded in the Ed25519 peer ID) and name us as `to`. Unsigned (v1), wrong-recipient and bad-signature messages are dropped. Signature, sender and recipient are stored, so any third party can re-verify a stored message with `verifyMessage()`. Limits: no forwarding yet (signer must equal the connection peer); signing proves authorship and recipient, not that the recipient read it; no sender-deniability; old unsigned v1 nodes can no longer message this version.

## Blocks `/frenet/block/1.0.0`
`put(bytes)` -> sha256 raw CIDv1, stored in SQLite, announced via DHT `provide`. `get(cid)` -> local, else `findProviders`, request the CID, verify sha256 before caching, then re-announce (replication). Cap 1 MB/block. Raw blocks are plaintext to anyone with the CID.

## Files (`src/files.ts`)
File -> 256 KB chunks -> each sealed with AES-256-GCM (random per-file key, random 96-bit nonce, AAD `c<index>`) -> blocks. Manifest `{name,size,chunks[]}` is sealed too (AAD `m`) and its CID is the file ID. Link: `frenet://<manifestCid>#<key>`; the key is never stored or sent by the node, so providers see ciphertext only. `{encrypt:false}` makes a public file. Max 16 MB. No key recovery: lose the link, lose the file.

## Retention
Own blocks are pinned (until deleted or per-file TTL). Replicas fetched from peers expire after `--replica-ttl-days`. Expired blocks are never served and are swept every 10 min and at startup. `--quota-mb` bounds local bytes; over-quota adds fail and roll back, over-quota replicas are served but not cached. Local delete removes manifest + unshared chunks and vacuums the DB; copies on other peers are outside our control.

## Local API (127.0.0.1)
`GET /api/status|peers|messages|events(SSE)|blocks/<cid>|files`, `POST /api/send|dial|blocks|files|files/get|files/delete` (base64 `data`). Foreign `Host` headers (DNS rebinding) and cross-origin POSTs are rejected; JSON content-type required; strict CSP on static files.

## Known limits
- NAT traversal is best-effort, not guaranteed. Layers, in order: UPnP port mapping (router permitting) -> AutoNAT reachability detection -> circuit-relay v2 reservation on `--relay` peers (or relays discovered among connected peers) -> DCUtR hole punching to upgrade relayed links to direct. Symmetric NATs / CGNAT may stay relay-only.
- Relayed connections are limited (a relay we run allows 2 min / 2 MiB per connection). Messaging and block fetch are allowed over them; large files may need the direct upgrade to succeed. Relays are not a privacy layer: they see peer IDs and traffic volume, but not content (Noise is end-to-end), and `remotePeer` is still the authenticated peer, never the relay.
- Running a relay (`--relay-server`) donates bandwidth (capped at 64 reservations). There is no relay discovery service or reputation yet: you must supply relay addresses you trust to be available.
- Firewalls are not modified.
- Messages to offline peers fail; no store-and-forward.
- Reputation, Sybil resistance, secure updates: not implemented.
