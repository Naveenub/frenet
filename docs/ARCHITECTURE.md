# Architecture (Phase 1)

```
web/ (dashboard)  <--HTTP+SSE, loopback only-->  src/api.ts          src/gateway.ts (sites, :7778)
                                                    |
                              src/node.ts  (libp2p: tcp, circuit-relay v2, noise, yamux, mdns, bootstrap, kad-dht, identify, ping, autonat, dcutr, upnp)
                               |-- src/identity.ts   Ed25519 key file, 0600
                               |-- src/messaging.ts  /frenet/msg/1.0.0, one JSON message per stream
                               |-- src/names.ts      /frenet/name/1.0.0, signed name records + keyword search
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

## Sites (`src/sites.ts`, `src/gateway.ts`)
A site = public files (Files with `encrypt:false`) plus a manifest block `{v:1,type:'site',index,files:{path->fileCid}}`; the site ID is the manifest's CID. Paths are relative, `[A-Za-z0-9._-]` segments, no `.`/`..`; max 64 files / 32 MB. The manifest is validated on read because the publisher is untrusted (path charset, CID shape, prototype keys are not files).
The gateway (default `127.0.0.1:7778`) serves `GET/HEAD http://<siteCid>.localhost:<port>/<path>`: the `Host` must be a valid site CID (DNS-rebinding defence; each site is a separate browser origin). Responses carry `default-src 'none'; img/style/script/font/media/connect 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'`, `nosniff`, `no-referrer`, CORP same-origin. Only a fixed MIME allow-list is rendered; other types are served as attachments. Browser subresource requests from other pages (`Sec-Fetch-Dest` other than `document`, unless same-origin) are refused so a web page cannot make this node fetch arbitrary CIDs. Clients that send no `Sec-Fetch-*` headers (curl) are allowed: they are already local.
Limits: static content only; the gateway is plain HTTP on loopback; fetching an unseen site reveals the CID you want to your DHT neighbours. Mutable addressing and search live in the next section.

## Names, updates and search (`src/names.ts`)
**Record.** `{v:1,name,pub,target,seq,ts,keywords[],title,sig}`. `pub` is the publisher's raw Ed25519 public key (base32, 52 chars) and is part of the name (`<name>.<pub>`), so names are self-certifying: `sig` is Ed25519 over `frenet-name/v1\nname\npub\ntarget\nseq\nts\nkeywords\ntitle` and must verify under `pub`. There is no registry to capture; a different key is simply a different name. Validation (`validateRecord`) checks the label (`[a-z0-9-]`, 1-63), `pub` round-trips as a 32-byte key, `target` is a canonical CID, `seq` is a positive safe integer, `ts` is not more than 5 min in the future, <= 8 keywords of `[a-z0-9]{2,32}` (no duplicates), title <= 80 chars without control characters, and the signature. Anything else is dropped.
**Updates.** `publish(name, target)` signs `seq = max(local, network) + 1`. Stores and resolvers keep only the highest `seq` per `(name, pub)` (`Store.putName`), so a stale valid record cannot roll a name back locally. The site manifest a name points at is an ordinary immutable site, so every version keeps its own `frenet-site://` ID.
**Distribution.** No DHT value store: like blocks, a record is announced as a provider record, under `sha256("frenet-name/v1\nname\npub")` for resolution and `sha256("frenet-kw/v1\nword")` per keyword for search. Peers holding a record serve it over `/frenet/name/1.0.0` (one JSON request <= 512 B, response <= 64 KB, rate limited like blocks): `{k:'name',name,pub}` -> record or null, `{k:'kw',word}` -> up to 20 records. `resolve` asks up to 8 providers, verifies each answer and takes the highest `seq` (15 s in-memory cache; falls back to the locally cached copy if the network has nothing). Every foreign record is stored (capped at 5000, oldest first) so this node can serve it onward. Own names are re-announced every 6 h.
**Search.** `search(q)` tokenises to <= 5 words, asks keyword providers per word, keeps only records that verify and really contain that word (a provider cannot stuff records into a keyword it does not carry), then returns the records whose name/title/keywords contain *all* words: own first, then newest.
**Gateway.** Host `<name>.<pub>.localhost` is resolved to the current `target` and served exactly like a site (same CSP, own origin per name). Resolution happens only after the method and `Sec-Fetch-*` checks, so a drive-by page cannot make this node run name lookups.
**Local API.** `POST /api/sites` also takes `name`, `title`, `keywords` (validated before anything is published, so a bad name leaves no orphan site); `GET /api/names`, `GET /api/names/resolve?name&pub`, `GET /api/search?q`.
**Limits.** Names are not globally human-memorable (the key is in the address). Rollback to an older valid record is possible if only stale holders are reachable. Search is opt-in, unranked and spammable: anyone can publish under any keyword; there is no reputation, Sybil resistance or content (full-text) index. Provider records expire, so the publishing node should stay online (own names are re-announced, blocks are not yet). No transfer or revocation of a name.

## Retention
Own blocks are pinned (until deleted or per-file TTL). Replicas fetched from peers expire after `--replica-ttl-days`. Expired blocks are never served and are swept every 10 min and at startup. `--quota-mb` bounds local bytes; over-quota adds fail and roll back, over-quota replicas are served but not cached. Local delete removes manifest + unshared chunks and vacuums the DB; copies on other peers are outside our control.

## Local API (127.0.0.1)
`GET /api/status|peers|messages|events(SSE)|blocks/<cid>|files|names|names/resolve|search`, `POST /api/send|dial|blocks|files|files/get|files/delete|sites` (base64 `data`). Foreign `Host` headers (DNS rebinding) and cross-origin POSTs are rejected; JSON content-type required; strict CSP on static files.

## Known limits
- NAT traversal is best-effort, not guaranteed. Layers, in order: UPnP port mapping (router permitting) -> AutoNAT reachability detection -> circuit-relay v2 reservation on `--relay` peers (or relays discovered among connected peers) -> DCUtR hole punching to upgrade relayed links to direct. Symmetric NATs / CGNAT may stay relay-only.
- Relayed connections are limited (a relay we run allows 2 min / 2 MiB per connection). Messaging and block fetch are allowed over them; large files may need the direct upgrade to succeed. Relays are not a privacy layer: they see peer IDs and traffic volume, but not content (Noise is end-to-end), and `remotePeer` is still the authenticated peer, never the relay.
- Running a relay (`--relay-server`) donates bandwidth (capped at 64 reservations). There is no relay discovery service or reputation yet: you must supply relay addresses you trust to be available.
- Firewalls are not modified.
- Messages to offline peers fail; no store-and-forward.
- Reputation, Sybil resistance, secure updates: not implemented.
