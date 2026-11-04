# Architecture (Phase 1)

```
web/ (dashboard)  <--HTTP+SSE, loopback only-->  src/api.ts
                                                    |
                              src/node.ts  (libp2p: tcp, noise, yamux, mdns, bootstrap, kad-dht, identify, ping)
                               |-- src/identity.ts   Ed25519 key file, 0600
                               |-- src/messaging.ts  /frenet/msg/1.0.0, one JSON message per stream
                               `-- src/store.ts      SQLite (node:sqlite), local only
```

## Messaging protocol `/frenet/msg/1.0.0`
- One stream per message: `{v:1,id,ts,body}` JSON, closed by sender.
- Sender identity = `connection.remotePeer` (authenticated by Noise). Claimed identity is never read from the payload.
- Receiver checks: size <= 32 KB frame / 16 KB body, schema, timestamp within 5 min, unseen `(peer,id)`, token-bucket rate limit (burst 20, 2/s).
- Messages are not yet signed at the application layer, so they are not verifiable by third parties; they are authenticated only per hop (direct connection).

## Local API (127.0.0.1)
`GET /api/status|peers|messages|events(SSE)`, `POST /api/send|dial`. Foreign `Host` headers (DNS rebinding) and cross-origin POSTs are rejected; JSON content-type required; strict CSP on static files.

## Known limits
- No NAT traversal or relays: peers must be directly reachable (LAN, public IP, or forwarded port). Firewalls are not modified.
- Messages to offline peers fail; no store-and-forward.
- Reputation, Sybil resistance, secure updates: not implemented.
