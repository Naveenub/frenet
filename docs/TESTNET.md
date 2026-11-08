# Public testnet kit

**Status: no public testnet is running.** This page is what an operator needs to start one. Starting it needs hosts, DNS and people that this repository cannot provide.

## 1. Bootstrap and relay hosts (3 or more, in different networks or regions)
Each host needs a public IPv4 address and UDP and TCP port 4001 open in its **own** firewall (do not disable the host firewall; open only that port).
```
docker build -t frenet .          # Dockerfile is untested, see its first line
docker run -d --name frenet --restart unless-stopped -v frenet-data:/data -p 4001:4001/tcp -p 4001:4001/udp frenet \
  --relay-server --listen /ip4/0.0.0.0/tcp/4001 --listen /ip4/0.0.0.0/udp/4001/quic-v1 \
  --announce /ip4/<PUBLIC_IP>/tcp/4001 --announce /ip4/<PUBLIC_IP>/udp/4001/quic-v1
```
Without Docker: `npm ci && npm run build && node dist/cli.js --relay-server ...` with the same flags. Read each host's peer ID from its log or `GET /api/status` (loopback), and form `/ip4/<ip>/tcp/4001/p2p/<peerId>`.

## 2. Publish the list
Publish the three or more multiaddrs on a page you control and in the repository. Participants run `frenet --bootstrap <addr> --bootstrap <addr> --relay <addr>`. Bootstrap and relay peers you configure are exempt from auto-blocking and the proof-of-work rule, so do not hand strangers the ability to list their own.

## 3. Before inviting anyone
- Replace the placeholder contact in `SECURITY.md` with a monitored address.
- Run `docs/REAL-NETWORK-TEST.md` (home router, CGNAT, UPnP, UDP-blocked, mDNS) and record results in the README status.
- Run `npm run test:scale` and read `docs/SCALE.md`, in particular the open routing-table finding: with few bootstrap peers a new node may not find content for a while.
- Decide whether `--min-identity-bits` is on. It partitions the network from nodes that did not mine, so the whole testnet must agree.
- Say plainly on the page that the code has had no independent audit (`docs/AUDIT.md`) and that testnet data may be lost.

## 4. What to watch
`GET /api/status`, `/api/peers` and `/api/reputation` on each host (loopback; use SSH). There is no central telemetry by design, so health reports come from operators.
