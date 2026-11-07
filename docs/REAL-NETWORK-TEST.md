# Real-network test checklist

Closes the "untested" items the namespace lab cannot cover. Run, then record results in README "Status".

Setup: one public host (VPS) running `npm start -- --relay-server --listen /ip4/0.0.0.0/tcp/4001 --listen /ip4/0.0.0.0/udp/4001/quic-v1 --announce /ip4/<ip>/tcp/4001 --announce /ip4/<ip>/udp/4001/quic-v1`. Two NATed hosts on different networks, each with `--relay <relay multiaddr>`.

| Case | Do | Pass |
|---|---|---|
| Home router | A and B on different home routers; B dials A's `/p2p-circuit` address, send a message | delivered; `GET /api/peers` shows relayed link |
| CGNAT | A on a mobile hotspot | same |
| UPnP | A on a UPnP router, `--relay` omitted, 4 public bootstrap peers connected | a public `/ip4/<wan>/tcp/4001` address appears in `GET /api/status`; B dials it directly |
| UDP-blocking firewall | block outbound UDP on A | QUIC dial fails, TCP/relay still delivers |
| mDNS Wi-Fi | two laptops, same SSID, `--no-mdns` off | peers appear with no bootstrap; repeat on a guest/isolated SSID and note failure |
| Hole punching | after relayed link is up, wait 60 s | expected to **fail** until the transport fix; a direct link means it was fixed |
