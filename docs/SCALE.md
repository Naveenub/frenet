# Scale tests

`npm run test:scale` starts N real FRENET nodes in **one process** (loopback TCP + Noise + yamux, no mDNS, no NAT, no QUIC). Each node dials only two earlier nodes, so content must be found through the DHT rather than a full mesh. It then fetches blocks stored on one node from another and sends direct messages between random pairs.

```
FRENET_SCALE_N=40 FRENET_SCALE_FETCHES=30 FRENET_SCALE_MSGS=20 npm run test:scale -- --json
FRENET_SCALE_SETTLE_MS=6000      # wait after joining before measuring (default 6000)
FRENET_SCALE_MIN_FETCH_OK=0.9    # exit 2 when fewer fetches succeed
```

Reported: join time, routing-table size (`rtMin`, `rtMedian`), average connections, fetch and message success and p50/p95 latency, process RSS.

## What it shows and what it does not
It measures one machine. It says nothing about WAN latency, NAT, churn, packet loss, hostile peers or thousands of independent hosts. Those need the public testnet (`docs/TESTNET.md`). Latencies here are loopback and are not a promise.

## Results (sandbox, Node 22, 20 to 40 nodes, one run each unless noted)
| N | settle | fetch ok | fetch p50 / p95 | message ok | rtMin | RSS |
|---|---|---|---|---|---|---|
| 20 | 2 s | 9/20 | 56 / 67 ms | 7/20 | n/a | 305 MB |
| 20 | 6 s, five runs | 7/30, 20/30, 26/30, 30/30, 30/30 | 41 to 155 / 65 to 1464 ms | 7 to 20 of 20 | 0 to 9 | 275 to 481 MB |
| 20 | 20 s, two runs | 24/30 and 30/30 | 94 to 140 / 255 to 316 ms | 15/20 and 20/20 | 0 and 9 | 297 to 420 MB |
| 40 | 6 s | 28/30 | 211 / 715 ms | 18/20 | 0 | 445 MB |

## Finding (open)
In a freshly bootstrapped, sparsely joined network, **content lookup and direct messages are unreliable until every node's DHT routing table has filled**. Some nodes stay at 0 to 2 routing-table entries for 20 s or longer, and a node in that state finds nothing. The success rate swings from 23% to 100% between runs of the same configuration. Messages to a peer that is neither connected nor in the peer store are queued by the outbox, not delivered. Calling `dht.refreshRoutingTable()` on every node did not clearly fix it (20/30 and 26/30 in two runs). Not fixed here; the cause is unconfirmed. A real network with many bootstrap peers and long-lived nodes may behave differently, which is one more reason to run the testnet.
