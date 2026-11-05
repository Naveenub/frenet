#!/usr/bin/env python3
"""Cross-check src/recovery.ts Shamir sharing against an independent implementation.

The reference is SLIP-39's GF(256) arithmetic and Lagrange interpolation (`shamir-mnemonic`, the Trezor reference
library; same field: Rijndael polynomial 0x11b, generator 3). Our share *format* differs, so we only compare the
mathematics:
  1. every k-subset of our shares, interpolated at x=0 by the reference, yields our secret (+ its 4-byte hash trailer);
  2. interpolating a k-subset at any other share's x reproduces that share (all n shares lie on one degree-(k-1) polynomial);
  3. shares the reference computes at fresh x coordinates are accepted by our combine and give the same secret.

    pip install shamir-mnemonic
    python3 -I scripts/crosscheck-shamir.py          (run from the repo root)
"""
import base64, hashlib, itertools, json, math, random, subprocess, sys
from shamir_mnemonic.shamir import RawShare, _interpolate

PREFIX = "frenet-share:1:"

def b64u_decode(s): return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
def b64u_encode(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def parse(share):
    p = share.split(":")
    assert share.startswith(PREFIX) and len(p) == 7, share
    return int(p[2]), p[3], int(p[4]), b64u_decode(p[5])

def make(k, setid, x, data):
    body = f"{PREFIX}{k}:{setid}:{x}:{b64u_encode(data)}"
    return f"{body}:{hashlib.sha256(body.encode()).hexdigest()[:8]}"

def node(*args, stdin=None):
    return subprocess.run(["node", "--import", "tsx", "scripts/shamir-vectors.ts", *args], input=stdin, capture_output=True, text=True, check=True).stdout

vectors = json.loads(node())
checked = 0
combine_sets, expected = [], []
for v in vectors:
    k, n = v["k"], v["n"]
    secret = bytes.fromhex(v["secret"])
    framed = secret + hashlib.sha256(secret).digest()[:4]
    parsed = [parse(s) for s in v["shares"]]
    raw = {x: RawShare(x, d) for (_, _, x, d) in parsed}
    setid = parsed[0][1]
    xs = sorted(raw)
    # all subsets when there are few; otherwise 200 random ones (never enumerate: C(32,16) is 601 million)
    subsets = list(itertools.combinations(xs, k)) if math.comb(n, k) <= 300 else [tuple(sorted(random.sample(xs, k))) for _ in range(200)]
    for sub in subsets:
        shares = [raw[x] for x in sub]
        assert _interpolate(shares, 0) == framed, f"secret mismatch k={k} n={n} subset={sub}"
        for other in raw:
            if other not in sub:
                assert _interpolate(shares, other) == raw[other].data, f"not on one polynomial k={k} n={n} x={other}"
        checked += 1
    # (3) the reference produces fresh shares; our combine must accept them in place of originals
    sub = [raw[x] for x in sorted(raw)[:k]]
    fresh_x = [x for x in range(1, 33) if x not in raw][:k]
    if len(fresh_x) == k:
        fresh = [make(k, setid, x, _interpolate(sub, x)) for x in fresh_x]
        combine_sets.append(fresh); expected.append(v["secret"])
if combine_sets:
    got = json.loads(node("combine", stdin=json.dumps(combine_sets)))
    assert got == expected, "our combine rejected or mis-combined shares produced by the reference implementation"
print(f"OK: {len(vectors)} vectors, {checked} subsets agree with the reference; {len(combine_sets)} reference-made share sets recombined by our code")
