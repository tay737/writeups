#!/usr/bin/env python3
import time
import ldap_oracle as O

tests = [
    ("*)(description=*", "baseline: any description"),
    ("*)(description>=a", "ordering: >= 'a'"),
    ("*)(description>=0", "ordering: >= '0'"),
    ("*)(description>=zzzzzzzz", "ordering: >= 'zzzzzzzz' (expect no-match)"),
    ("*)(description<=a", "ordering: <= 'a'"),
    ("*)(&(description>=a)(description<=b)", "range [a,b]"),
]

t0 = time.time()
for inj, note in tests:
    t = time.time()
    r = O.probe(inj)
    print(f"{note:48s} {r:28s} ({time.time()-t:.1f}s)", flush=True)
print(f"total {time.time()-t0:.1f}s", flush=True)
