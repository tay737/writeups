#!/usr/bin/env python3
"""Check the full (example-writeup) user list for description fields."""
import pool_extract as P

P.init_pool()

USERS = """adriana.i angelo.o anthony.r ashley.b auditor bob.w camilla.b clarissa.c
elijah.m fernando.r fiona.c harris.d heather.s jacob.b james.s jennifer.a jessica.e
joel.c johanna.f johnathan.j ken.w mark.s mikayla.a natalie.a nate.h patrick.s
ramona.l ray.n rene.s shae.j stephanie.w stephen.m tanya.r taylor.m tish.c
vincent.g web_admin will.s winda.s zeke.s admin administrator krbtgt""".split()

print(f"checking {len(USERS)} accounts for a description\n", flush=True)
hits = []
for u in USERS:
    r = P.oracle(f"{u})(description=*")
    if r:
        hits.append(u)
        print(f"  [DESC] {u}", flush=True)
    else:
        print(f"  -      {u}", flush=True)

print(f"\naccounts WITH description: {hits}", flush=True)
print(f"requests: {P.REQ[0]}", flush=True)
