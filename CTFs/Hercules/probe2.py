#!/usr/bin/env python3
import pool_extract as P

P.init_pool()

tests = [
    ("*)(sAMAccountName=auditor", "sanity: exact user match (expect True)"),
    ("*)(sAMAccountName=audito", "sanity: partial without wildcard (expect False)"),
    ("*)(description=change*", "desc baseline 'change'"),
    ("*)(description=change\\2a*", "desc 'change' + escaped literal asterisk"),
    ("*)(description=changef*", "desc 'changef' (expect False)"),
    ("*)(description=changet*", "desc 'changet'"),
    ("*)(description=changet\\2a*", "desc 'changet' + escaped asterisk"),
    ("*)(description=changet\\2ath*", "desc 'changet*th'"),
    ("*)(description=changet\\2a*th*", "desc contains 'changet' '*th'"),
    ("*)(description=change!*", "desc 'change!'"),
    ("*)(description=change1*", "desc 'change1'"),
    ("*)(description=change\\*", "desc 'change' any suffix"),
]

for inj, note in tests:
    print(f"{P.oracle(inj)!s:5s} {note}", flush=True)
