#!/usr/bin/env python3
import pool_extract as P

P.init_pool()

tests = [
    ("change\n", "newline"),
    ("change\r", "carriage return"),
    ("change\t", "tab"),
    ("change\x0b", "vertical tab"),
    ("change\x0c", "form feed"),
    ("change\n\n", "double newline"),
    ("change ", "space"),
    ("change*", "wildcard (control: expect True)"),
    ("change", "exact 'change' (expect False)"),
]

for pre, note in tests:
    inj = f"*)(description={pre}*"
    print(f"{P.oracle(inj)!s:5s} {note:32s} prefix={pre!r}", flush=True)
print(f"requests: {P.REQ[0]}", flush=True)
