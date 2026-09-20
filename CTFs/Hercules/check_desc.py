#!/usr/bin/env python3
import ldap_oracle as O

users = ["auditor", "will.s", "mark.s", "ashley.b", "heather.s", "stephen.m",
         "patrick.s", "jennifer.a", "zeke.s", "tish.c", "admin", "administrator"]

print("=== per-user description check (scoped to app's base filter) ===", flush=True)
for u in users:
    print(f"{u:16s} -> {O.probe(u + ')(description=*')}", flush=True)

print("\n=== any user at all with a description? ===", flush=True)
for pat in ["*)(description=*", "*)(department=*", "*)(telephoneNumber=*"]:
    print(f"{pat:24s} -> {O.probe(pat)}", flush=True)
