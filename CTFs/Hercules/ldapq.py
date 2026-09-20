#!/usr/bin/env python3
"""Minimal LDAP helper (simple bind as ken.w) — NTLM is disabled on this DC."""
import sys, ldap3
from ldap3 import Server, Connection, ALL, SUBTREE, SIMPLE

DC = "10.129.242.196"
DOMAIN = "hercules.htb"
BASE = "DC=hercules,DC=htb"
USER = f"{DOMAIN}\\ken.w"
PASS = "change*th1s_p@ssw()rd!!"

def conn():
    s = Server(DC, get_info=ALL)
    c = Connection(s, user=f"ken.w@{DOMAIN}", password=PASS, authentication=SIMPLE, auto_bind=True)
    return c

def q(filterstr, attrs=None, base=BASE, scope=SUBTREE):
    c = conn()
    c.search(base, filterstr, search_scope=scope, attributes=attrs or ["*"])
    out = []
    for e in c.entries:
        out.append(dict(e.entry_attributes_as_dict))
    c.unbind()
    return out

if __name__ == "__main__":
    f = sys.argv[1] if len(sys.argv) > 1 else "(objectClass=user)"
    attrs = sys.argv[2].split(",") if len(sys.argv) > 2 else ["sAMAccountName", "memberOf", "description", "distinguishedName"]
    for e in q(f, attrs):
        print(e)
