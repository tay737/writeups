#!/usr/bin/env python3
"""Analyse BloodHound v4/v5 JSON: outbound ACL edges, memberships, OU placement.

usage: bh_analyze.py <principal>            # outbound edges + memberships
       bh_analyze.py --over <target>        # inbound edges (who has rights over target)
       bh_analyze.py --group <groupname>    # members of a group
"""
import json, glob, sys, collections

D = "/home/kali/hercules/bh/x"
data = {f.split("_")[-1].replace(".json", ""): json.load(open(f))["data"]
        for f in glob.glob(D + "/*.json")}

objs = {}
for kind, lst in data.items():
    for o in lst:
        p = o.get("Properties", {})
        for k in {str(p.get("name", "")).lower(),
                  str(p.get("samaccountname", "")).lower(),
                  str(o.get("ObjectIdentifier", "")).lower()}:
            if k:
                objs[k] = (kind, o)

def get(name):
    return objs.get(str(name).lower())

def nm(sid_or_name, fallback_key=None):
    if sid_or_name is None:
        return "?"
    o = objs.get(str(sid_or_name).lower())
    if o:
        return o[1]["Properties"].get("name")
    return sid_or_name

def aces(o):
    return o.get("Aces", []) or []

def show_outbound(name):
    g = get(name)
    if not g:
        print(f"!! {name} not found"); return
    kind, o = g
    p = o["Properties"]
    print(f"\n===== {p.get('name')}  [{kind}]  sid={o.get('ObjectIdentifier')}")
    print(f"  enabled={p.get('enabled')}  pwdlastset={p.get('pwdlastset')}")
    print(f"  groups: {p.get('groups')}")
    dn = p.get("distinguishedname", "")
    print(f"  ou: {dn.split(',', 1)[1] if ',' in dn else dn}")
    print(f"  description: {p.get('description')}")
    c = collections.Counter()
    for a in aces(o):
        c[(a.get("RightName"), bool(a.get("IsInherited")))] += 1
    print("  --- outbound edge summary ---")
    for (r, inh), n in sorted(c.items()):
        print(f"    {r:22s} inherited={inh}  x{n}")
    print("  --- non-inherited outbound edges (direct) ---")
    for a in aces(o):
        if a.get("IsInherited"):
            continue
        t = a.get("ObjectIdentifier")
        print(f"    {a.get('RightName'):22s} -> {nm(t)}")

def show_over(name, right_filter=None):
    g = get(name)
    if not g:
        print(f"!! {name} not found"); return
    kind, o = g
    print(f"\n##### who controls {o['Properties'].get('name')}")
    for a in aces(o):
        r = a.get("RightName")
        if right_filter and r not in right_filter:
            continue
        print(f"   {nm(a.get('PrincipalSID')):28s} -> {r}  inherited={a.get('IsInherited')}")

def show_group(name):
    g = get(name)
    if not g:
        print(f"!! {name} not found"); return
    kind, o = g
    print(f"\n##### members of {o['Properties'].get('name')}")
    for a in aces(o):
        if a.get("RightName") in ("Member", "GenericAll") or True:
            pass
    # members come from the 'members' property or from users' groups
    p = o["Properties"]
    print("   properties.members:", p.get("members"))
    for k, (knd, u) in objs.items():
        if knd != "users":
            continue
        if p.get("name") in (u["Properties"].get("groups") or []):
            print("   member:", u["Properties"].get("name"))

if __name__ == "__main__":
    if sys.argv[1] == "--over":
        show_over(sys.argv[2], sys.argv[3].split(",") if len(sys.argv) > 3 else None)
    elif sys.argv[1] == "--group":
        show_group(sys.argv[2])
    else:
        for a in sys.argv[1:]:
            show_outbound(a)
