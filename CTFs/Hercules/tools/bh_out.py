#!/usr/bin/env python3
"""BloodHound JSON: what does <principal> control? (reverse ACE index)

usage: bh_out.py <principal> [--all]
"""
import json, glob, sys, collections

D = "/home/kali/hercules/bh/x"
data = {f.split("_")[-1].replace(".json", ""): json.load(open(f))["data"]
        for f in glob.glob(D + "/*.json")}

all_objs = []
for kind, lst in data.items():
    for o in lst:
        o["_kind"] = kind
        all_objs.append(o)

by_sid = {}
by_key = {}
for o in all_objs:
    sid = o.get("ObjectIdentifier")
    p = o.get("Properties", {})
    if sid:
        by_sid[sid.upper()] = o
    for k in {str(p.get("name", "")).lower(), str(p.get("samaccountname", "")).lower()}:
        if k:
            by_key[k] = o

def name_of(obj):
    return obj.get("Properties", {}).get("name") or obj.get("ObjectIdentifier")

def principals_for(pname):
    o = by_key.get(pname.lower())
    if not o:
        return None, []
    p = o["Properties"]
    sid = o.get("ObjectIdentifier")
    groups = []
    # member-of relationships are stored as group Properties.members (v4) or via users' groups
    for g in all_objs:
        if g["_kind"] != "groups":
            continue
        members = g["Properties"].get("members") or []
        if p.get("name") in members:
            groups.append(g)
    return o, groups

def controls(pname):
    o, groups = principals_for(pname)
    if not o:
        print("!! not found:", pname); return
    p = o["Properties"]
    print(f"\n===== {name_of(o)}  [{o['_kind']}]  sid={o.get('ObjectIdentifier')}")
    print(f"  dn: {p.get('distinguishedname')}")
    print(f"  groups (as listed in group objects): {[name_of(g) for g in groups]}")
    print(f"  Properties.groups: {p.get('groups')}")
    principals = {str(o.get("ObjectIdentifier", "")).upper(), str(p.get("name", "")).lower()}
    for g in groups:
        principals.add(str(g.get("ObjectIdentifier", "")).upper())
        principals.add(str(g["Properties"].get("name", "")).lower())
    principals.discard("")

    hits = collections.defaultdict(list)
    for obj in all_objs:
        for a in obj.get("Aces", []) or []:
            ps = str(a.get("PrincipalSID", ""))
            if ps.upper() in principals or ps.lower() in principals:
                hits[a.get("RightName")].append((name_of(obj), a.get("IsInherited")))
    print("  --- objects this principal controls (direct or via groups) ---")
    for r, lst in sorted(hits.items()):
        uniq = collections.Counter(lst)
        print(f"  [{r}]")
        for (tgt, inh), n in sorted(uniq.items()):
            print(f"      {tgt}   inherited={inh} x{n}")

if __name__ == "__main__":
    for a in sys.argv[1:]:
        controls(a)
