#!/usr/bin/env python3
"""Read raw nTSecurityDescriptor from LDAP and dump ACEs (ground truth, incl. OUs)."""
import sys, json, collections
from ldap3 import Server, Connection, ALL, SIMPLE
from ldap3.protocol.microsoft import security_descriptor_control
from impacket.ldap import ldaptypes

DC = "10.129.242.196"
BASE = "DC=hercules,DC=htb"
USER = "natalie.a@hercules.htb"
PASS = "Prettyprincess123!"

ACCESS = {
    0x00000001: "CreateChild", 0x00000002: "DeleteChild",
    0x00000004: "ListChildren", 0x00000008: "Self",
    0x00000010: "ReadProperty", 0x00000020: "WriteProperty",
    0x00000040: "DeleteTree", 0x00000080: "ListObject",
    0x00000100: "ExtendedRight", 0x00010000: "Delete",
    0x00020000: "ReadControl", 0x00040000: "WriteDacl",
    0x00080000: "WriteOwner", 0x00100000: "Synchronize",
    0x000F01FF: "FullControl",
}

def conn():
    s = Server(DC, get_info=ALL)
    return Connection(s, user=USER, password=PASS, authentication=SIMPLE, auto_bind=True)

def sidmap(c):
    c.search(BASE, "(|(objectClass=user)(objectClass=group)(objectClass=computer))",
             attributes=["objectSid", "sAMAccountName"], paged_size=500)
    m = {str(e.objectSid.value): str(e.sAMAccountName) for e in c.entries}
    c.search(BASE, "(objectClass=*)", attributes=["objectSid", "name"],
             search_scope="LEVEL", paged_size=500)
    for e in c.entries:
        if e.objectSid:
            m.setdefault(str(e.objectSid.value), str(e.name))
    return m

def rights_from_mask(mask, is_obj=False):
    out = []
    if mask & 0x000F01FF == 0x000F01FF:
        return ["GenericAll"]
    for bit, nm in ACCESS.items():
        if nm in ("FullControl",):
            continue
        if mask & bit:
            out.append(nm)
    if mask & 0x00010000 and mask & 0x00000020:  # DELETE|WRITE_PROP -> approx GenericWrite
        pass
    return out

def dump(target_dn, c, m, interesting=None):
    c.search(target_dn, "(objectClass=*)", attributes=["nTSecurityDescriptor", "name"],
             search_scope="BASE", controls=security_descriptor_control(sdflags=0x04))
    e = c.entries[0]
    raw = e.nTSecurityDescriptor.raw_values[0]
    sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=raw)
    print(f"\n##### {e.entry_dn}")
    for ace in sd["Dacl"]["Data"]:
        if ace["AceType"] not in (0x00, 0x05):  # ACCESS_ALLOWED
            continue
        mask = ace["Ace"]["Mask"]["Mask"]
        sid = ace["Ace"]["Sid"].formatCanonical()
        who = m.get(sid, sid)
        objtype = ""
        try:
            if ace["Ace"]["ObjectType"] and ace["Ace"]["ObjectType"] != b"\x00" * 16:
                from uuid import UUID
                objtype = str(UUID(bytes_le=ace["Ace"]["ObjectType"]))
        except Exception:
            pass
        if interesting and who.lower() not in interesting and objtype not in interesting:
            continue
        print(f"   {who:34s} mask=0x{mask:08x} {','.join(rights_from_mask(mask)):40s} obj={objtype}")

if __name__ == "__main__":
    c = conn()
    m = sidmap(c)
    json.dump(m, open("/home/kali/hercules/sidmap.json", "w"), indent=1)
    print("sidmap entries:", len(m))
    targets = sys.argv[1:]
    for t in targets:
        dump(t, c, m)
    c.unbind()
