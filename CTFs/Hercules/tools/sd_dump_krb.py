#!/usr/bin/env python3
"""Dump ACEs of AD objects over LDAP using Kerberos (KRB5CCNAME).

usage: sd_dump_krb.py <dn> [<dn> ...]
"""
import sys, json, uuid
from ldap3 import Server, Connection, ALL, SASL, KERBEROS
from ldap3.protocol.microsoft import security_descriptor_control
from impacket.ldap import ldaptypes

DC = "dc.hercules.htb"

def conn():
    s = Server(DC, get_info=ALL)
    return Connection(s, authentication=SASL, sasl_mechanism=KERBEROS, auto_bind=True)

def sidmap(c):
    c.search("DC=hercules,DC=htb", "(|(objectClass=user)(objectClass=group)(objectClass=computer))",
             attributes=["objectSid", "sAMAccountName"], paged_size=1000)
    m = {str(e.objectSid.value): str(e.sAMAccountName) for e in c.entries if e.objectSid}
    return m

def rights(mask, objtype=""):
    out = []
    if mask & 0x000F01FF == 0x000F01FF:
        out.append("GenericAll")
    else:
        for bit, nm in [(1, "CreateChild"), (2, "DeleteChild"), (4, "ListChildren"), (8, "Self"),
                        (0x10, "ReadProperty"), (0x20, "WriteProperty"), (0x40, "DeleteTree"),
                        (0x80, "ListObject"), (0x100, "ExtendedRight"), (0x10000, "Delete"),
                        (0x20000, "ReadControl"), (0x40000, "WriteDacl"), (0x80000, "WriteOwner"),
                        (0x100000, "Synchronize")]:
            if mask & bit:
                out.append(nm)
    return ",".join(out)

def dump(dn, c, m):
    c.search(dn, "(objectClass=*)", attributes=["nTSecurityDescriptor", "name"], search_scope="BASE",
             controls=security_descriptor_control(sdflags=0x04))
    if not c.entries:
        print(f"!! {dn}: not found"); return
    e = c.entries[0]
    try:
        raw = e.entry_raw_attributes["nTSecurityDescriptor"][0]
    except Exception:
        print(f"!! {dn}: SD not readable"); return
    sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=raw)
    print(f"\n##### {e.entry_dn}")
    for ace in sd["Dacl"]["Data"]:
        if ace["AceType"] not in (0x00, 0x05):
            continue
        mask = ace["Ace"]["Mask"]["Mask"]
        sid = ace["Ace"]["Sid"].formatCanonical()
        who = m.get(sid, sid)
        obj = ""
        try:
            t = ace["Ace"]["ObjectType"]
            if t and t != b"\x00" * 16:
                obj = str(uuid.UUID(bytes_le=t))
        except Exception:
            pass
        if who in ("NT AUTHORITY\\SYSTEM", "Domain Admins", "Enterprise Admins", "Administrators",
                   "BUILTIN\\Administrators"):
            continue
        print(f"   {who:32s} {rights(mask):58s} obj={obj}")

if __name__ == "__main__":
    c = conn()
    m = sidmap(c)
    for dn in sys.argv[1:]:
        dump(dn, c, m)
    c.unbind()
