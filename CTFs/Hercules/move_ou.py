#!/usr/bin/env python3
"""Move an AD object to another OU (LDAP modDN) authenticated with Kerberos (bob.w).

usage: move_ou.py
"""
from ldap3 import Server, Connection, ALL, SASL, KERBEROS

DC = "dc.hercules.htb"
SRC = "CN=Mark Stone,OU=Security Department,OU=DCHERCULES,DC=hercules,DC=htb"
NEW_SUP = "OU=Web Department,OU=DCHERCULES,DC=hercules,DC=htb"
RDN = "CN=Mark Stone"

s = Server(DC, get_info=ALL)
c = Connection(s, authentication=SASL, sasl_mechanism=KERBEROS, auto_bind=True)
print("bound as:", c.extend.standard.who_am_i())
ok = c.modify_dn(SRC, RDN, new_superior=NEW_SUP)
print("move_dn:", ok, c.result.get("description"), c.result.get("message"))
c.unbind()
