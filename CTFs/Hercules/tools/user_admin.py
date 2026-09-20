#!/usr/bin/env python3
"""Enable an account and/or set its password over LDAPS (Kerberos SASL).

usage: user_admin.py <dn> [--enable] [--password NEW]
env:   KRB5CCNAME / KRB5_CONFIG
"""
import sys, ssl
from ldap3 import Server, Connection, ALL, SASL, KERBEROS, Tls

dn = sys.argv[1]
enable = "--enable" in sys.argv
newpw = None
if "--password" in sys.argv:
    newpw = sys.argv[sys.argv.index("--password") + 1]

tls = Tls(validate=ssl.CERT_NONE)
s = Server("dc.hercules.htb", port=636, use_ssl=True, tls=tls, get_info=ALL)
c = Connection(s, authentication=SASL, sasl_mechanism=KERBEROS, auto_bind=True)
print("bound as:", c.extend.standard.who_am_i())

if enable:
    c.search(dn, "(objectClass=*)", attributes=["userAccountControl"], search_scope="BASE")
    uac = int(c.entries[0].userAccountControl.value)
    print(f"  uac before: {uac:#x}")
    new_uac = uac & ~0x2            # clear ACCOUNTDISABLE
    new_uac |= 0x200                # NORMAL_ACCOUNT
    ok = c.modify(dn, {"userAccountControl": [("MODIFY_REPLACE", new_uac)]})
    print(f"  enable: {ok} {c.result.get('description')} {c.result.get('message') or ''}")

if newpw:
    ok = c.modify(dn, {"unicodePwd": [("MODIFY_REPLACE", ('"%s"' % newpw).encode("utf-16-le"))]})
    print(f"  password: {ok} {c.result.get('description')} {c.result.get('message') or ''}")

c.unbind()
