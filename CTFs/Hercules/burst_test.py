#!/usr/bin/env python3
"""Find how many requests a single session may make before a 429."""
import re
import requests
import urllib3

urllib3.disable_warnings()
LOGIN = "https://10.129.242.196/Login"

s = requests.Session()
s.verify = False
r0 = s.get(LOGIN, timeout=15)
tok = re.search(r'name="__RequestVerificationToken"[^>]*value="([^"]+)"', r0.text).group(1)
n = 0
for i in range(40):
    r = s.post(LOGIN, data={"Username": "auditor", "Password": "x", "RememberMe": "false",
                            "__RequestVerificationToken": tok}, timeout=20)
    n += 1
    print(f"req {n}: {r.status_code}", flush=True)
    if r.status_code == 429:
        break
