#!/usr/bin/env python3
"""Determine whether the /Login rate limit is per-session (cookie) or per-IP."""
import re
import time

import requests
import urllib3

urllib3.disable_warnings()
LOGIN = "https://10.129.242.196/Login"


def run(session_id, n=10):
    s = requests.Session()
    s.verify = False
    r0 = s.get(LOGIN, timeout=15)
    tok = re.search(r'name="__RequestVerificationToken"[^>]*value="([^"]+)"', r0.text).group(1)
    codes = []
    for i in range(n):
        r = s.post(LOGIN, data={"Username": "auditor", "Password": "x",
                                "RememberMe": "false",
                                "__RequestVerificationToken": tok}, timeout=20)
        codes.append(r.status_code)
        if r.status_code == 429:
            break
        time.sleep(0.15)
    return codes


t0 = time.time()
for sid in range(3):
    codes = run(sid)
    print(f"session {sid}: {codes}", flush=True)
print(f"elapsed {time.time()-t0:.1f}s", flush=True)
