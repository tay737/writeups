#!/usr/bin/env python3
import re
import requests
import urllib3

urllib3.disable_warnings()
BASE = "https://10.129.242.196"
S = requests.Session()
S.verify = False
r = S.get(f"{BASE}/Login", timeout=15)
tok = re.search(r'name="__RequestVerificationToken"[^>]*value="([^"]+)"', r.text).group(1)
r = S.post(f"{BASE}/Login", data={"Username": "ken.w", "Password": "change*th1s_p@ssw()rd!!",
                                  "RememberMe": "true",
                                  "__RequestVerificationToken": tok},
           timeout=20, allow_redirects=False)
ck = S.cookies.get(".ASPXAUTH")
open("/home/kali/hercules/ken.cookie", "w").write(ck)
print(f"status={r.status_code} loc={r.headers.get('Location')}")
print(f"ASPXAUTH({len(ck)} chars): {ck}")
