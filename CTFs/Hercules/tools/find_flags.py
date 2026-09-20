#!/usr/bin/env python3
"""Recursively hunt for flag files over SMB (Kerberos, KRB5CCNAME ccache).

usage: find_flags.py [share] [start-dir]
"""
import sys, re
from impacket.smbconnection import SMBConnection

TARGET = "dc.hercules.htb"
USER, DOM = "Administrator", "hercules.htb"
PATTERNS = re.compile(r"(root|user|flag|proof)", re.I)
SKIP = {"appdata", "windows", "winsxs", "temp", "nethood", "recent", "cookies",
        "sendto", "templates", "favorites", "links", "$recycle.bin", "history",
        "my documents", "start menu", "saved games", "searches", "3d objects"}


def walk(conn, share, path, depth=0, out=None):
    if depth > 6:
        return
    try:
        entries = conn.listPath(share, path + "\\*")
    except Exception as e:
        print(f"[!] {share}:{path}: {e}")
        return
    for e in entries:
        name = e.get_longname()
        if name in (".", ".."):
            continue
        full = path + "\\" + name
        if e.is_directory():
            if name.lower() in SKIP:
                continue
            walk(conn, share, full, depth + 1, out)
        else:
            if PATTERNS.search(name) or e.get_filesize() < 200 and name.lower().endswith(".txt"):
                line = f"{share}:{full}  ({e.get_filesize()} bytes, {e.get_mtime()})"
                print(line, flush=True)
                if out:
                    out.write(line + "\n")


def main():
    share = sys.argv[1] if len(sys.argv) > 1 else "C$"
    start = sys.argv[2] if len(sys.argv) > 2 else ""
    conn = SMBConnection(TARGET, TARGET, sess_port=445)
    conn.kerberosLogin(USER, "", DOM, "", "", None, useCache=True)
    print(f"[*] connected, walking {share}:{start}")
    with open("/tmp/flags_found.txt", "w") as fh:
        walk(conn, share, start, out=fh)
    print("[*] done")


if __name__ == "__main__":
    main()
