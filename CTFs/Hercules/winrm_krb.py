#!/usr/bin/env python3
"""Minimal WinRM-over-Kerberos client (SPNEGO/Negotiate) — no pywinrm needed.

usage: winrm_krb.py "<command>"     # env: KRB5CCNAME, KRB5_CONFIG
"""
import sys, re, base64, urllib3
import requests
import gssapi

import uuid

HOST = "dc.hercules.htb"
PORT = 5986
URL = f"https://{HOST}:{PORT}/wsman"
SPN = f"HTTP/{HOST}@HERCULES.HTB"

urllib3.disable_warnings()

NS_S = "http://www.w3.org/2003/05/soap-envelope"
NS_WSMAN = "http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
NS_RSP = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell"
NS_XSI = "http://www.w3.org/2001/XMLSchema-instance"
EPR = f"<w:To s:mustUnderstand=\"true\">{URL}</w:To>" \
      f"<w:ResourceURI s:mustUnderstand=\"true\">{NS_RSP}/cmd</w:ResourceURI>" \
      f"<w:ReplyTo><a:Address s:mustUnderstand=\"false\">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address></w:ReplyTo>" \
      f"<w:Action s:mustUnderstand=\"true\">{{action}}</w:Action>" \
      f"<w:MessageID>uuid:{{mid}}</w:MessageID>" \
      f"<w:DataLocale s:mustUnderstand=\"false\" xml:lang=\"en-US\"/>"

HEADER = (f"<s:Header><a:Action s:mustUnderstand=\"true\">{{action}}</a:Action>"
          f"<a:To s:mustUnderstand=\"true\">{URL}</a:To>"
          f"<w:ResourceURI s:mustUnderstand=\"true\">{NS_RSP}/cmd</w:ResourceURI>"
          f"<a:ReplyTo><a:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address></a:ReplyTo>"
          f"<a:MessageID>uuid:{{mid}}</a:MessageID>"
          f"<wsman:OptionSet xmlns:wsman=\"{NS_WSMAN}\">{{options}}</wsman:OptionSet>"
          f"{{selectors}}"
          f"</s:Header>")


def envelope(body, action, selectors="", options=""):
    mid = str(uuid.uuid4())
    hdr = HEADER.format(action=action, mid=mid, selectors=selectors, options=options)
    return (f"<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
            f"<s:Envelope xmlns:s=\"{NS_S}\" xmlns:a=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\""
            f" xmlns:w=\"{NS_WSMAN}\" xmlns:rsp=\"{NS_RSP}\" xmlns:xsi=\"{NS_XSI}\""
            f" xmlns:cfg=\"http://schemas.microsoft.com/wbem/wsman/1/config\""
            f" xmlns:p=\"http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd\">"
            f"{hdr}<s:Body>{body}</s:Body></s:Envelope>")


class WinRM:
    def __init__(self):
        self.s = requests.Session()
        self.s.verify = False
        self.ctx = None

    def _context(self):
        name = gssapi.Name(SPN, gssapi.NameType.kerberos_principal)
        return gssapi.SecurityContext(name=name, usage="initiate")

    def post(self, data, action):
        """Fresh Kerberos/SPNEGO context per request (IIS expects a new AP-REQ each time)."""
        hdrs = {"Content-Type": "application/soap+xml;charset=UTF-8"}
        ctx = self._context()
        tok = ctx.step(None)
        for _ in range(4):
            h = dict(hdrs)
            if tok is not None:
                h["Authorization"] = "Negotiate " + base64.b64encode(tok).decode()
            r = self.s.post(URL, data=data, headers=h)
            if r.status_code == 401:
                ch = r.headers.get("WWW-Authenticate", "")
                m = re.search(r"Negotiate ([A-Za-z0-9+/=]+)", ch)
                if not m:
                    raise SystemExit("401 without token: " + ch)
                tok = ctx.step(base64.b64decode(m.group(1)))
                continue
            if r.status_code not in (200, 500):
                raise SystemExit(f"HTTP {r.status_code}: {r.text[:400]}")
            return r
        raise SystemExit("auth failed")


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "whoami"

    w = WinRM()
    # 1. Create shell
    body = (f"<rsp:Create xmlns:rsp=\"{NS_RSP}\">"
            f"<rsp:InputStreams>stdin</rsp:InputStreams>"
            f"<rsp:OutputStreams>stdout stderr</rsp:OutputStreams>"
            f"</rsp:Create>")
    r = w.post(envelope(body, f"{NS_RSP}/Create"), f"{NS_RSP}/Create")
    m = re.search(r"ShellId>(?:<[^>]+>)*([0-9a-fA-F-]{36})", r.text)
    shell = m.group(1) if m else None
    if not shell:
        m = re.search(r"([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})", r.text)
        shell = m.group(1) if m else None
    if not shell:
        raise SystemExit("no shell id:\n" + r.text[:1500])
    sel = f"<w:SelectorSet><w:Selector Name=\"ShellId\">{shell}</w:Selector></w:SelectorSet>"

    # 2. Run command
    body = (f"<rsp:CommandLine><rsp:Command>cmd.exe /c {cmd}</rsp:Command></rsp:CommandLine>")
    r = w.post(envelope(body, f"{NS_RSP}/Command", selectors=sel), f"{NS_RSP}/Command")
    m = re.search(r"CommandId>([0-9a-fA-F-]{36})<", r.text)
    if not m:
        m = re.search(r"([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})", r.text)
    cid = m.group(1)

    # 3. Receive output
    out = []
    for _ in range(50):
        body = (f"<rsp:Receive><rsp:DesiredStream CommandId=\"{cid}\">stdout stderr</rsp:DesiredStream></rsp:Receive>")
        r = w.post(envelope(body, f"{NS_RSP}/Receive", selectors=sel), f"{NS_RSP}/Receive")
        chunks = re.findall(r"<rsp:Stream[^>]*Name=\"(stdout|stderr)\"[^>]*>([^<]*)</rsp:Stream>", r.text)
        for name, b64 in chunks:
            if b64:
                out.append(base64.b64decode(b64).decode("utf-8", "replace"))
        if "<rsp:CommandState" in r.text and 'State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done"' in r.text:
            break
        if "</rsp:ReceiveResponse>" in r.text and "CommandState" not in r.text:
            break
    sys.stdout.write("".join(out))


if __name__ == "__main__":
    main()
