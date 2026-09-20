# Hercules Walkthrough
(Windows/AD)
(Insane)
(Retired - at the time of completion)
[https://app.hackthebox.com/machines/Hercules](Link to machine)

# Proof of completion

<img width="1728" height="1072" alt="Screenshot 2026-09-20 at 13 51 12" src="https://github.com/user-attachments/assets/4147a6e2-2e69-4d92-b5ba-db633297aecd" />

### Attack path
`LDAP injection → blind extraction → passwd spray → ken.w → LFI → machineKey → web_admin → ODT/Responder → natalie.a → ACLs → auditor → ESC3 → ashley.b → IIS_Administrator → IIS_Webserver$ → SPN-less RBCD → Administrator`

## 1. Recon

- IIS / HTTPS
- Kerberos
- LDAP / LDAPS
- SMB
- WinRM over `5986`
- AD Web Services
- `NTLM:False` → Kerberos-only auth
- Used `fixhosts.c` + local `krb5.conf` for name resolution.

Web app: `https://hercules.htb/`

- ASP.NET MVC
- `/Login`
- Username = strict regex
- Password = weak validation
- Injection point was passwd field

## 2. LDAP Injection

The app URL-decodes input twice.

```text
%2a     → filtered
%252a   → %2a → *
```

So a double-encoded wildcard reaches LDAP.

### Oracle

- `Login attempt failed` → LDAP match
- `Invalid login attempt` → no match
- Form re-render → LDAP syntax error

Limits:

- `<` / `>` blocked → no binary search
- Used equality + wildcard
- Only the final injected condition could remain open.

## 3. Rate Limit

Rate limit was **per session**, not IP.

- ~10 requests/session → `429`
- Multiple sessions bypassed the limit.
- Built a 16-session extraction pool.

```bash
python3 pool_extract.py
```

## 4. Blind Extraction

Target:

```text
description
```

Found:

```text
johnathan.j
```

Description contained a passwd-style string

LDAP escaping was needed:

```text
* → \2a
( → \28
) → \29
```

Important:

> The account containing the hint did not own the credential.

Sprayed across the full user list → `ken.w`.

## 5. ken.w → LFI → web_admin

Login as `ken.w`.

LFI in the download function:

```text
/Home/Downloads?fileName=../../web.config
```

`web.config` exposed the ASP.NET `machineKey`.

Used it to forge `.ASPXAUTH`:

```text
ken.w → web_admin
```

`web_admin` unlocked extra web functionality, including the report upload.

## 6. ODT → Responder → natalie.a

Mailboxes suggested:

- domain credentials in use
- document sharing
- passwd-cleanup task

Uploaded a malicious ODT.

Flow:

```text
malicious ODT
    ↓
SMB callback
    ↓
Responder
    ↓
natalie.a NTLMv2
    ↓
passwd crack
```

Result: access as `natalie.a`.

## 7. natalie.a → auditor

BloodHound showed:

```text
natalie.a
   ↓ GenericWrite
Web Department users
```

Used Shadow Credentials against `bob.w`.

`bob.w` could modify `distinguishedName`, so a Security user could be moved into the Web OU.

This made the existing ACL apply.

Result:

```text
natalie.a
   ↓
auditor
   ↓
WinRM
```

## 8. auditor → fernando.r → ESC3 → ashley.b

`auditor` had `GenericAll` over the **Forest Migration OU**.

`fernando.r` was inside it.

Enabled `fernando.r`, then abused AD CS:

```text
fernando.r
   ↓
Enrollment Agent cert
   ↓
request cert on behalf of ashley.b
   ↓
ashley.b
```

This gave WinRM foothold (+1)

## 9. ashley.b → IIS_Administrator

`ashley.b` = IT Support.

passwd-cleanup task expanded IT support OU rights

Enabled:

```text
IIS_Administrator
```

`IIS_Administrator` = Service Operators.

rights over `IIS_Webserver$` inc.:

```text
User-Force-Change-Password
```

No SPN write, but machine account passwd can be changed

## 10. SPN-less RBCD

`IIS_Webserver$` had:

```text
AllowedToAct → DC$
```

but:

```text
servicePrincipalName = null
```

classic S4U failed.

used SPN-less RBCD with U2U:

```text
TGT
 ↓
read session key
 ↓
set machine NT hash = session key
 ↓
S4U2self + U2U
 ↓
S4U2proxy
 ↓
Administrator ticket
```

## 11. P-t-T

Used the Administrator ccache with SMB/Kerberos

Flags removed from this sanitised version

DCSync was also possible with the resulting privileges

# What did I learn?

### LDAP
Escape metacharacters with hex values!!

### Credentials
Passwd hint may belong to a different account > spray extracted creds across known user set

### ASP.NET
LFI → `web.config` → `machineKey` → forged Forms Auth cookie > low-priv user > app admin

### GenericWrite
`GenericWrite` over a user > enable shadow creds

### AD ACLs
If group membership can't be changed- check object attributes e.g `distinguishedName` + inherited OU ACLs

### ESC3
Enrollment Agent abuse can allow a user certificate to be requested (on behalf of another acc)

### RBCD
RBCD on a DC is highly privileged > if the controlled account has no SPN, U2U can be used for the SPN-less case

### Kerberos
NTLM disabled, valid ccaches and correct SPNs = essential!

### Ccache
`getTGT.py` > overwrite cache files so save/rename before obtaining another TGT

# Tools

```text
fixhosts.c
krb5.conf
pool_extract.py
enum_desc_users.py
extract_user.py
spray4.sh
web_ken.py
CookieForge/
use_forged.py
mkbadodt2.py
upload2.py
bh_out.py
sd_dump_krb.py
move_ou.py
user_admin.py
ou_acl.py
set_pwd.py
winrm_krb.py
rbcd_ws.sh
find_flags.py
```
Working on making an automated script that includes the tools that were created for this machine, and executes as a singular .py that gets you from start to finish automatically, will upload later when done, but it's not a priority as of now.

## Short

```text
LDAP injection
 ↓
blind extraction
 ↓
passwd spray → ken.w
 ↓
LFI → machineKey → web_admin
 ↓
malicious ODT → Responder → natalie.a
 ↓
Shadow Credentials / ACL abuse → auditor
 ↓
ESC3 → ashley.b
 ↓
IIS_Administrator → IIS_Webserver$
 ↓
SPN-less RBCD
 ↓
Administrator
```
