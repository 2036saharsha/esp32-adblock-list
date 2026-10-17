#!/usr/bin/env bash
# Download all source lists into $1 (default: lists/)
set -euo pipefail
D=${1:-lists}; mkdir -p "$D"; cd "$D"
dl() { curl -fsSL --retry 3 --max-time 180 -o "$1" "$2"; }
H=https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard
for f in pro pro.mini multi light native.amazon native.apple native.huawei native.lgwebos \
         native.oppo-realme native.roku native.samsung native.tiktok native.vivo native.winoffice native.xiaomi; do
  dl "hz_$f.txt" "$H/$f-onlydomains.txt"
done
dl stevenblack.txt https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
dl adguard_dns.txt https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt
dl oisd_big.txt https://big.oisd.nl/domainswild2
dl 1hosts_lite.txt https://raw.githubusercontent.com/badmojr/1Hosts/master/Lite/domains.txt
dl pgl_yoyo.txt 'https://pgl.yoyo.org/adservers/serverlist.php?hostformat=nohtml&showintro=0&mimetype=plaintext'
dl easyprivacy.txt https://v.firebog.net/hosts/Easyprivacy.txt
dl tranco.zip https://tranco-list.eu/top-1m.csv.zip && unzip -o -q tranco.zip && rm tranco.zip
