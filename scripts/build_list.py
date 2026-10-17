#!/usr/bin/env python3
"""Build a consensus-ranked wildcard blocklist sized for a 2MB-PSRAM ESP32_AdBlocker.

Usage: build_list.py <lists_dir> <out_file> <max_domains>

Entries are treated as wildcards (entry blocks itself + all subdomains), which
matches the patched firmware's parent-domain lookup.
"""
import csv, re, sys, os
from collections import defaultdict

LISTS, OUT, MAXN = sys.argv[1], sys.argv[2], int(sys.argv[3])

# wildcard-semantics sources and their vote weight
WILDCARD = {
    "hz_pro.txt": 1, "hz_multi.txt": 1, "hz_light.txt": 1,
    "hz_pro.mini.txt": 2,   # Hagezi's most-queried subset: strong signal
    "oisd_big.txt": 1, "adguard_dns.txt": 1,
}
# exact-name sources: vote for any pool domain they list (or list a subdomain of)
EXACT = {"stevenblack.txt": 1, "1hosts_lite.txt": 1, "easyprivacy.txt": 1, "pgl_yoyo.txt": 1}
# modern device/OS telemetry lists: always included
NATIVE_PREFIX = "hz_native."

# never block these exact parents (subdomains like ads.youtube.com stay allowed to be listed)
PROTECT = {
    "google.com", "googleapis.com", "gstatic.com", "googlevideo.com", "youtube.com", "ytimg.com",
    "googleusercontent.com", "gmail.com", "android.com", "apple.com", "icloud.com", "mzstatic.com",
    "microsoft.com", "windows.com", "windowsupdate.com", "live.com", "office.com", "office.net",
    "microsoftonline.com", "msftconnecttest.com", "amazonaws.com", "amazon.com", "cloudfront.net",
    "akamai.net", "akamaihd.net", "akamaized.net", "akamaiedge.net", "edgekey.net", "fastly.net",
    "cloudflare.com", "cloudflare.net", "github.com", "githubusercontent.com", "facebook.com",
    "fbcdn.net", "instagram.com", "whatsapp.net", "whatsapp.com", "netflix.com", "nflxvideo.net",
    "spotify.com", "t-mobile.com", "tmobile.com", "samsung.com", "xiaomi.com", "roku.com",
    "tiktok.com", "tiktokcdn.com", "reddit.com", "twitter.com", "x.com", "twimg.com",
    "wikipedia.org", "duckduckgo.com", "bing.com", "yahoo.com", "linkedin.com", "zoom.us",
    "discord.com", "discordapp.com", "steamcontent.com", "steampowered.com", "playstation.net",
    "xboxlive.com", "nintendo.net", "jsdelivr.net", "unpkg.com", "cdnjs.cloudflare.com",
}

DOM = re.compile(r"^(?=.{4,100}$)[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?)+$")

def norm(d):
    d = d.strip().lower().rstrip(".")
    if d.startswith("*."): d = d[2:]
    if d.startswith("www."): d = d[4:]
    return d if DOM.match(d) and not d.replace(".", "").isdigit() else None

def parse(path):
    out = set()
    with open(path, encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.split("#", 1)[0].strip()
            if not line or line[0] in "!@[":
                continue
            if line.startswith("||"):
                m = re.match(r"^\|\|([^\^/$]+)\^$", line)   # plain domain rules only
                if not m: continue
                line = m.group(1)
            else:
                parts = line.split()
                if len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1", "::", "::1"):
                    line = parts[1]
                elif len(parts) != 1:
                    continue
            d = norm(line)
            if d and d not in ("localhost", "localhost.localdomain", "local", "broadcasthost", "0.0.0.0"):
                out.add(d)
    return out

def parents(d):
    p = d.split(".")
    return [".".join(p[i:]) for i in range(1, len(p) - 1)]   # keep >= 2 labels

score = defaultdict(int)
native = set()
for fn in sorted(os.listdir(LISTS)):
    path = os.path.join(LISTS, fn)
    if fn in WILDCARD:
        for d in parse(path): score[d] += WILDCARD[fn]
    elif fn.startswith(NATIVE_PREFIX):
        native |= parse(path)
for d in native: score[d] += 1

# exact sources vote for pool domains they cover (domain itself or a subdomain)
for fn, w in EXACT.items():
    voted = set()
    for d in parse(os.path.join(LISTS, fn)):
        for c in [d] + parents(d):
            if c in score and c not in voted:
                score[c] += w; voted.add(c)

# drop protected exact parents
for d in PROTECT: score.pop(d, None); native.discard(d)

# collapse: a child is redundant if any parent is in the pool; fold its score up
pool = set(score)
for d in list(pool):
    for p in parents(d):
        if p in pool:
            score[p] = max(score[p], score[d]); pool.discard(d); native.discard(d)
            break

# popularity tiebreak from Tranco (rank of the domain or its nearest ranked parent)
rank = {}
with open(os.path.join(LISTS, "top-1m.csv")) as f:
    for r, dom in csv.reader(f): rank[dom] = int(r)
def pop(d):
    for c in [d] + parents(d):
        if c in rank: return rank[c]
    return 10**7

must = sorted(native & pool)
rest = sorted(pool - set(must), key=lambda d: (-score[d], pop(d), len(d), d))
rest = [d for d in rest if score[d] >= 2]              # require some consensus
chosen = must + rest[: max(0, MAXN - len(must))]

with open(OUT, "w") as f:
    f.write("# ESP32_AdBlocker consensus wildcard list (entries also block their subdomains)\n")
    f.write(f"# {len(chosen)} domains: {len(must)} device-telemetry + top consensus ad/tracker domains\n")
    f.write("# Sources: HaGeZi (pro, pro.mini, multi, light, native.*), OISD big, AdGuard DNS,\n")
    f.write("#          StevenBlack, 1Hosts Lite, EasyPrivacy, Peter Lowe. Ranked by agreement + Tranco.\n")
    for d in sorted(chosen): f.write(d + "\n")

sizes = [len(d) + 1 for d in chosen]
print(f"pool after collapse: {len(pool)}  native: {len(must)}  consensus>=2: {len(rest)}")
print(f"chosen: {len(chosen)}  storage bytes: {sum(sizes)}  avg len: {sum(sizes)/len(sizes):.1f}")
print("min score in chosen:", min(score[d] for d in chosen[len(must):]) if len(chosen) > len(must) else "-")
