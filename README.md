# esp32-adblock-list

A consensus-ranked DNS blocklist sized for [ESP32_AdBlocker](https://github.com/s60sc/ESP32_AdBlocker) on boards with only 2MB PSRAM (~75,000 entries).

**Blocklist URL:** `https://raw.githubusercontent.com/2036saharsha/esp32-adblock-list/main/blocklist.txt`

## How it's built

1. Pulls HaGeZi (pro, pro.mini, multi, light and the native device-telemetry lists), OISD big, AdGuard DNS filter, StevenBlack, 1Hosts Lite, EasyPrivacy and Peter Lowe's list.
2. Treats entries as wildcards and collapses subdomains under listed parents.
3. Scores each domain by how many lists agree (HaGeZi pro.mini counts double), breaking ties by Tranco popularity.
4. Always includes the native telemetry lists (Samsung, Xiaomi, Amazon, Roku, LG, TikTok, Windows, Apple, …), then fills up with the highest-consensus domains. Every included domain is backed by several sources.
5. A protect-list keeps essential parents (google.com, apple.com, amazonaws.com, …) from ever being listed outright.

A GitHub Action rebuilds the list daily at 02:30 UTC.

**Wildcard semantics:** each entry is meant to block itself *and all subdomains*. Stock ESP32_AdBlocker only blocks exact names, so it needs the parent-domain lookup patch (`isBlockedWild` in `appSpecific.cpp`) for full effect.
