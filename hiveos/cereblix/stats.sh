#!/usr/bin/env bash
# Report hashrate + accepted shares to the Hive OS dashboard. Hive SOURCES this
# script and reads the `khs` (kH/s) and `stats` (JSON) variables it sets, so we
# locate ourselves via BASH_SOURCE (not $0). The miner logs every ~15s a line like:
#   2026/06/13 20:45:01 hashrate: 1234.5 H/s | block 3510 (epoch 0) | shares 42 · blocks 0
# No jq dependency: the values are numeric, so the JSON is built directly.
SD="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[[ -f "$SD/h-manifest.conf" ]] && . "$SD/h-manifest.conf"

log="${CUSTOM_LOG_BASENAME}.log"
hs=0
acc=0

if [[ -f "$log" ]]; then
  line=$(grep -E 'hashrate:' "$log" | tail -n1)
  v=$(echo "$line" | sed -nE 's/.*hashrate: ([0-9.]+) H\/s.*/\1/p')
  a=$(echo "$line" | sed -nE 's/.*shares ([0-9]+).*/\1/p')
  [[ -n "$v" ]] && hs=$v
  [[ -n "$a" ]] && acc=$a
fi

# khs is always kilohashes/sec for Hive's internal totals.
khs=$(awk "BEGIN{printf \"%.6f\", $hs/1000}")
stats="{\"hs\":[$hs],\"hs_units\":\"hs\",\"temp\":[0],\"fan\":[0],\"uptime\":0,\"ar\":[$acc,0],\"algo\":\"neuromorph\",\"bus_numbers\":[0]}"
