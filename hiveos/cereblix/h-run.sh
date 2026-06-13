#!/usr/bin/env bash
# Launch the Cereblix CPU miner. Hive runs this inside a screen session; we tee
# output to the log so stats.sh can report hashrate/shares to the dashboard.
# BASH_SOURCE (not $0) locates us correctly however Hive invokes the script.
cd "$(dirname "${BASH_SOURCE[0]}")"
. h-manifest.conf

mkdir -p "$(dirname "$CUSTOM_LOG_BASENAME")"
chmod +x cereblix-miner 2>/dev/null

ARGS=$(cat "$CUSTOM_CONFIG_FILENAME" 2>/dev/null)
echo "starting: ./cereblix-miner $ARGS"
# truncating tee (no --append): each (re)start gives stats.sh a fresh log
./cereblix-miner $ARGS 2>&1 | tee "${CUSTOM_LOG_BASENAME}.log"
