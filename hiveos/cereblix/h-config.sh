#!/usr/bin/env bash
# Build the miner argument file from the Flight Sheet fields.
# Hive SOURCES this script, so we locate ourselves via BASH_SOURCE (not $0, which
# points at Hive's caller when sourced). Hive provides: CUSTOM_TEMPLATE (Wallet),
# CUSTOM_URL (Pool URL), CUSTOM_USER_CONFIG (Extra config arguments).
HCDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[[ -f "$HCDIR/h-manifest.conf" ]] && . "$HCDIR/h-manifest.conf"

# Wallet template -> -addr. A CRB address is "crb1" + 40 hex chars (no dots), so
# cutting at the first dot safely strips any ".worker" suffix Hive may append.
ADDR=$(echo "$CUSTOM_TEMPLATE" | cut -d. -f1 | tr -d ' ')

# Pool URL -> -node; fall back to the main pool if the field is empty.
NODE="$CUSTOM_URL"
[[ -z "$NODE" ]] && NODE="https://cereblix.com/pool/api"

# CUSTOM_USER_CONFIG = optional extra flags, e.g. "-threads 6"
echo "-addr $ADDR -node $NODE $CUSTOM_USER_CONFIG" > "$HCDIR/${CUSTOM_CONFIG_FILENAME:-cereblix.conf}"
