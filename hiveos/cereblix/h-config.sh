#!/usr/bin/env bash
# Build the miner argument file from the Flight Sheet fields.
# Hive provides: CUSTOM_TEMPLATE (Wallet/%WAL%), CUSTOM_URL (Pool URL),
# CUSTOM_USER_CONFIG (Extra config arguments), CUSTOM_PASS (unused here).
cd "$(dirname "$0")"
. h-manifest.conf

# Wallet template -> -addr. A CRB address is "crb1" + 40 hex chars (no dots),
# so cutting at the first dot safely strips any ".worker" suffix Hive may add.
ADDR=$(echo "$CUSTOM_TEMPLATE" | cut -d. -f1 | tr -d ' ')

# Pool URL -> -node; fall back to the main pool if the field is left empty.
NODE="$CUSTOM_URL"
[[ -z "$NODE" ]] && NODE="https://cereblix.com/pool/api"

# CUSTOM_USER_CONFIG = optional extra flags, e.g. "-threads 6"
echo "-addr $ADDR -node $NODE $CUSTOM_USER_CONFIG" > "$CUSTOM_CONFIG_FILENAME"
