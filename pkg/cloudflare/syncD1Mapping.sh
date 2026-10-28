#!/usr/bin/env bash
set -euo pipefail

# Synchronize the current list mapping from 'currentListMap.csv' into the D1 database.
# by batch of 500 (or the value of BATCH_SIZE)

# Make sure to copy and chmod +x before running.
# Usage: ACCOUNT_ID=<your_account_id> DATABASE_ID=<your_database_id> CLOUDFLARE_API_TOKEN=<your_api_token> ./syncD1Mapping.sh


INPUT="currentListMap.csv"
BATCH_SIZE=500

if [[ ! -f "$INPUT" ]]; then
    echo "Error: $INPUT not found" >&2
    exit 1
fi

if [[ -z "${ACCOUNT_ID:-}" ]]; then
    echo "Error: ACCOUNT_ID is not set" >&2
    exit 1
fi

if [[ -z "${DATABASE_ID:-}" ]]; then
    echo "Error: DATABASE_ID is not set" >&2
    exit 1
fi

if [[ -z "${CLOUDFLARE_API_TOKEN:-}" ]]; then
    echo "Error: CLOUDFLARE_API_TOKEN is not set" >&2
    exit 1
fi

TOTAL=$(wc -l < "$INPUT")

echo "Importing $TOTAL IPs into D1..." >&2

awk -F',' -v batch_size="$BATCH_SIZE" '
function start_insert() {
    sql = "INSERT OR IGNORE INTO ip_list_state (ip, action, until, list_action, list_id, item_id) VALUES "
}

function flush() {
    if (count > 0) {
        print sql ";"
        count = 0
    }
}

{
    if (count == 0)
        start_insert()

    if (count > 0)
        sql = sql ","

    # CSV format: ip,item_id,list_id
    sql = sql "('\''" $1 "'\'','\''ban'\'',NULL,'\''listed'\'','\''" $3 "'\'','\''" $2 "'\'')"

    count++

    if (count >= batch_size)
        flush()
}

END {
    flush()
}
' "$INPUT" |
while IFS= read -r SQL; do

    echo "Importing batch..." >&2

    RESPONSE=$(
        jq -n --arg sql "$SQL" '{sql: $sql}' |
        curl -sS \
            "https://api.cloudflare.com/client/v4/accounts/$ACCOUNT_ID/d1/database/$DATABASE_ID/query" \
            -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
            -H "Content-Type: application/json" \
            --data-binary @-
    )

    SUCCESS=$(echo "$RESPONSE" | jq -r '.success')

    if [[ "$SUCCESS" != "true" ]]; then
        echo "D1 import failed:" >&2
        echo "$RESPONSE" | jq >&2
        exit 1
    fi

    CHANGES=$(echo "$RESPONSE" | jq -r '.result[0].meta.changes // 0')

    echo "  → $CHANGES rows inserted" >&2

done

echo "Import complete." >&2