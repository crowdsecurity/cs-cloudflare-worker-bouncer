#!/usr/bin/env bash
set -euo pipefail

# Fetch all items from Cloudflare IP lists that start with "crowdsec_"
# and save them to a CSV 'currentListMap.csv' file with columns: IP, item ID, list ID.

# copy and chmod +x before running
# Usage: ACCOUNT_ID=<your_account_id> CLOUDFLARE_API_TOKEN=<your_api_token> ./getListsItems.sh

OUTPUT="currentListMap.csv"
BASE_URL="https://api.cloudflare.com/client/v4/accounts/$ACCOUNT_ID/rules/lists"

> "$OUTPUT"

# Get all crowdsec_* lists
LISTS=$(curl -sS \
  "$BASE_URL" \
  -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN")

echo "$LISTS" \
  | jq -r '.result[] | select(.name | startswith("crowdsec_")) | [.id, .name] | @tsv' \
  | while IFS=$'\t' read -r LIST_ID LIST_NAME; do

    echo "Fetching $LIST_NAME ($LIST_ID)..." >&2

    CURSOR=""

    while true; do

      URL="$BASE_URL/$LIST_ID/items?per_page=500"

      if [[ -n "$CURSOR" ]]; then
        URL="${URL}&cursor=$(printf '%s' "$CURSOR" | jq -sRr @uri)"
      fi

      RESPONSE=$(curl -sS \
        "$URL" \
        -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN")

      # Check Cloudflare API response
      SUCCESS=$(echo "$RESPONSE" | jq -r '.success')

      if [[ "$SUCCESS" != "true" ]]; then
        echo "Error fetching $LIST_NAME:" >&2
        echo "$RESPONSE" | jq '.errors' >&2
        exit 1
      fi

      # Write IP,itemId,listId
      echo "$RESPONSE" \
        | jq -r --arg listId "$LIST_ID" \
          '.result[] | "\(.ip),\(.id),\($listId)"' \
        >> "$OUTPUT"

      # Get next cursor
      CURSOR=$(echo "$RESPONSE" \
        | jq -r '.result_info.cursors.after // empty')

      # No cursor = finished
      if [[ -z "$CURSOR" ]]; then
        break
      fi

    done

done

echo "Done: $OUTPUT" >&2
echo "$(wc -l < "$OUTPUT") items retrieved." >&2