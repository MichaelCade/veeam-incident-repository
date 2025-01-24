#!/bin/bash

# Function to securely read input
read_secure_input() {
  local prompt="$1"
  read -s -p "$prompt" input
  echo "$input"
}

# Prompt for credentials or use environment variables
URL="${VEEAM_API_URL:-https://192.168.169.185:9419/api/oauth2/token}"
USERNAME="${VEEAM_API_USERNAME:-}"
PASSWORD="${VEEAM_API_PASSWORD:-}"

if [ -z "$USERNAME" ]; then
  read -p "Enter username: " USERNAME
fi

if [ -z "$PASSWORD" ]; then
  PASSWORD=$(read_secure_input "Enter password: ")
  echo
fi

# Obtain token
BODY=$(jq -n \
  --arg grant_type "password" \
  --arg username "$USERNAME" \
  --arg password "$PASSWORD" \
  '{grant_type: $grant_type, username: $username, password: $password}')

HEADERS=(
  -H "Content-Type: application/json"
  -H "x-api-version: 1.1-rev1"
)

echo "Obtaining access token..."
RESPONSE=$(curl -s -k -X POST "$URL" -d "$BODY" "${HEADERS[@]}")
TOKEN=$(echo "$RESPONSE" | jq -r .access_token)

if [ -z "$TOKEN" ] || [ "$TOKEN" == "null" ]; then
  echo "Failed to obtain access token. Check credentials and URL."
  exit 1
fi

# Prepare headers with token
AUTH_HEADERS=(
  -H "Content-Type: application/json"
  -H "x-api-version: 1.1-rev1"
  -H "Authorization: Bearer $TOKEN"
)

# Define event data
DETECTION_TIME="$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)"
FQDN="DevOps-MGMT01"
UUID="423738ed-997d-80d4-328f-f4fd78c887a4"
DETAILS="Event-Driven Backup Demo"
SEVERITY="Infected"
ENGINE="Event-Driven"

EVENT_BODY=$(jq -n \
  --arg detectionTimeUtc "$DETECTION_TIME" \
  --arg fqdn "$FQDN" \
  --arg uuid "$UUID" \
  --arg details "$DETAILS" \
  --arg severity "$SEVERITY" \
  --arg engine "$ENGINE" \
  '{
    detectionTimeUtc: $detectionTimeUtc,
    machine: {fqdn: $fqdn, uuid: $uuid},
    details: $details,
    severity: $severity,
    engine: $engine
  }')

# Trigger event
EVENT_URL="https://192.168.169.185:9419/api/v1/malwareDetection/events"
echo "Triggering event..."
EVENT_RESPONSE=$(curl -s -k -X POST "$EVENT_URL" -d "$EVENT_BODY" "${AUTH_HEADERS[@]}")

if echo "$EVENT_RESPONSE" | jq . >/dev/null 2>&1; then
  echo "Event triggered successfully:"
  echo "$EVENT_RESPONSE" | jq
else
  echo "Failed to trigger event. Response: $EVENT_RESPONSE"
fi
