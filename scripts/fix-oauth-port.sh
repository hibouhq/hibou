#!/usr/bin/env bash
# scripts/fix-oauth-port.sh — Update Forgejo OAuth redirect URI for VS Code port forwarding.
# Usage: ./scripts/fix-oauth-port.sh 51953
#   or:  make fix-auth PORT=51953
set -euo pipefail

PORT="${1:-${PORT:-}}"
if [ -z "$PORT" ]; then
  echo "Usage: $0 <VS_CODE_FORWARDED_PORT>"
  echo "  Check the VS Code PORTS panel for the forwarded port of 3000 (Vite Dev Server)."
  exit 1
fi

FORGEJO_URL="${FORGEJO_URL:-http://localhost:3030}"
FORGEJO_ADMIN_USER="${FORGEJO_ADMIN_USER:-hibou-admin}"
FORGEJO_ADMIN_PASS="${FORGEJO_ADMIN_PASS:-hibou-admin}"

REDIRECT_URIS="[
  \"http://localhost:8080/api/v1/auth/callback?provider=forgejo\",
  \"http://localhost:3000/api/v1/auth/callback?provider=forgejo\",
  \"http://localhost:${PORT}/api/v1/auth/callback?provider=forgejo\"
]"

# Find the OAuth app ID
APP_ID=$(curl -sf "$FORGEJO_URL/api/v1/user/applications/oauth2" \
  -u "$FORGEJO_ADMIN_USER:$FORGEJO_ADMIN_PASS" | \
  python3 -c "import sys,json; apps=json.load(sys.stdin); print(next(a['id'] for a in apps if a['name']=='hibou'))")

if [ -z "$APP_ID" ]; then
  echo "ERROR: OAuth app 'hibou' not found in Forgejo"
  exit 1
fi

curl -sf -X PATCH "$FORGEJO_URL/api/v1/user/applications/oauth2/$APP_ID" \
  -u "$FORGEJO_ADMIN_USER:$FORGEJO_ADMIN_PASS" \
  -H "Content-Type: application/json" \
  -d "{
    \"name\": \"hibou\",
    \"confidential_client\": true,
    \"redirect_uris\": $REDIRECT_URIS
  }" > /dev/null

echo "✓ Updated Forgejo OAuth redirect URIs to include port $PORT"
