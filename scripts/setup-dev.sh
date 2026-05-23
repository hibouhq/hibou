#!/usr/bin/env bash
# scripts/setup-dev.sh — Bootstrap local development environment.
# Creates the Forgejo admin user and OAuth2 application automatically.
set -euo pipefail

FORGEJO_URL="${FORGEJO_URL:-http://localhost:3000}"
FORGEJO_ADMIN_USER="${FORGEJO_ADMIN_USER:-hibou-admin}"
FORGEJO_ADMIN_PASS="${FORGEJO_ADMIN_PASS:-hibou-admin}"
FORGEJO_ADMIN_EMAIL="${FORGEJO_ADMIN_EMAIL:-admin@localhost}"
HIBOU_CALLBACK_URL="${HIBOU_CALLBACK_URL:-http://localhost:8080/api/v1/auth/callback?provider=forgejo}"

echo "==> Waiting for Forgejo to be ready..."
for i in $(seq 1 30); do
  if curl -fsSo /dev/null "$FORGEJO_URL/api/v1/version" 2>/dev/null; then
    break
  fi
  if [ "$i" -eq 30 ]; then
    echo "ERROR: Forgejo did not become ready in time"
    exit 1
  fi
  sleep 2
done
echo "    Forgejo is ready at $FORGEJO_URL"

# Create admin user (idempotent — ignore if already exists)
echo "==> Creating Forgejo admin user '$FORGEJO_ADMIN_USER'..."
docker compose exec -T forgejo forgejo admin user create \
  --admin \
  --username "$FORGEJO_ADMIN_USER" \
  --password "$FORGEJO_ADMIN_PASS" \
  --email "$FORGEJO_ADMIN_EMAIL" \
  --must-change-password=false 2>/dev/null || echo "    (user already exists)"

# Generate API token for admin operations
echo "==> Generating admin API token..."
TOKEN_RESPONSE=$(curl -sf "$FORGEJO_URL/api/v1/users/$FORGEJO_ADMIN_USER/tokens" \
  -u "$FORGEJO_ADMIN_USER:$FORGEJO_ADMIN_PASS" \
  -H "Content-Type: application/json" \
  -d '{"name":"hibou-setup","scopes":["all"]}' 2>/dev/null || true)

if [ -z "$TOKEN_RESPONSE" ]; then
  # Token might already exist — delete and recreate
  curl -sf "$FORGEJO_URL/api/v1/users/$FORGEJO_ADMIN_USER/tokens/hibou-setup" \
    -u "$FORGEJO_ADMIN_USER:$FORGEJO_ADMIN_PASS" \
    -X DELETE 2>/dev/null || true
  TOKEN_RESPONSE=$(curl -sf "$FORGEJO_URL/api/v1/users/$FORGEJO_ADMIN_USER/tokens" \
    -u "$FORGEJO_ADMIN_USER:$FORGEJO_ADMIN_PASS" \
    -H "Content-Type: application/json" \
    -d '{"name":"hibou-setup","scopes":["all"]}')
fi

ADMIN_TOKEN=$(echo "$TOKEN_RESPONSE" | grep -o '"sha1":"[^"]*"' | cut -d'"' -f4)
if [ -z "$ADMIN_TOKEN" ]; then
  echo "ERROR: Failed to get admin token"
  exit 1
fi

# Create OAuth2 application (idempotent — check first)
echo "==> Creating OAuth2 application 'hibou'..."
EXISTING_APP=$(curl -sf "$FORGEJO_URL/api/v1/user/applications/oauth2" \
  -H "Authorization: token $ADMIN_TOKEN" | grep -o '"name":"hibou"' || true)

if [ -n "$EXISTING_APP" ]; then
  echo "    OAuth2 app 'hibou' already exists, fetching credentials..."
  APP_JSON=$(curl -sf "$FORGEJO_URL/api/v1/user/applications/oauth2" \
    -H "Authorization: token $ADMIN_TOKEN" | python3 -c "
import sys, json
apps = json.load(sys.stdin)
for app in apps:
    if app['name'] == 'hibou':
        print(json.dumps(app))
        break
")
else
  APP_JSON=$(curl -sf "$FORGEJO_URL/api/v1/user/applications/oauth2" \
    -H "Authorization: token $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{
      \"name\": \"hibou\",
      \"confidential_client\": true,
      \"redirect_uris\": [\"$HIBOU_CALLBACK_URL\"]
    }")
fi

CLIENT_ID=$(echo "$APP_JSON" | python3 -c "import sys,json; print(json.load(sys.stdin)['client_id'])")
CLIENT_SECRET=$(echo "$APP_JSON" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('client_secret','(already created — check .env)'))")

echo ""
echo "==> Setup complete!"
echo ""
echo "Add the following to your .env file:"
echo ""
echo "  HIBOU_FORGE_0_TYPE=forgejo"
echo "  HIBOU_FORGE_0_ID=forgejo"
echo "  HIBOU_FORGE_0_URL=$FORGEJO_URL"
echo "  HIBOU_FORGE_0_CLIENT_ID=$CLIENT_ID"
echo "  HIBOU_FORGE_0_CLIENT_SECRET=$CLIENT_SECRET"
echo ""
echo "Forgejo admin login: $FORGEJO_URL"
echo "  Username: $FORGEJO_ADMIN_USER"
echo "  Password: $FORGEJO_ADMIN_PASS"
echo ""

# Auto-update .env if it exists
if [ -f .env ]; then
  echo "==> Auto-updating .env..."
  sed -i "s|^HIBOU_FORGE_0_CLIENT_ID=.*|HIBOU_FORGE_0_CLIENT_ID=$CLIENT_ID|" .env
  sed -i "s|^HIBOU_FORGE_0_CLIENT_SECRET=.*|HIBOU_FORGE_0_CLIENT_SECRET=$CLIENT_SECRET|" .env
  echo "    .env updated."
fi

# Clean up the admin token
curl -sf "$FORGEJO_URL/api/v1/users/$FORGEJO_ADMIN_USER/tokens/hibou-setup" \
  -u "$FORGEJO_ADMIN_USER:$FORGEJO_ADMIN_PASS" \
  -X DELETE 2>/dev/null || true
