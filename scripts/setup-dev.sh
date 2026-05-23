#!/usr/bin/env bash
# scripts/setup-dev.sh — Bootstrap local development environment.
# Creates the Forgejo admin user and OAuth2 application automatically.
set -euo pipefail

FORGEJO_URL="${FORGEJO_URL:-http://localhost:3030}"
FORGEJO_ADMIN_USER="${FORGEJO_ADMIN_USER:-hibou-admin}"
FORGEJO_ADMIN_PASS="${FORGEJO_ADMIN_PASS:-hibou-admin}"
FORGEJO_ADMIN_EMAIL="${FORGEJO_ADMIN_EMAIL:-admin@localhost}"
HIBOU_CALLBACK_URL="${HIBOU_CALLBACK_URL:-http://localhost:8080/api/v1/auth/callback?provider=forgejo}"

wait_for_forgejo() {
  echo "==> Waiting for Forgejo to be ready..."
  for i in $(seq 1 30); do
    if curl -fsSo /dev/null "$FORGEJO_URL/api/v1/version" 2>/dev/null; then
      echo "    Forgejo is ready at $FORGEJO_URL"
      return
    fi
    sleep 2
  done
  echo "ERROR: Forgejo did not become ready in time"
  exit 1
}

create_admin_user() {
  echo "==> Creating Forgejo admin user '$FORGEJO_ADMIN_USER'..."
  docker compose exec -T -u git forgejo forgejo admin user create \
    --admin \
    --username "$FORGEJO_ADMIN_USER" \
    --password "$FORGEJO_ADMIN_PASS" \
    --email "$FORGEJO_ADMIN_EMAIL" \
    --must-change-password=false 2>/dev/null || echo "    (user already exists)"
}

generate_admin_token() {
  echo "==> Generating admin API token..."
  local token_response
  token_response=$(curl -sf "$FORGEJO_URL/api/v1/users/$FORGEJO_ADMIN_USER/tokens" \
    -u "$FORGEJO_ADMIN_USER:$FORGEJO_ADMIN_PASS" \
    -H "Content-Type: application/json" \
    -d '{"name":"hibou-setup","scopes":["all"]}' 2>/dev/null || true)

  if [ -z "$token_response" ]; then
    curl -sf "$FORGEJO_URL/api/v1/users/$FORGEJO_ADMIN_USER/tokens/hibou-setup" \
      -u "$FORGEJO_ADMIN_USER:$FORGEJO_ADMIN_PASS" \
      -X DELETE 2>/dev/null || true
    token_response=$(curl -sf "$FORGEJO_URL/api/v1/users/$FORGEJO_ADMIN_USER/tokens" \
      -u "$FORGEJO_ADMIN_USER:$FORGEJO_ADMIN_PASS" \
      -H "Content-Type: application/json" \
      -d '{"name":"hibou-setup","scopes":["all"]}')
  fi

  ADMIN_TOKEN=$(echo "$token_response" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('token', d.get('sha1', '')))")
  if [ -z "$ADMIN_TOKEN" ]; then
    echo "ERROR: Failed to get admin token"
    exit 1
  fi
}

create_oauth_app() {
  echo "==> Creating OAuth2 application 'hibou'..."
  local existing_app
  existing_app=$(curl -sf "$FORGEJO_URL/api/v1/user/applications/oauth2" \
    -H "Authorization: token $ADMIN_TOKEN" | grep -o '"name":"hibou"' || true)

  if [ -n "$existing_app" ]; then
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
}

print_credentials() {
  local client_id client_secret
  client_id=$(echo "$APP_JSON" | python3 -c "import sys,json; print(json.load(sys.stdin)['client_id'])")
  client_secret=$(echo "$APP_JSON" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('client_secret','(already created — check .env)'))")

  echo ""
  echo "==> Setup complete!"
  echo ""
  echo "Add the following to your .env file:"
  echo ""
  echo "  HIBOU_FORGE_0_TYPE=forgejo"
  echo "  HIBOU_FORGE_0_ID=forgejo"
  echo "  HIBOU_FORGE_0_URL=$FORGEJO_URL"
  echo "  HIBOU_FORGE_0_CLIENT_ID=$client_id"
  echo "  HIBOU_FORGE_0_CLIENT_SECRET=$client_secret"
  echo ""
  echo "Forgejo admin login: $FORGEJO_URL"
  echo "  Username: $FORGEJO_ADMIN_USER"
  echo "  Password: $FORGEJO_ADMIN_PASS"
  echo ""

  if [ -f .env ]; then
    echo "==> Auto-updating .env..."
    sed -i "s|^HIBOU_FORGE_0_CLIENT_ID=.*|HIBOU_FORGE_0_CLIENT_ID=$client_id|" .env
    sed -i "s|^HIBOU_FORGE_0_CLIENT_SECRET=.*|HIBOU_FORGE_0_CLIENT_SECRET=$client_secret|" .env
    echo "    .env updated."
  fi
}

cleanup_token() {
  curl -sf "$FORGEJO_URL/api/v1/users/$FORGEJO_ADMIN_USER/tokens/hibou-setup" \
    -u "$FORGEJO_ADMIN_USER:$FORGEJO_ADMIN_PASS" \
    -X DELETE 2>/dev/null || true
}

main() {
  wait_for_forgejo
  create_admin_user
  generate_admin_token
  create_oauth_app
  print_credentials
  cleanup_token
}

main "$@"
