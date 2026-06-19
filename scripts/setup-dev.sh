#!/usr/bin/env bash
# scripts/setup-dev.sh — Bootstrap local development environment.
# Creates the Forgejo admin user and OAuth2 application automatically.
set -euo pipefail

FORGEJO_URL="${FORGEJO_URL:-http://localhost:3030}"
FORGEJO_ADMIN_USER="${FORGEJO_ADMIN_USER:-hibou-admin}"
FORGEJO_ADMIN_PASS="${FORGEJO_ADMIN_PASS:-hibou-admin}"
FORGEJO_ADMIN_EMAIL="${FORGEJO_ADMIN_EMAIL:-admin@localhost}"
HIBOU_CALLBACK_URL="${HIBOU_CALLBACK_URL:-http://localhost:8585/api/v1/auth/callback?provider=forgejo}"
HIBOU_CALLBACK_URL_VITE="${HIBOU_CALLBACK_URL_VITE:-http://localhost:3000/api/v1/auth/callback?provider=forgejo}"
WEBHOOK_SECRET="${WEBHOOK_SECRET:-hibou-webhook-dev-secret}"
WEBHOOK_URL="${WEBHOOK_URL:-http://host.docker.internal:8585/api/v1/webhooks/forgejo}"

# When first startup, Forgejo will return an error page for the API endpoints until the initial setup is complete. During this time, we can detect that it's a fresh instance and trigger the setup flow automatically.
install_forgejo_if_needed() {
  local api_status app_url

  echo "==> Waiting for Forgejo HTTP server..."
  for i in $(seq 1 30); do
    if curl -sSo /dev/null "$FORGEJO_URL/" 2>/dev/null; then
      break
    fi
    sleep 2
  done

  if ! curl -sSo /dev/null "$FORGEJO_URL/" 2>/dev/null; then
    echo "ERROR: Forgejo HTTP server did not become reachable in time"
    exit 1
  fi

  api_status=$(curl -sS -o /dev/null -w "%{http_code}" "$FORGEJO_URL/api/v1/version" 2>/dev/null || true)
  if [ "$api_status" != "404" ]; then
    return
  fi

  echo "==> Forgejo in install mode. Bootstrapping fresh instance..."
  app_url="${FORGEJO_URL%/}/"

  curl -sS -o /dev/null -X POST "$FORGEJO_URL/" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data "db_type=sqlite3" \
    --data "db_path=/data/gitea/gitea.db" \
    --data "app_name=Forgejo" \
    --data "repo_root_path=/data/git/repositories" \
    --data "lfs_root_path=/data/git/lfs" \
    --data "run_user=git" \
    --data "domain=localhost" \
    --data "ssh_port=22" \
    --data "http_port=3000" \
    --data-urlencode "app_url=$app_url" \
    --data "log_root_path=/data/gitea/log" \
    --data "admin_name=$FORGEJO_ADMIN_USER" \
    --data "admin_passwd=$FORGEJO_ADMIN_PASS" \
    --data "admin_confirm_passwd=$FORGEJO_ADMIN_PASS" \
    --data "admin_email=$FORGEJO_ADMIN_EMAIL"

  sleep 5
}

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
        \"redirect_uris\": [\"$HIBOU_CALLBACK_URL\", \"$HIBOU_CALLBACK_URL_VITE\"]
      }")
  fi
}

setup_webhooks() {
  echo "==> Configuring Forgejo webhooks..."

  local repos_json repo_lines
  repos_json=$(curl -sf "$FORGEJO_URL/api/v1/user/repos?limit=100" \
    -H "Authorization: token $ADMIN_TOKEN")
  repo_lines=$(printf '%s' "$repos_json" | python3 -c '
import json
import sys

for repo in json.load(sys.stdin):
    owner = (repo.get("owner") or {}).get("login") or ""
    name = repo.get("name") or ""
    if owner and name:
        print(f"{owner}\t{name}")
')

  if [ -z "$repo_lines" ]; then
    echo "    No repositories found for webhook setup"
    return
  fi

  while IFS=$'\t' read -r owner repo; do
    [ -n "$owner" ] || continue
    [ -n "$repo" ] || continue

    local hooks_json existing_hook
    hooks_json=$(curl -sf "$FORGEJO_URL/api/v1/repos/$owner/$repo/hooks?limit=100" \
      -H "Authorization: token $ADMIN_TOKEN")
    existing_hook=$(printf '%s' "$hooks_json" | TARGET_URL="$WEBHOOK_URL" python3 -c '
import json
import os
import sys

target_url = os.environ["TARGET_URL"]
for hook in json.load(sys.stdin):
    config = hook.get("config") or {}
    if config.get("url") == target_url:
        print("found")
        break
')

    if [ "$existing_hook" = "found" ]; then
      echo "    $owner/$repo: webhook already configured"
      continue
    fi

    curl -sf "$FORGEJO_URL/api/v1/repos/$owner/$repo/hooks" \
      -H "Authorization: token $ADMIN_TOKEN" \
      -H "Content-Type: application/json" \
      -d "{
        \"type\": \"forgejo\",
        \"active\": true,
        \"config\": {
          \"url\": \"$WEBHOOK_URL\",
          \"content_type\": \"json\",
          \"secret\": \"$WEBHOOK_SECRET\"
        },
        \"events\": [\"push\", \"pull_request\", \"create\", \"delete\"]
      }" >/dev/null
    echo "    $owner/$repo: webhook created"
  done <<< "$repo_lines"
}

print_credentials() {
  local client_id client_secret
  client_id=$(echo "$APP_JSON" | python3 -c "import sys,json; print(json.load(sys.stdin)['client_id'])")
  client_secret=$(echo "$APP_JSON" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('client_secret',''))")

  echo ""
  echo "==> Setup complete!"
  echo ""
  echo "Add the following to your .env file:"
  echo ""
  echo "  HIBOU_DEVELOPMENT=true"
  echo "  HIBOU_FORGE_0_TYPE=forgejo"
  echo "  HIBOU_FORGE_0_ID=forgejo"
  echo "  HIBOU_FORGE_0_URL=$FORGEJO_URL"
  echo "  HIBOU_FORGE_0_CLIENT_ID=$client_id"
  if [ -n "$client_secret" ]; then
    echo "  HIBOU_FORGE_0_CLIENT_SECRET=$client_secret"
  else
    echo "  HIBOU_FORGE_0_CLIENT_SECRET=(already set — kept from .env)"
  fi
  echo "  HIBOU_FORGE_0_WEBHOOK_SECRET=$WEBHOOK_SECRET"
  echo ""
  echo "Forgejo admin login: $FORGEJO_URL"
  echo "  Username: $FORGEJO_ADMIN_USER"
  echo "  Password: $FORGEJO_ADMIN_PASS"
  echo "Webhook secret: $WEBHOOK_SECRET"
  echo ""

  if [ -f .env ]; then
    echo "==> Auto-updating .env..."
    grep -q "^HIBOU_DEVELOPMENT=" .env && sed -i "s|^HIBOU_DEVELOPMENT=.*|HIBOU_DEVELOPMENT=true|" .env
    grep -q "^HIBOU_FORGE_0_TYPE=" .env && sed -i "s|^HIBOU_FORGE_0_TYPE=.*|HIBOU_FORGE_0_TYPE=forgejo|" .env
    grep -q "^HIBOU_FORGE_0_ID=" .env && sed -i "s|^HIBOU_FORGE_0_ID=.*|HIBOU_FORGE_0_ID=forgejo|" .env
    grep -q "^HIBOU_FORGE_0_URL=" .env && sed -i "s|^HIBOU_FORGE_0_URL=.*|HIBOU_FORGE_0_URL=$FORGEJO_URL|" .env
    grep -q "^HIBOU_FORGE_0_CLIENT_ID=" .env && sed -i "s|^HIBOU_FORGE_0_CLIENT_ID=.*|HIBOU_FORGE_0_CLIENT_ID=$client_id|" .env
    # Only update client secret if we got a new one (Forgejo doesn't return it for existing apps)
    if [ -n "$client_secret" ] && [ "$client_secret" != "(already created — check .env)" ]; then
      grep -q "^HIBOU_FORGE_0_CLIENT_SECRET=" .env && sed -i "s|^HIBOU_FORGE_0_CLIENT_SECRET=.*|HIBOU_FORGE_0_CLIENT_SECRET=$client_secret|" .env
    fi
    grep -q "^HIBOU_FORGE_0_WEBHOOK_SECRET=" .env && sed -i "s|^HIBOU_FORGE_0_WEBHOOK_SECRET=.*|HIBOU_FORGE_0_WEBHOOK_SECRET=$WEBHOOK_SECRET|" .env
    if ! grep -q "^HIBOU_FORGE_0_WEBHOOK_SECRET=" .env; then
      echo "HIBOU_FORGE_0_WEBHOOK_SECRET=$WEBHOOK_SECRET" >> .env
    fi
    if ! grep -q "^HIBOU_DEVELOPMENT=" .env; then
      echo "HIBOU_DEVELOPMENT=true" >> .env
    fi
    echo "    .env updated."
  fi

  if ! grep -q "^HIBOU_FORGE_0_TYPE=" .env 2>/dev/null; then
    cat >> .env <<FORGE_EOF

# Local Hibou development mode
HIBOU_DEVELOPMENT=true

# Forge: local Forgejo
HIBOU_FORGE_0_TYPE=forgejo
HIBOU_FORGE_0_ID=forgejo
HIBOU_FORGE_0_URL=$FORGEJO_URL
HIBOU_FORGE_0_CLIENT_ID=$client_id
HIBOU_FORGE_0_CLIENT_SECRET=$client_secret
HIBOU_FORGE_0_WEBHOOK_SECRET=$WEBHOOK_SECRET
FORGE_EOF
    echo "    Forge config appended to .env"
  else
    echo "    Forge config already in .env"
  fi
}

cleanup_token() {
  curl -sf "$FORGEJO_URL/api/v1/users/$FORGEJO_ADMIN_USER/tokens/hibou-setup" \
    -u "$FORGEJO_ADMIN_USER:$FORGEJO_ADMIN_PASS" \
    -X DELETE 2>/dev/null || true
}

main() {
  install_forgejo_if_needed
  wait_for_forgejo
  create_admin_user
  generate_admin_token
  create_oauth_app
  setup_webhooks
  print_credentials
  cleanup_token
}

main "$@"
