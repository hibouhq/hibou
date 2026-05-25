#!/usr/bin/env bash
set -euo pipefail

FORGEJO_URL="${FORGEJO_URL:-http://localhost:3030}"
HIBOU_URL="${HIBOU_URL:-http://localhost:8080}"
FORGEJO_ADMIN_USER="${FORGEJO_ADMIN_USER:-hibou-admin}"
FORGEJO_ADMIN_PASS="${FORGEJO_ADMIN_PASS:-hibou-admin}"
FORGEJO_OWNER="${FORGEJO_OWNER:-$FORGEJO_ADMIN_USER}"
TMPDIR_BASE="$(mktemp -d)"
WEBHOOK_SECRET="${WEBHOOK_SECRET:-hibou-webhook-dev-secret}"
WEBHOOK_URL="${WEBHOOK_URL:-http://host.docker.internal:8080/api/v1/webhooks/forgejo}"

FORGEJO_TOKEN=""
API_KEY=""
API_KEY_ID=""
HIBOU_PID=""
COOKIE_JAR="$TMPDIR_BASE/cookies.txt"
SKIP_UPLOADS=""
K9S_RELEASES=("v0.50.14" "v0.50.15" "v0.50.16" "v0.50.17" "v0.50.18")

cleanup() {
  local exit_code=$?

  if [[ -n "$API_KEY_ID" ]] && [[ -n "$HIBOU_PID" ]] && kill -0 "$HIBOU_PID" 2>/dev/null; then
    curl -sf -b "$COOKIE_JAR" \
      -X DELETE "$HIBOU_URL/api/v1/users/me/api-keys/$API_KEY_ID" >/dev/null 2>&1 || true
  fi

  if [[ -n "$HIBOU_PID" ]]; then
    kill "$HIBOU_PID" 2>/dev/null || true
    wait "$HIBOU_PID" 2>/dev/null || true
  fi

  if [[ -n "$FORGEJO_TOKEN" ]]; then
    curl -sf "$FORGEJO_URL/api/v1/users/$FORGEJO_ADMIN_USER/tokens/seed-real" \
      -u "$FORGEJO_ADMIN_USER:$FORGEJO_ADMIN_PASS" \
      -X DELETE >/dev/null 2>&1 || true
  fi

  rm -rf "$TMPDIR_BASE"
  exit "$exit_code"
}

trap cleanup EXIT

wait_for_forgejo() {
  echo "==> Waiting for Forgejo to be ready..."
  for _ in $(seq 1 30); do
    if curl -fsSo /dev/null "$FORGEJO_URL/api/v1/version" 2>/dev/null; then
      echo "    Forgejo is ready at $FORGEJO_URL"
      return
    fi
    sleep 2
  done

  echo "ERROR: Forgejo did not become ready in time" >&2
  exit 1
}

wait_for_hibou() {
  echo "==> Waiting for Hibou to be ready..."
  for _ in $(seq 1 30); do
    if curl -fsSo /dev/null "$HIBOU_URL/api/v1/health" 2>/dev/null; then
      echo "    Hibou is ready at $HIBOU_URL"
      return
    fi
    sleep 2
  done

  echo "ERROR: Hibou did not become ready in time" >&2
  exit 1
}

generate_admin_token() {
  echo "==> Generating Forgejo admin token..."

  curl -sf "$FORGEJO_URL/api/v1/users/$FORGEJO_ADMIN_USER/tokens/seed-real" \
    -u "$FORGEJO_ADMIN_USER:$FORGEJO_ADMIN_PASS" \
    -X DELETE >/dev/null 2>&1 || true

  local token_response
  token_response=$(curl -sf "$FORGEJO_URL/api/v1/users/$FORGEJO_ADMIN_USER/tokens" \
    -u "$FORGEJO_ADMIN_USER:$FORGEJO_ADMIN_PASS" \
    -H "Content-Type: application/json" \
    -d '{"name":"seed-real","scopes":["all"]}')

  FORGEJO_TOKEN=$(printf '%s' "$token_response" | python3 -c 'import json,sys; data=json.load(sys.stdin); print(data.get("token") or data.get("sha1") or "")')
  if [[ -z "$FORGEJO_TOKEN" ]]; then
    echo "ERROR: Failed to get Forgejo admin token" >&2
    exit 1
  fi
}

mirror_k9s_repo() {
  local repo="k9s"
  local repo_url="$FORGEJO_URL/api/v1/repos/$FORGEJO_OWNER/$repo"

  if curl -fsSo /dev/null -H "Authorization: token $FORGEJO_TOKEN" "$repo_url" 2>/dev/null; then
    echo "    k9s repo already exists in Forgejo"
    return
  fi

  echo "    Migrating derailed/k9s from GitHub via Forgejo API..."
  curl -sf "$FORGEJO_URL/api/v1/repos/migrate" \
    -H "Authorization: token $FORGEJO_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"clone_addr":"https://github.com/derailed/k9s.git","repo_name":"k9s","service":"github"}' \
    >/dev/null
  echo "    Migration complete"
}

setup_k9s_webhook() {
  echo "==> Configuring Forgejo webhook for k9s..."

  local hooks_json existing_hook
  hooks_json=$(curl -sf "$FORGEJO_URL/api/v1/repos/$FORGEJO_OWNER/k9s/hooks?limit=100" \
    -H "Authorization: token $FORGEJO_TOKEN")
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

  if [[ "$existing_hook" == "found" ]]; then
    echo "    k9s webhook already configured"
    return
  fi

  curl -sf "$FORGEJO_URL/api/v1/repos/$FORGEJO_OWNER/k9s/hooks" \
    -H "Authorization: token $FORGEJO_TOKEN" \
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

  echo "    k9s webhook created"
}

download_release_sbom() {
  local tag=$1
  local output_file=$2
  local sbom_url="https://github.com/derailed/k9s/releases/download/${tag}/k9s_Linux_amd64.tar.gz.sbom.json"

  if ! curl -sfL -o "$output_file" "$sbom_url"; then
    echo "ERROR: Failed to download SBOM for $tag" >&2
    return 1
  fi
}

get_tag_commit_sha() {
  local repo=$1
  local tag=$2
  local response

  response=$(curl -sf \
    -H "Authorization: token $FORGEJO_TOKEN" \
    "$FORGEJO_URL/api/v1/repos/$FORGEJO_OWNER/$repo/tags/$tag")

  printf '%s' "$response" | python3 -c 'import json,sys; print((json.load(sys.stdin).get("commit") or {}).get("sha", ""))'
}

get_branch_commit_sha() {
  local repo=$1
  local branch=$2

  curl -sf \
    -H "Authorization: token $FORGEJO_TOKEN" \
    "$FORGEJO_URL/api/v1/repos/$FORGEJO_OWNER/$repo/branches/$branch" | \
    python3 -c 'import json,sys; print(json.load(sys.stdin)["commit"]["id"])'
}

upload_sbom() {
  local repo=$1
  local ref_name=$2
  local commit_sha=$3
  local sbom_file=$4

  local payload_file="$TMPDIR_BASE/${repo}-${ref_name//\//_}-sbom-payload.json"
  SBOM_FILE="$sbom_file" REPO="$repo" REF_NAME="$ref_name" COMMIT_SHA="$commit_sha" PAYLOAD_FILE="$payload_file" python3 - <<'PY'
import base64
import json
import os

with open(os.environ["SBOM_FILE"], "rb") as fh:
    content_b64 = base64.b64encode(fh.read()).decode()

payload = {
    "provider": "forgejo",
    "org": "devtools",
    "repo": os.environ["REPO"],
    "ref": os.environ["REF_NAME"],
    "commit_sha": os.environ["COMMIT_SHA"],
    "format": "spdx-json",
    "artifact": {
        "filename": "k9s_Linux_amd64.tar.gz.sbom.json",
        "content_base64": content_b64,
    },
}

with open(os.environ["PAYLOAD_FILE"], "w", encoding="utf-8") as fh:
    json.dump(payload, fh)
PY

  curl -sf "$HIBOU_URL/api/v1/upload/sbom" \
    -H "Authorization: Bearer $API_KEY" \
    -H "Content-Type: application/json" \
    --data @"$payload_file" >/dev/null
}

seed_hibou_data() {
  echo "==> Starting Hibou and seeding local data..."
  go build -o "$TMPDIR_BASE/hibou" . 2>/dev/null
  ln -sf hibou "$TMPDIR_BASE/hibou-server"

  env \
    HIBOU_ARTIFACT_PATH=tmp/artifacts \
    HIBOU_FORGE_0_TYPE= \
    HIBOU_FORGE_0_ID= \
    HIBOU_FORGE_0_URL= \
    HIBOU_FORGE_0_CLIENT_ID= \
    HIBOU_FORGE_0_CLIENT_SECRET= \
    HIBOU_FORGE_0_WEBHOOK_SECRET= \
    "$TMPDIR_BASE/hibou-server" serve >/tmp/hibou-seed-real.log 2>&1 &
  HIBOU_PID=$!

  wait_for_hibou

  echo "==> Running hibou seed command..."
  "$TMPDIR_BASE/hibou-server" seed >/dev/null

  # Fix provider for devtools org if seeded before the forgejo switch,
  # ensure k9s repo exists, and fix default_branch if set to 'main'.
  docker compose exec -T postgres psql -U hibou -d hibou -tAc "
    UPDATE organizations SET provider = 'forgejo' WHERE slug = 'devtools' AND provider != 'forgejo';
    INSERT INTO repositories (org_id, team_id, name, slug, provider, provider_id, default_branch, sync_state)
      SELECT o.id, t.id, 'k9s', 'k9s', 'forgejo', 'hibou-admin/k9s', 'master', 'synced'
      FROM organizations o
      JOIN teams t ON t.org_id = o.id AND t.slug = 'platform'
      WHERE o.slug = 'devtools'
        AND NOT EXISTS (SELECT 1 FROM repositories r WHERE r.org_id = o.id AND r.slug = 'k9s');
    UPDATE repositories SET default_branch = 'master'
      WHERE slug = 'k9s' AND default_branch = 'main'
        AND org_id = (SELECT id FROM organizations WHERE slug = 'devtools');
  " >/dev/null 2>&1 || true

  echo "==> Authenticating with Hibou dev login..."
  curl -sf -c "$COOKIE_JAR" -X POST "$HIBOU_URL/api/v1/auth/dev-login" >/dev/null

  local existing_count
  existing_count=$(curl -sf -b "$COOKIE_JAR" "$HIBOU_URL/api/v1/orgs/forgejo/devtools/repos/k9s/snapshots?per_page=1" 2>/dev/null | \
    python3 -c 'import json,sys; d=json.load(sys.stdin); print(len(d.get("data",[])))' 2>/dev/null || echo "0")
  if [[ "$existing_count" != "0" ]]; then
    echo "    Real data already seeded, skipping uploads."
    SKIP_UPLOADS="true"
  fi

  echo "==> Creating Hibou upload API key..."
  local key_response
  key_response=$(curl -sf -b "$COOKIE_JAR" "$HIBOU_URL/api/v1/users/me/api-keys" \
    -H "Content-Type: application/json" \
    -d '{"name":"seed-real","scopes":["upload"]}')
  API_KEY=$(printf '%s' "$key_response" | python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["key"])')
  API_KEY_ID=$(printf '%s' "$key_response" | python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["api_key"]["id"])')
}

modify_sbom_bump_versions() {
  local input_file=$1
  local output_file=$2

  python3 - "$input_file" "$output_file" <<'PYEOF'
import json
import re
import sys

with open(sys.argv[1], encoding="utf-8") as f:
    sbom = json.load(f)

count = 0
for pkg in sbom.get("packages", []):
    ver = pkg.get("versionInfo", "")
    match = re.match(r'^(\d+)\.(\d+)\.(\d+)$', ver)
    if match and count < 5:
        major, minor, patch = map(int, match.groups())
        pkg["versionInfo"] = f"{major}.{minor}.{patch + 1}"
        count += 1

with open(sys.argv[2], 'w', encoding="utf-8") as f:
    json.dump(sbom, f)
PYEOF
}

modify_sbom_remove_packages() {
  local input_file=$1
  local output_file=$2

  python3 - "$input_file" "$output_file" <<'PYEOF'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as f:
    sbom = json.load(f)

packages = sbom.get("packages", [])
removed = []
kept = []
for pkg in packages:
    if len(removed) < 3 and pkg.get("SPDXID", "") != "SPDXRef-DOCUMENT" and not pkg.get("name", "").startswith("k9s") and len(kept) > 0:
        removed.append(pkg)
    else:
        kept.append(pkg)

sbom["packages"] = kept

removed_ids = {p["SPDXID"] for p in removed}
sbom["relationships"] = [
    rel for rel in sbom.get("relationships", [])
    if rel.get("spdxElementId") not in removed_ids and rel.get("relatedSpdxElement") not in removed_ids
]

with open(sys.argv[2], 'w', encoding="utf-8") as f:
    json.dump(sbom, f)
PYEOF
}

create_prs() {
  echo "==> Creating pull requests in Forgejo..."

  local branches=("deps/update-go-modules" "fix/resolve-cve-2024")
  local titles=("chore(deps): bump Go module dependencies" "fix: resolve CVE-2024 vulnerabilities")
  local bodies=(
    "Bumps several Go module dependencies to their latest versions.\n\n- Updated golang.org/x/net\n- Updated golang.org/x/crypto\n- Updated google.golang.org/grpc"
    "Resolves CVE-2024 vulnerabilities by removing affected packages.\n\n- Removed vulnerable dependency\n- Updated indirect dependencies"
  )

  local i
  for i in "${!branches[@]}"; do
    local branch="${branches[$i]}"
    local title="${titles[$i]}"
    local body="${bodies[$i]}"

    if curl -fsSo /dev/null -H "Authorization: token $FORGEJO_TOKEN" \
      "$FORGEJO_URL/api/v1/repos/$FORGEJO_OWNER/k9s/branches/$branch" 2>/dev/null; then
      echo "    Branch $branch already exists, skipping"
      continue
    fi

    curl -sf "$FORGEJO_URL/api/v1/repos/$FORGEJO_OWNER/k9s/branches" \
      -H "Authorization: token $FORGEJO_TOKEN" \
      -H "Content-Type: application/json" \
      -d "{\"new_branch_name\":\"$branch\",\"old_branch_name\":\"master\"}" >/dev/null

    local pr_payload
    pr_payload=$(BRANCH="$branch" TITLE="$title" BODY="$body" python3 - <<'PYEOF'
import json
import os

print(json.dumps({
    "title": os.environ["TITLE"],
    "body": os.environ["BODY"].encode("utf-8").decode("unicode_escape"),
    "head": os.environ["BRANCH"],
    "base": "master",
}))
PYEOF
)

    local pr_response
    pr_response=$(curl -sf "$FORGEJO_URL/api/v1/repos/$FORGEJO_OWNER/k9s/pulls" \
      -H "Authorization: token $FORGEJO_TOKEN" \
      -H "Content-Type: application/json" \
      -d "$pr_payload")

    local pr_number
    pr_number=$(printf '%s' "$pr_response" | python3 -c 'import json,sys; print(json.load(sys.stdin)["number"])')
    echo "    Created PR #$pr_number: $title"
  done
}

upload_pr_sboms() {
  echo "==> Uploading modified SBOMs for pull requests..."

  local latest_tag="${K9S_RELEASES[${#K9S_RELEASES[@]}-1]}"
  local base_sbom="$TMPDIR_BASE/k9s-${latest_tag}.sbom.json"

  local prs
  prs=$(curl -sf \
    -H "Authorization: token $FORGEJO_TOKEN" \
    "$FORGEJO_URL/api/v1/repos/$FORGEJO_OWNER/k9s/pulls?state=open&limit=10")

  local pr_count
  pr_count=$(printf '%s' "$prs" | python3 -c 'import json,sys; print(len(json.load(sys.stdin)))')
  if (( pr_count == 0 )); then
    echo "    No open PRs found"
    return
  fi

  local idx
  for idx in $(seq 0 $((pr_count - 1))); do
    local pr_number pr_head_branch pr_head_sha
    pr_number=$(printf '%s' "$prs" | python3 -c "import json,sys; print(json.load(sys.stdin)[$idx]['number'])")
    pr_head_branch=$(printf '%s' "$prs" | python3 -c "import json,sys; head=json.load(sys.stdin)[$idx]['head']; print(head.get('label') or head.get('ref') or '')")
    pr_head_sha=$(printf '%s' "$prs" | python3 -c "import json,sys; print(json.load(sys.stdin)[$idx]['head']['sha'])")

    local modified_sbom="$TMPDIR_BASE/k9s-pr-${pr_number}.sbom.json"

    if [[ "$pr_head_branch" == *"deps"* ]] || [[ "$pr_head_branch" == *"deps/"* ]]; then
      modify_sbom_bump_versions "$base_sbom" "$modified_sbom"
      echo "    PR #$pr_number ($pr_head_branch): bumped versions"
    else
      modify_sbom_remove_packages "$base_sbom" "$modified_sbom"
      echo "    PR #$pr_number ($pr_head_branch): removed packages"
    fi

    upload_sbom "k9s" "refs/pull/$pr_number/head" "$pr_head_sha" "$modified_sbom"
    echo "    PR #$pr_number SBOM uploaded"
  done
}

main() {
  wait_for_forgejo
  generate_admin_token

  echo "==> Mirroring k9s repository to Forgejo..."
  mirror_k9s_repo
  setup_k9s_webhook

  seed_hibou_data

  if [[ "$SKIP_UPLOADS" != "true" ]]; then
    echo "==> Downloading and uploading k9s SBOMs..."
    local tag
    for tag in "${K9S_RELEASES[@]}"; do
      echo "    Processing $tag..."
      local sbom_file="$TMPDIR_BASE/k9s-${tag}.sbom.json"
      local commit_sha
      download_release_sbom "$tag" "$sbom_file"
      commit_sha=$(get_tag_commit_sha "k9s" "$tag")
      upload_sbom "k9s" "refs/tags/$tag" "$commit_sha" "$sbom_file"
    done

    echo "==> Uploading SBOM for master branch..."
    local master_sha
    master_sha=$(get_branch_commit_sha "k9s" "master")
    local latest_sbom="$TMPDIR_BASE/k9s-${K9S_RELEASES[${#K9S_RELEASES[@]}-1]}.sbom.json"
    upload_sbom "k9s" "refs/heads/master" "$master_sha" "$latest_sbom"
    echo "    master branch SBOM uploaded"
  fi

  # PRs are idempotent (branch existence check) and need the SBOM files
  # downloaded above OR already present from a previous run.
  # Download latest SBOM if not present (for re-runs where SKIP_UPLOADS=true).
  local latest_tag="${K9S_RELEASES[${#K9S_RELEASES[@]}-1]}"
  local base_sbom="$TMPDIR_BASE/k9s-${latest_tag}.sbom.json"
  if [[ ! -f "$base_sbom" ]]; then
    download_release_sbom "$latest_tag" "$base_sbom"
  fi

  create_prs
  upload_pr_sboms

  echo "==> Real seed data complete."
}

main "$@"
