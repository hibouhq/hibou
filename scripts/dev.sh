#!/usr/bin/env bash
set -euo pipefail

local_login=false
case "${1:-}" in
  '') ;;
  --local) local_login=true ;;
  *) printf 'Usage: bash scripts/dev.sh [--local]\n' >&2; exit 2 ;;
esac
if (( $# > 1 )); then
  printf 'Usage: bash scripts/dev.sh [--local]\n' >&2
  exit 2
fi

workspace_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$workspace_dir"

set -a
if [[ -f .env ]]; then
  source .env
fi
set +a

export HIBOU_DEVELOPMENT=true
export HIBOU_ARTIFACT_PATH=tmp/artifacts
frontend_host=0.0.0.0
if [[ "$local_login" == true ]]; then
  export HIBOU_FORGE_0_TYPE=''
  frontend_host=127.0.0.1
  printf 'Local Dev Login enabled. Keep this instance private.\n'
  docker compose up -d --wait --wait-timeout 600 postgres trivy
fi

child_pids=()
cleanup() {
  if (( ${#child_pids[@]} > 0 )); then
    kill "${child_pids[@]}" 2>/dev/null || true
    wait "${child_pids[@]}" 2>/dev/null || true
  fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

tmp/dev/hibou-server serve &
child_pids+=("$!")
cd site
./node_modules/.bin/vite --host "$frontend_host" &
child_pids+=("$!")
wait -n "${child_pids[@]}"
