#!/usr/bin/env bash
#
# deploy.sh — Wait for a release's CI to publish, then upgrade the dogfood cluster.
#
# CI publishes the image and the chart at the same version, so this waits on the
# release run, confirms the chart is actually resolvable in GHCR, then upgrades.
#
# Usage:
#   ./deploy.sh                    # newest GitHub release
#   ./deploy.sh 0.1.0-alpha.45     # explicit version (leading "v" ok)
#   ./deploy.sh --no-wait          # chart is already published, just deploy
#   ./deploy.sh -n                 # dry run: print the helm command only
#
set -euo pipefail

REPO=hibouhq/hibou
NAMESPACE=hibou
CHART=oci://ghcr.io/hibouhq/charts/hibou
# Dogfooding: after a successful rollout the deployment is recorded in Hibou
# itself via `hibou release deploy`. Auth comes from `hibou login` state or
# the HIBOU_TOKEN env var (HIBOU_API_TOKEN accepted as an alias); skipped
# with a warning when neither is available.
export HIBOU_SERVER="${HIBOU_SERVER:-https://hibouhq.com}"
export HIBOU_ORG="${HIBOU_ORG:-github/hibouhq}"
HIBOU_REPO_SLUG="${HIBOU_REPO_SLUG:-hibou}"
HIBOU_CLIENT_SLUG="${HIBOU_CLIENT_SLUG:-internal}"
HIBOU_ENVIRONMENT="${HIBOU_ENVIRONMENT:-production}"
[ -n "${HIBOU_API_TOKEN:-}" ] && export HIBOU_TOKEN="${HIBOU_TOKEN:-$HIBOU_API_TOKEN}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VALUES="${ROOT}/infra/dogfood/values-dogfood.yaml"
: "${KUBECONFIG:=${ROOT}/infra/scaleway/kubeconfig.yaml}"
export KUBECONFIG

VERSION=""
WAIT=1
DRY=0

while [ $# -gt 0 ]; do
  case "$1" in
    --no-wait)    WAIT=0; shift;;
    -n|--dry-run) DRY=1; shift;;
    -h|--help)    sed -n '2,14p' "$0" | sed 's/^#\{1,\} \{0,1\}//'; exit 0;;
    -*)           echo "unknown option: $1" >&2; exit 1;;
    *)            VERSION="$1"; shift;;
  esac
done

die() { echo "error: $*" >&2; exit 1; }
info() { echo "==> $*"; }

command -v gh >/dev/null || die "gh not found"
command -v helm >/dev/null || die "helm not found"
[ -f "$VALUES" ] || die "values file not found: $VALUES"

if [ -z "$VERSION" ]; then
  VERSION="$(gh release list -R "$REPO" -L 1 --json tagName --jq '.[0].tagName')"
  [ -n "$VERSION" ] || die "no releases found in $REPO"
  info "Newest release: $VERSION"
fi
VERSION="${VERSION#v}"
TAG="v${VERSION}"

if [ "$WAIT" -eq 1 ]; then
  # The release-triggered run reports the tag as its head branch.
  info "Looking for the CI run for $TAG"
  RUN_ID=""
  for _ in $(seq 1 30); do
    RUN_ID="$(gh run list -R "$REPO" --event release --limit 20 \
      --json databaseId,headBranch \
      --jq "[.[] | select(.headBranch == \"${TAG}\")] | .[0].databaseId // empty")"
    [ -n "$RUN_ID" ] && break
    sleep 10
  done
  [ -n "$RUN_ID" ] || die "no release run found for $TAG (was the release published?)"

  info "Watching run $RUN_ID"
  gh run watch "$RUN_ID" -R "$REPO" --exit-status \
    || die "release CI failed — nothing was published, see: gh run view $RUN_ID -R $REPO --log-failed"

  # CI green is not the same as the registry serving the new tag.
  info "Waiting for chart ${VERSION} in GHCR (up to 5m)"
  for i in $(seq 1 30); do
    # Keep the last helm error: "not found" and "unauthorized" need different
    # fixes, and swallowing it made every failure look like a hang.
    if CHART_ERR="$(helm show chart "$CHART" --version "$VERSION" 2>&1 >/dev/null)"; then
      break
    fi
    if [ "$i" -eq 30 ]; then
      echo "helm: ${CHART_ERR}" >&2
      die "chart ${VERSION} never appeared (if unauthorized: helm registry login ghcr.io)"
    fi
    printf '.' >&2
    sleep 10
  done
  echo >&2
fi

kubectl version --request-timeout=5s >/dev/null 2>&1 \
  || die "cluster unreachable (KUBECONFIG=${KUBECONFIG})"

HELM_ARGS=(
  upgrade --install hibou "$CHART"
  --version "$VERSION"
  --namespace "$NAMESPACE"
  --values "$VALUES"
  --set-string "hibou.image.tag=${VERSION}"
  # Not in values-dogfood.yaml; drop these and the image reverts.
  --set seaweedfs.image.repository=chrislusf/seaweedfs
  --set-string seaweedfs.image.tag=4.34
  --wait --timeout 6m
)

if [ "$DRY" -eq 1 ]; then
  info "dry run"
  printf 'helm'; printf ' %q' "${HELM_ARGS[@]}"; echo
  exit 0
fi

info "Deploying ${VERSION}"
helm "${HELM_ARGS[@]}"

info "Verifying"
kubectl rollout status "deploy/hibou" -n "$NAMESPACE" --timeout=180s
kubectl get deploy hibou -n "$NAMESPACE" -o jsonpath='{.spec.template.spec.containers[*].image}{"\n"}'
code="$(curl -sS -o /dev/null -w '%{http_code}' https://hibouhq.com/ || true)"
echo "https://hibouhq.com -> ${code}"
[ "$code" = "200" ] || die "site returned ${code}"

# Record the deployment in Hibou (assign the release to the dogfood client).
# Best-effort: the rollout already succeeded, so failures warn and never fail
# the deploy. The release row is derived from the tag's snapshot, which may
# still be finishing artifact processing — hence the retry loop.
# Resolve a hibou CLI matching the server, the same way the upload action
# does: ask /api/v1/bin/version what the server serves, reuse a matching PATH
# or cached binary, otherwise download from /api/v1/bin/{os}/{arch}. The CLI
# has no self-update; version-matching happens here, at the invocation site.
# Sets HIBOU_CLI (command array); returns non-zero when no CLI can be had.
ensure_hibou_cli() {
  local want="" have="" os arch cache bin tmp
  want="$(curl -sS --max-time 10 "${HIBOU_SERVER}/api/v1/bin/version" 2>/dev/null \
    | sed -n 's/.*"version":"\([^"]*\)".*/\1/p')" || want=""

  if command -v hibou >/dev/null; then
    have="$(hibou version --short 2>/dev/null || true)"
    if [ -n "$want" ] && [ "$have" = "$want" ]; then
      HIBOU_CLI=(hibou)
      return 0
    fi
  fi

  if [ -z "$want" ]; then
    # Server did not answer; a stale CLI beats none, source tree beats that.
    if command -v hibou >/dev/null; then
      echo "warn: could not read server CLI version — using hibou ${have:-unknown} from PATH" >&2
      HIBOU_CLI=(hibou)
      return 0
    fi
    if command -v go >/dev/null; then
      HIBOU_CLI=(go run "$ROOT")
      return 0
    fi
    echo "warn: no server version, no hibou, no go toolchain" >&2
    return 1
  fi

  case "$(uname -s)" in
    Linux)  os=linux;;
    Darwin) os=darwin;;
    *)      echo "warn: unsupported OS $(uname -s) for CLI download" >&2; return 1;;
  esac
  case "$(uname -m)" in
    x86_64)         arch=amd64;;
    aarch64|arm64)  arch=arm64;;
    *)              echo "warn: unsupported arch $(uname -m) for CLI download" >&2; return 1;;
  esac

  cache="${XDG_CACHE_HOME:-$HOME/.cache}/hibou/bin"
  bin="${cache}/hibou-${want}"
  if [ ! -x "$bin" ]; then
    info "Downloading hibou ${want} (${os}/${arch}) from ${HIBOU_SERVER}"
    mkdir -p "$cache"
    tmp="$(mktemp "${cache}/hibou.XXXXXX")"
    if ! curl -fsSL --max-time 120 -o "$tmp" "${HIBOU_SERVER}/api/v1/bin/${os}/${arch}"; then
      rm -f "$tmp"
      echo "warn: CLI download failed" >&2
      return 1
    fi
    chmod +x "$tmp"
    mv "$tmp" "$bin"
  fi
  HIBOU_CLI=("$bin")
}

record_deployment() {
  if ! ensure_hibou_cli; then
    echo "warn: no usable hibou CLI — deployment not recorded" >&2
    return 0
  fi
  local hibou_cli=("${HIBOU_CLI[@]}")

  info "Recording deployment of ${TAG} in Hibou (${HIBOU_CLIENT_SLUG}/${HIBOU_ENVIRONMENT})"
  local output
  for i in $(seq 1 10); do
    if output="$("${hibou_cli[@]}" release deploy \
      --repo "$HIBOU_REPO_SLUG" \
      --version "$TAG" \
      --client "$HIBOU_CLIENT_SLUG" \
      --env "$HIBOU_ENVIRONMENT" \
      --notes "deploy.sh by $(whoami)@$(hostname)" 2>&1)"; then
      info "$output"
      return 0
    fi
    # The release is derived from the tag's snapshot; keep waiting while the
    # server has not materialized it yet. Anything else is a real failure.
    case "$output" in
      *"not found"*)
        [ "$i" -eq 10 ] && break
        sleep 15
        ;;
      *)
        break
        ;;
    esac
  done
  echo "warn: deployment not recorded: ${output}" >&2
}
record_deployment

info "Done: ${VERSION}"
