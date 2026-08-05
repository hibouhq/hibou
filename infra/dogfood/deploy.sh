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

info "Done: ${VERSION}"
