#!/usr/bin/env bash
set -euo pipefail

CLUSTER_NAME="hibou-dev"

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

info() { echo -e "${GREEN}==>${NC} $*"; }
error() { echo -e "${RED}==> ERROR:${NC} $*" >&2; }

# Kill any port-forward processes
pkill -f "kubectl port-forward.*hibou" 2>/dev/null && info "Killed port-forward processes" || true

# Delete vind cluster
if command -v vcluster &>/dev/null && vcluster list 2>/dev/null | grep -q "${CLUSTER_NAME}"; then
  info "Deleting vind cluster '${CLUSTER_NAME}'..."
  vcluster delete "${CLUSTER_NAME}"
  info "Cluster deleted."
else
  info "Cluster '${CLUSTER_NAME}' not found, nothing to delete."
fi
