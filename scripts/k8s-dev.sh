#!/usr/bin/env bash
set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

CLUSTER_NAME="hibou-dev"
NAMESPACE="hibou"
RELEASE_NAME="hibou"
FULLNAME="hibou"  # matches helm fullname when release name contains chart name
CNPG_CLUSTER="${FULLNAME}-pg"
PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
CHART_DIR="${PROJECT_DIR}/chart/hibou"
IMAGE_NAME="ghcr.io/hibouhq/hibou"
IMAGE_TAG="dev"
VCLUSTER_VERSION="v0.34.0"

info()  { echo -e "${GREEN}==>${NC} $*"; }
warn()  { echo -e "${YELLOW}==> WARNING:${NC} $*"; }
error() { echo -e "${RED}==> ERROR:${NC} $*" >&2; }

# Install vCluster CLI if missing
if ! command -v vcluster &>/dev/null; then
  info "Installing vCluster CLI ${VCLUSTER_VERSION}..."
  curl -sSL "https://github.com/loft-sh/vcluster/releases/download/${VCLUSTER_VERSION}/vcluster-linux-amd64" -o /usr/local/bin/vcluster \
    || sudo curl -sSL "https://github.com/loft-sh/vcluster/releases/download/${VCLUSTER_VERSION}/vcluster-linux-amd64" -o /usr/local/bin/vcluster
  chmod +x /usr/local/bin/vcluster 2>/dev/null || sudo chmod +x /usr/local/bin/vcluster
fi

# Check prerequisites
for cmd in docker kubectl helm vcluster apko; do
  if ! command -v "$cmd" &>/dev/null; then
    error "$cmd is not installed"
    exit 1
  fi
done

# Set Docker driver for vind
vcluster use driver docker

# Build Wolfi base image if missing
if ! docker image inspect hibou-base:latest-amd64 &>/dev/null || ! docker image inspect hibou-base:latest-arm64 &>/dev/null; then
  info "Building Wolfi base image..."
  apko_args=("${PROJECT_DIR}/apko.yaml" "hibou-base:latest" "/tmp/hibou-base.tar")
  if [ -f "${PROJECT_DIR}/apko.lock.json" ]; then
    apko_args=("--lockfile" "${PROJECT_DIR}/apko.lock.json" "${apko_args[@]}")
  fi
  apko build "${apko_args[@]}"
  docker load < /tmp/hibou-base.tar
else
  info "Base image hibou-base already exists, skipping build (run 'make base-image' to rebuild)"
fi

# Build Hibou Docker image first (vind uses pull-through cache from local Docker)
info "Building Hibou Docker image..."
SOURCE_DATE_EPOCH=$(git -C "${PROJECT_DIR}" log -1 --format=%ct 2>/dev/null || echo 0)
docker build \
  --build-arg SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH}" \
  --build-arg VERSION="${IMAGE_TAG}" \
  --build-arg COMMIT="$(git -C "${PROJECT_DIR}" rev-parse --short HEAD 2>/dev/null || echo unknown)" \
  --build-arg DATE="$(git -C "${PROJECT_DIR}" log -1 --format=%cI 2>/dev/null || echo 1970-01-01T00:00:00Z)" \
  -t "${IMAGE_NAME}:${IMAGE_TAG}" "${PROJECT_DIR}"

# Create or reuse cluster
if vcluster list 2>/dev/null | grep -q "${CLUSTER_NAME}"; then
  info "Cluster '${CLUSTER_NAME}' already exists, reconnecting..."
  vcluster connect "${CLUSTER_NAME}" 2>/dev/null || true
else
  info "Creating vind cluster '${CLUSTER_NAME}'..."
  vcluster create "${CLUSTER_NAME}"
fi

# Wait for cluster ready
info "Waiting for cluster to be ready..."
kubectl wait --for=condition=Ready nodes --all --timeout=120s

# Create namespace
kubectl create namespace "${NAMESPACE}" --dry-run=client -o yaml | kubectl apply -f -

# Build Helm chart dependencies
info "Building Helm chart dependencies..."
helm dependency update "${CHART_DIR}"

# Phase 1: Install CNPG operator (CRDs must exist before Cluster resources)
info "Installing CNPG operator (CRDs)..."
helm upgrade --install "${RELEASE_NAME}" "${CHART_DIR}" \
  --namespace "${NAMESPACE}" \
  --set postgresql.enabled=false \
  --set cnpg.operator.enabled=true \
  --set cnpg.cluster.enabled=false \
  --set hibou.replicas=0 \
  --set hibou.trivy.url=http://placeholder \
  --set trivy.enabled=false \
  --wait --timeout 5m

# Phase 2: Full install with CNPG cluster + Hibou
# vind uses pull-through cache — local Docker images are available automatically
info "Installing Hibou chart with CNPG cluster..."
helm upgrade --install "${RELEASE_NAME}" "${CHART_DIR}" \
  --namespace "${NAMESPACE}" \
  --set postgresql.enabled=false \
  --set cnpg.operator.enabled=true \
  --set cnpg.cluster.enabled=true \
  --set cnpg.cluster.instances=1 \
  --set cnpg.cluster.tls=false \
  --set hibou.sessionSecret=dev-secret-do-not-use-in-prod \
  --set hibou.image.tag="${IMAGE_TAG}" \
  --set hibou.image.pullPolicy=IfNotPresent \
  --set hibou.replicas=1 \
  --set trivy.enabled=true \
  --wait --timeout 5m

# Wait for CNPG cluster to be ready
info "Waiting for CNPG PostgreSQL cluster to be ready..."
kubectl wait --for=condition=Ready cluster/${CNPG_CLUSTER} \
  --namespace "${NAMESPACE}" --timeout=300s 2>/dev/null || {
  warn "CNPG cluster not ready via 'cluster' resource. Waiting for pod readiness instead..."
  kubectl wait --for=condition=Ready pod -l cnpg.io/cluster=${CNPG_CLUSTER} \
    --namespace "${NAMESPACE}" --timeout=300s
}

# Wait for Hibou pod
info "Waiting for Hibou pods to be ready..."
kubectl wait --for=condition=Ready pod -l app.kubernetes.io/name=hibou \
  --namespace "${NAMESPACE}" --timeout=120s

info "All pods:"
kubectl get pods -n "${NAMESPACE}"

# Port-forward in background
pkill -f "kubectl port-forward.*hibou" 2>/dev/null || true
sleep 1
info "Starting port-forward (Hibou on localhost:8080)..."
kubectl port-forward -n "${NAMESPACE}" svc/${FULLNAME} 8080:8080 &
PF_PID=$!

echo ""
info "============================================"
info "  Hibou dev cluster is ready!"
info "  UI:  http://localhost:8080"
info "  Port-forward PID: ${PF_PID}"
info "  Namespace: ${NAMESPACE}"
info "============================================"
echo ""
info "To stop port-forward: kill ${PF_PID}"
info "To pause cluster: vcluster pause ${CLUSTER_NAME}"
info "To tear down: make k8s-dev-clean"
