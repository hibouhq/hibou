# Deployment Guide

## Architecture Overview

```
┌──────────────────────────────────────────────────────┐
│                Your private network                   │
│                                                       │
│  ┌──────────────────────────────────────────┐         │
│  │ Hibou :8080                              │         │
│  │ ┌─────────────────────────────────────┐  │         │
│  │ │ Built-in security middleware        │  │         │
│  │ │ ✓ GitHub IP allowlist (auto-updated)│  │         │
│  │ │ ✓ Rate limiting (per-IP)            │  │         │
│  │ │ ✓ Webhook HMAC-SHA256 validation    │  │         │
│  │ │ ✓ API token authentication          │  │         │
│  │ └─────────────────────────────────────┘  │         │
│  └─────────────┬────────────────────────────┘         │
│                │                                      │
│       ┌────────┴────────┐     ┌──────────────┐        │
│       │ Your ingress    │     │ PostgreSQL   │        │
│       │ (any controller)│     │              │        │
│       └────────┬────────┘     └──────────────┘        │
│                │ :443                                 │
│  (UI: VPN / port-forward / internal DNS)              │
└────────────────┼──────────────────────────────────────┘
            │
  GitHub (webhooks + runner uploads)
```

**Key points:**

- Hibou makes outbound calls to GitHub API for repo discovery and commit statuses
- GitHub reaches Hibou through your existing ingress, and Hibou applies IP allowlisting plus webhook rate limiting itself
- GitHub-hosted runners (`ubuntu-latest`) upload directly to the public Hibou URL with an API token
- UI can stay private via VPN, `kubectl port-forward`, or internal DNS while webhook traffic remains public

## Prerequisites

- Kubernetes cluster
- Ingress controller (any)
- Helm 3
- A GitHub App (for org-wide repo discovery and commit statuses)
- A public hostname pointing to your cluster
- TLS certificate (cert-manager recommended)

## Step 1: GitHub App Setup

Use a GitHub App for org-wide repo access, webhook delivery, and commit status updates.

### Create the App

1. GitHub → Settings → Developer Settings → GitHub Apps → **New GitHub App**
2. App name: `hibou-<your-org>`
3. Homepage URL: `http://localhost` (placeholder is fine)
4. Callback URL: `http://<hibou-internal-host>:8080/api/v1/auth/callback`
5. Webhook URL: set this after Step 2 to `https://hibou.example.com/api/v1/webhooks/github`
6. Webhook secret: generate one with `openssl rand -hex 32`
7. Click **Create GitHub App**

### Set permissions

| Permission | Access | Why |
|-----------|--------|-----|
| Repository → Contents | Read-only | Read files, branches |
| Repository → Metadata | Read-only | Discover repos |
| Repository → Pull requests | Read & write | Post PR check results |
| Repository → Commit statuses | Read & write | Set CI status |
| Organization → Members | Read-only | Org membership info |

### Generate a private key

On the App settings page, click **Generate a private key** and save the `.pem` file.

### Note the credentials

Collect these values from the App settings page:

- **App ID**
- **Client ID**
- **Client Secret**
- **Webhook Secret**
- **Private key** (`.pem` file)

### Install the App on your org

1. App settings page → **Install App**
2. Select your organization
3. Choose **All repositories** or the subset you want
4. Click **Install**

## Step 2: GitHub Connectivity

Hibou includes built-in security middleware for GitHub-facing traffic. No special
ingress configuration needed: your existing ingress controller routes traffic to
Hibou, and Hibou handles webhook protection itself.

### Built-in protections

| Layer | Protection | Configured via |
|-------|-----------|---------------|
| Network | Forge IP allowlist (GitHub: auto from [`/meta`](https://api.github.com/meta); GitLab SaaS: built-in defaults; others: static CIDRs) | `HIBOU_FORGE_N_IP_ALLOWLIST=true` with optional `HIBOU_FORGE_N_ALLOWED_CIDRS=...` override |
| Transport | TLS termination | Your ingress controller |
| Application | Webhook HMAC-SHA256 signature validation | Forge webhook secret |
| Application | Per-IP rate limiting | `HIBOU_FORGE_N_RATE_LIMIT_RPS=10` |
| Application | API token authentication (uploads) | API keys in Hibou UI |

### Enable the protections

Add these environment variables to Hibou:

```bash
# GitHub forge (index 0) — automatic IP fetching from /meta
HIBOU_FORGE_0_IP_ALLOWLIST=true
HIBOU_FORGE_0_RATE_LIMIT_RPS=10

# GitLab SaaS forge (index 1) — built-in defaults, no CIDRs needed
HIBOU_FORGE_1_IP_ALLOWLIST=true
# Optional: override with custom CIDRs
# HIBOU_FORGE_1_ALLOWED_CIDRS="custom/cidr"
HIBOU_FORGE_1_RATE_LIMIT_RPS=10
```

With Helm, set them through values or inject them through your deployment env.

### Ingress configuration

Use whatever ingress controller you already run. Route traffic to Hibou:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: hibou
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
spec:
  ingressClassName: nginx
  rules:
    - host: hibou.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: hibou
                port:
                  number: 8080
  tls:
    - hosts:
        - hibou.example.com
      secretName: hibou-tls
```

Hibou handles the rest. Requests from IPs outside the configured forge allowlist get 403 on that forge's webhook route automatically.

### How it works

1. On startup, Hibou builds a per-forge IP allowlist for webhook routes.
2. GitHub forges fetch IP ranges from `https://api.github.com/meta` and refresh them every 6 hours.
3. GitLab SaaS uses built-in published CIDRs when `HIBOU_FORGE_N_IP_ALLOWLIST=true` and no custom forge URL or override CIDRs are set.
4. Other forges use static CIDRs from `HIBOU_FORGE_N_ALLOWED_CIDRS`.
5. `/api/v1/webhooks/{provider}` rejects non-allowed IPs with 403 when that forge's allowlist is loaded.
6. If a dynamic fetch fails, Hibou allows webhook traffic until the first successful refresh and logs a warning for each allowed request.
7. Webhook payloads are always validated via HMAC-SHA256 regardless of IP filtering.

This follows GitHub's recommendation for [delivering webhooks to private systems](https://docs.github.com/en/webhooks/using-webhooks/delivering-webhooks-to-private-systems).

### Configure GitHub App webhook URL

In your GitHub App settings, set the webhook URL to:

```
https://hibou.example.com/api/v1/webhooks/github
```

## Existing Secrets Reference

| Secret | Required Keys |
|--------|---------------|
| Session | `HIBOU_SESSION_SECRET` |
| Forge (index N) | `HIBOU_FORGE_N_CLIENT_ID`, `HIBOU_FORGE_N_CLIENT_SECRET`, optional `HIBOU_FORGE_N_WEBHOOK_SECRET`, `HIBOU_FORGE_N_APP_ID`, `HIBOU_FORGE_N_PRIVATE_KEY` |
| Database (external) | `url` (full `postgres://` connection string) |

The forge key index (0, 1, ...) must match the forge's position in the `forges[]` array.

## Step 3: Deploy Hibou

### Create namespace and secrets

```bash
kubectl create namespace hibou

kubectl create secret generic hibou-session -n hibou \
  --from-literal=HIBOU_SESSION_SECRET="$(openssl rand -hex 32)"

kubectl create secret generic hibou-forge-github -n hibou \
  --from-literal=HIBOU_FORGE_0_CLIENT_ID="<client-id>" \
  --from-literal=HIBOU_FORGE_0_CLIENT_SECRET="<client-secret>" \
  --from-literal=HIBOU_FORGE_0_WEBHOOK_SECRET="<webhook-secret>" \
  --from-literal=HIBOU_FORGE_0_APP_ID="<app-id>" \
  --from-file=HIBOU_FORGE_0_PRIVATE_KEY=<path-to-private-key.pem>
```

### Install with Helm

Keep the UI private if you want, but point your public ingress at the Hibou service.

```bash
helm install hibou ./chart/hibou -n hibou \
  -f values-production.yaml \
  --set hibou.sessionSecretExistingSecret=hibou-session \
  --set hibou.forges[0].type=github \
  --set hibou.forges[0].existingSecret=hibou-forge-github \
  --set hibou.baseURL=http://hibou.internal:8080 \
  --set hibou.forges[0].ipAllowlist=true \
  --set hibou.forges[0].rateLimitRPS=10 \
  --set ingress.enabled=true \
  --set ingress.hostname=hibou.example.com \
  --set ingress.className=nginx \
  --set ingress.tls.enabled=true \
  --set postgresql.auth.password="$(openssl rand -hex 16)"
```

Set `hibou.baseURL` to the internal address your browser uses for the OAuth callback.

### Access the UI

```bash
kubectl port-forward -n hibou svc/hibou 8080:8080
```

Open `http://localhost:8080` and log in with GitHub.

## Step 4: CI Pipeline (Security Scanning)

Use GitHub-hosted runners. Uploads go directly to the public Hibou URL. No VPN step.

### Workflow example

```yaml
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      # ... scanning steps unchanged ...
      - name: Upload to Hibou
        uses: ./.github/actions/hibou-upload
        with:
          server: ${{ secrets.HIBOU_SERVER_URL }}
          token: ${{ secrets.HIBOU_API_TOKEN }}
```

### Secret configuration

| Secret | Value | Example |
|--------|-------|---------|
| `HIBOU_SERVER_URL` | Public Hibou URL | `https://hibou.example.com` |
| `HIBOU_API_TOKEN` | API token from Hibou UI | `hbt_abc123...` |

### Generate an API token

1. Open Hibou UI
2. Login with GitHub
3. Go to Settings → API Keys → Create new key
4. Copy the token into the `HIBOU_API_TOKEN` GitHub Actions secret

## Step 5: Verify Everything Works

1. Ingress active: `kubectl get ingress -n hibou` shows the Hibou ingress
2. Middleware enabled: `kubectl logs deploy/hibou -n hibou | grep github-ip-allowlist` shows allowlist refresh
3. Push a commit: trigger the security scan workflow on `ubuntu-latest`
4. Check Hibou UI: findings appear in the repo Weaknesses tab
5. Test block: `curl -X POST https://hibou.example.com/api/v1/webhooks/github` from your machine returns 403 if your IP is not in GitHub ranges

## Resource Requirements

| Component  | Request        | Limit           |
|-----------|----------------|-----------------|
| Hibou     | 100m / 128Mi   | 500m / 512Mi    |
| PostgreSQL| 250m / 256Mi   | 1 CPU / 1Gi     |
| Trivy     | 100m / 256Mi   | 500m / 512Mi    |
| **Total** | **~450m / 640Mi** | — |

Fits a $5-10/mo VPS with k3s or a small managed K8s node pool.

## Feature Matrix

| Feature | Works? | How |
|---------|--------|-----|
| GitHub login (OAuth2) | ✅ | Browser redirects to GitHub, callback hits internal URL |
| Org/repo discovery | ✅ | Hibou calls GitHub API outbound via App installation tokens |
| Commit statuses on PRs | ✅ | Hibou calls GitHub API outbound |
| CI scan upload | ✅ | GitHub-hosted runner uploads to Hibou with API token auth |
| Webhooks (push/PR events) | ✅ | GitHub sends to Hibou ingress, IP allowlisted + HMAC-validated |
| GitHub-hosted runners | ✅ | Upload directly to Hibou public URL |

## Full Public Deployment (Alternative)

If you want the UI publicly accessible too, enable the
main ingress:

```bash
--set ingress.enabled=true \
--set ingress.hostname=hibou.example.com \
--set ingress.className=nginx \
--set ingress.tls.enabled=true \
--set 'ingress.annotations.cert-manager\.io/cluster-issuer=letsencrypt-prod'
```

This exposes the full UI. Built-in middleware still protects webhook routes.

## Self-Hosted Runners (Fallback)

If your cluster has no public IP at all, use self-hosted runners instead:

### Runner in Kubernetes (ARC)

```bash
helm install arc \
  --namespace arc-systems --create-namespace \
  oci://ghcr.io/actions/actions-runner-controller-charts/gha-runner-scale-set-controller

helm install arc-runner \
  --namespace arc-runners --create-namespace \
  oci://ghcr.io/actions/actions-runner-controller-charts/gha-runner-scale-set \
  --set githubConfigUrl="https://github.com/<your-org>" \
  --set githubConfigSecret.github_token="<PAT-or-App-token>"
```

Runners share the cluster network and reach Hibou directly. Change CI workflows
to `runs-on: self-hosted` and set `HIBOU_SERVER_URL` to the in-cluster DNS:
`http://hibou.hibou.svc.cluster.local:8080`.
