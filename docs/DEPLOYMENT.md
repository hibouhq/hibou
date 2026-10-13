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
| Organization → Members | Read-only | Org membership info; also answers the `auth.allowed_orgs` sign-in allowlist |

Login asks the user only for `read:user user:email`. Hibou never requests the
`repo` scope: repositories are read with the App installation token, and when
the Client ID is the GitHub App's own (recommended), GitHub ignores OAuth scopes
and applies the App permissions above.

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
| Forge (index N) | `HIBOU_FORGE_N_CLIENT_ID`, `HIBOU_FORGE_N_CLIENT_SECRET`, `HIBOU_FORGE_N_WEBHOOK_SECRET`, `HIBOU_FORGE_N_APP_ID`, `HIBOU_FORGE_N_PRIVATE_KEY` |
| Database (external) | `url` (full `postgres://` connection string) |

The forge key index (0, 1, ...) must match the forge's position in the `forges[]` array.

Use one stable `HIBOU_SESSION_SECRET` value across every Hibou replica. Rotating that secret invalidates all existing `hibou_session` and `hibou_oauth_state` cookies, so active browser sessions are logged out and in-flight OAuth logins must restart.
Production is strict by default: if `HIBOU_SESSION_SECRET` / `session.secret` is empty, shorter than 32 bytes, or left at the shipped `change-me-in-production` default, Hibou exits during startup unless you explicitly opt into local development with `HIBOU_DEVELOPMENT=true` or `development: true`. Do not set that flag in production.

Outside development Hibou also refuses to start when a declared forge has no
`HIBOU_FORGE_N_CLIENT_ID` or no `HIBOU_FORGE_N_WEBHOOK_SECRET`: webhooks are
accepted only with a valid signature (GitHub, Forgejo) or token (GitLab).
Bodies over 25 MB are refused, and a delivery replayed within an hour (same
delivery id or identical body) is acknowledged without being processed again.
The replay window is per replica. In development a secret-less forge is
accepted with a warning on every delivery, and `/api/v1/auth/dev-login` exists
only in development with no forge configured.

### Sessions

Sessions are host-only cookies (no `Domain` attribute). Over HTTPS the cookies
are named `__Host-hibou_session` / `__Host-hibou_oauth_state`; over plain HTTP
(local development) they keep the bare names. Logging out revokes every session
of that user on every device (a per-user session epoch is signed into the
cookie). Sessions issued before this change are invalid: users sign in once
more after the upgrade. Login uses PKCE (S256).

State-changing requests authenticated by the session cookie are refused when
the browser marks them cross-site (`Sec-Fetch-Site`) or their `Origin` differs
from `HIBOU_BASE_URL`. Bearer-token requests and webhooks are not affected.
To serve the UI on more than one hostname, list the others in
`HIBOU_ALLOWED_ORIGINS` (`allowed_origins`, comma-separated
`scheme://host[:port]`; chart: `hibou.allowedOrigins`).

### Secure defaults and startup checks

Outside development (`HIBOU_DEVELOPMENT` unset), `hibou serve` refuses to
start when:

- `HIBOU_BASE_URL` is empty or not an absolute `http(s)` URL. Without it
  cookies are not `Secure` and lose the `__Host-` prefix. The chart derives it
  from `ingress.hostname`; without an ingress set `hibou.baseURL`.
- `/metrics` would be served on the application port without a bearer token
  (`metrics.port: 0` and no `metrics.bearer_token`). `/metrics` now defaults
  to its own port, `9090`, as in the chart. Scrapers that read it on the
  application port must move to `:9090` or send the token.
- the dedicated metrics port listens on a non-loopback address (`host`
  defaults to `0.0.0.0`) without `metrics.bearer_token(_file)`. Set a token,
  bind `host` to loopback, or, when the port is unreachable from untrusted
  networks (a Kubernetes pod port the ingress does not forward, ideally with
  `hibou.metrics.networkPolicy`), opt out with `metrics.require_token: false`
  (`HIBOU_METRICS_REQUIRE_TOKEN=false`).

Defaults that changed for self-hosting:

| Setting | Default | Note |
|---------|---------|------|
| `mcp.enabled` (`HIBOU_MCP_ENABLED`) | value of `development` | Plain HTTP on `mcp.port` (8081), all interfaces |
| `api.docs.enabled` (`HIBOU_API_DOCS_ENABLED`) | value of `development` | Swagger UI at `/api/v1/docs` (inline script, relaxed CSP); 404 when off |
| `metrics.port` (`HIBOU_METRICS_PORT`) | `9090` | `0` = application port, needs a bearer token outside development |
| `metrics.require_token` (`HIBOU_METRICS_REQUIRE_TOKEN`) | `true` | `false` lets the metrics port listen on all interfaces without a token |
| Chart `hibou.image.tag` | chart `appVersion` | Was `latest` |
| Chart `trivy.image.tag` | `0.72.0` | Was `latest`; Trivy and PostgreSQL now run non-root with a read-only root filesystem |
| Chart `hibou.autoProvisionOrgs` | `false` | When on, installing the forge App on any account creates an org; pair it with a sign-in allowlist |
| Chart `hibou.mcp.enabled` | `false` | |

`hibou.networkPolicy.enabled` stays `false` because it needs a CNI that
enforces NetworkPolicy. Enable it wherever yours does: besides the default-deny
policy for hibou pods it admits only hibou pods to the bundled SeaweedFS S3
port. SeaweedFS master, volume and filer listen on the pod's loopback only
either way. `helm install` prints a warning when the sign-in allowlists are
empty.

### Uploads

`POST /api/v1/upload` must send `Content-Length` (411 otherwise; the hibou
CLI and `curl --data-binary @file` do). It is admitted before it waits for one
of `upload.max_concurrent` slots (default 3 per replica) only when the caller
can upload somewhere: an API token with `uploads:write`, or a user who belongs
to an organization. One user or API key holds at most
`upload.max_concurrent_per_principal` uploads (default 2), and one org
`upload.max_concurrent_per_org` (default 2) across its service tokens and its
members (a user's upload counts against each of their orgs, since the target
org is only known from the body). Both are lowered to `upload.max_concurrent`
− 1 when set higher, so one principal or org always leaves a slot free. The
rest wait up to `upload.queue_wait` and then get 429 with `Retry-After` (the
CLI retries). Until admitted to a slot the request is under
`http.read_timeout`; once admitted, the body gets `Content-Length` at
64 KiB/s, at least 60s and at most `http.upload_read_timeout` (15m), and a
body that delivers less than `upload.min_throughput_bytes` (64 KiB) in any
`upload.min_throughput_window` (10s) is cut off.

The websocket (`/api/v1/ws`) lifts the server read/write timeouts only after
its session is validated, and a handshake with a body is refused (400). The
anonymous CLI download (`/api/v1/bin/…`) may take 10 minutes; authenticated
file downloads one hour.

### Client IP behind a CDN

Hibou takes the client IP from `X-Forwarded-For`, `http.forwarded_hops`
(`HIBOU_HTTP_FORWARDED_HOPS`, default `1`) entries from the right: with one
ingress that is the address the ingress saw. Set it to the number of proxies
that append to the header, or to `0` when nothing sits in front of hibou
(the TCP peer is used and `X-Forwarded-For` is ignored). With `1` or more,
anyone who can reach hibou without passing the proxy (a NodePort, the pod IP,
a second listener) chooses their own IP for rate limits, the audit log and
webhook IP allowlists: keep the application port reachable only through the
proxy, or use `0`.

Rate-limit buckets are per IPv4 address and per IPv6 /64. A client IP whose
bearer tokens fail authentication more than `rate_limit.auth` allows gets 429
before the token is looked up; requests without a token are not affected.

Behind a CDN, the hop your ingress saw is a CDN edge, so every client shares
its rate-limit bucket, audit IP and webhook IP-allowlist verdict. Set:

| Setting | Env | Chart |
|---------|-----|-------|
| `http.trusted_proxy_header` | `HIBOU_HTTP_TRUSTED_PROXY_HEADER` | `hibou.trustedProxy.header` |
| `http.trusted_proxy_cidrs` | `HIBOU_HTTP_TRUSTED_PROXY_CIDRS` (comma-separated) | `hibou.trustedProxy.cidrs` |

e.g. `CF-Connecting-IP` with Cloudflare's published ranges. The header is
used only when the hop is inside the CIDRs, so a client that bypasses the CDN
cannot choose its IP. Both are required together; off by default.

### Restricting sign-in

By default any account of a configured forge can sign in. To restrict it:

| Setting | Env | Meaning |
|---------|-----|---------|
| `auth.allowed_orgs` | `HIBOU_AUTH_ALLOWED_ORGS` (comma-separated) | Members of these forge orgs may sign in |
| `auth.allowed_users` | `HIBOU_AUTH_ALLOWED_USERS` (comma-separated) | These forge logins, or `provider:id` entries (e.g. `github:12345`), may sign in |

With either set, anyone else is refused in the OAuth callback before a user
row is created, and sent back to the login page with a "not allowed" notice.
Matching is case-insensitive.

The allowlist is also enforced after sign-in, on sessions, personal API keys
and MCP: an org membership answer is re-checked every 24 hours, and a user
stays allowed for at most 7 days while the forge cannot answer. Forge
memberships themselves are re-validated hourly; members the forge no longer
lists lose their Hibou membership.

- `allowed_orgs` works on GitHub only. In App mode membership is checked with
  the App's installation token on that org
  (`GET /orgs/{org}/members/{login}`), using the **Organization → Members:
  read** permission listed above, so the App must be installed on every
  allowed org and users grant nothing extra. Without App credentials (plain
  OAuth App), login additionally requests `read:org` and checks the user's own
  membership (state must be `active`). If the check fails, sign-in is refused.
- GitLab and Forgejo: only `allowed_users` applies; their users must be
  listed by login.
- A login can be renamed and then re-registered by someone else. Prefer
  `allowed_orgs`, or a numeric `provider:id` entry, where you can.

### Integration secrets at rest

Integration secrets (webhook URLs, signing secrets, SMTP passwords, tokens)
are write-only through the API: responses show `"***"`, and an update that
omits or echoes `"***"` keeps the stored value — except when the update
changes where those secrets are sent. Changing `smtp_host`, `smtp_port` or
`smtp_username` of an email integration, or `url` / `webhook_url` of a
webhook, Slack, Teams or Discord integration, while keeping another stored
secret is refused with HTTP 422 (`re-enter <field> when changing
<destination>`): send the secret again, or `""` to clear it.

Notification-rule `destination_config` only selects integrations, by
non-secret fields or by `integration_id`. Credential fields (`url`,
`webhook_url`, `secret`, `smtp_password`, `password`, `token`, `api_key`) are
refused there with HTTP 422, including in dry-run, so a rule cannot be used
to test guesses of an integration's secrets. Rules stored before this check
keep working, but their credential fields are ignored for matching (logged
as a warning); edit them to use `integration_id`.

Set `HIBOU_ENCRYPTION_KEY` (`encryption.key`) to a base64 32-byte key
(`openssl rand -base64 32`) to seal them with AES-GCM in the database. Sealed
values (`enc:v2:`) are bound to their organization, row and field: copied
into another row they do not decrypt. Values sealed by earlier versions
(`enc:v1:`) and plaintext values stay readable and are re-sealed on their
next update. Keep the key with your other secrets: losing it makes sealed
values unreadable, and those integrations must be re-entered. A malformed
key refuses startup.

Generic webhook deliveries from an integration with a `secret` carry
`X-Hibou-Timestamp` (unix seconds) and `X-Hibou-Signature-256:
sha256=<hex HMAC-SHA256(secret, timestamp + "." + body)>`. Receivers should
verify that signature and reject timestamps more than a few minutes old,
which bounds replay of a captured delivery. The older
`X-Hibou-Signature: sha256=<hex HMAC-SHA256(secret, body)>` is still sent for
existing receivers but does not protect against replay; it is deprecated.

### Secret-finding hashes

Secret findings store a keyed hash (HMAC-SHA256) of the secret, never the
secret. The key comes from `HIBOU_SECRET_HASH_KEY` (`secret_hash.key`) when
set, otherwise it is derived from `HIBOU_SESSION_SECRET`. Use the same value
on every replica and worker. Changing the key in effect — or the session
secret while `HIBOU_SECRET_HASH_KEY` is unset — changes the hash, and with
it the fingerprint of secret findings that have no line number: they are
reported once as new findings and the previous ones resolve. To rotate the
session secret without that, first set `HIBOU_SECRET_HASH_KEY` to the
current session secret value, then rotate the session secret.

Per-account caps: 10 organizations created, 50 API keys (personal and
org-requested together), 100 saved search presets per surface (HTTP 422, or
400 for presets). Organizations can only be created for a forge configured on
the instance (HTTP 400 otherwise).

### Instance administrators

`HIBOU_INSTANCE_ADMINS` / `HIBOU_INSTANCE_ADMINS_FILE` entries are either
`provider:provider_id` (recommended; for GitHub the numeric account id, e.g.
`github:1234567` from `https://api.github.com/users/<login>`) or emails. An
email entry only matches GitHub accounts: GitLab and Forgejo report a profile
email Hibou cannot treat as verified.

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

Supported chart combinations:

- Single replica or local development: `artifact.backend=filesystem` is acceptable.
- Multi-replica Hibou or worker deployments: use the bundled SeaweedFS default or another shared S3-compatible backend, and keep one shared session secret across all replicas.
- Unsupported: more than one Hibou or worker replica with filesystem artifact storage on ephemeral pod disk or a non-RWX PVC.

Probe defaults are split intentionally: liveness stays on `/api/v1/health`, while readiness uses `/api/v1/ready` so pods stop receiving traffic when PostgreSQL is unavailable without being killed for a transient dependency outage.

### Artifact storage options

Artifact bytes are never stored in PostgreSQL. PostgreSQL keeps control-plane state, coordination, and metadata only. Raw uploaded bytes live in one of three operator-selectable stores; see [ADR-015](adr/015-stateless-processing-and-worker-scaling.md) for the architecture rationale.

Bundled default: SeaweedFS.

- The chart enables bundled SeaweedFS by default.
- SeaweedFS is Hibou's default shared artifact store for Helm and multi-replica deployments.
- SeaweedFS uses its own ReadWriteOnce PVC, so it works on clusters that only provide block storage.

External S3-compatible endpoint: configuration only.

- Disable bundled SeaweedFS and set `artifact.backend=s3` plus `artifact.s3.*` values to target any S3-compatible endpoint with no code change.
- Supported examples include Ceph RGW, AWS S3, RustFS, SeaweedFS, and other compatible APIs.
- Policy: AWS is never the default, but operators may configure it.
- Policy: MinIO is never bundled and never the default.
- RustFS stays a watch-list option until stable GA.

Optional shared filesystem: operator-managed RWX PVC.

- Operators who already run a ReadWriteMany provisioner may keep `artifact.backend=filesystem` and enable `artifact.filesystem.persistence.enabled=true`.
- Multi-replica filesystem is supported only when that PVC uses `artifact.filesystem.persistence.accessMode=ReadWriteMany`.
- Leaving filesystem storage on ephemeral pod disk remains single-replica only.

Example: external S3-compatible endpoint.

```yaml
seaweedfs:
  enabled: false

artifact:
  backend: s3
  s3:
    endpoint: https://rgw.example.internal
    region: us-east-1
    bucket: hibou-artifacts
    existingSecret: hibou-artifact-s3
    usePathStyle: true
    useSSL: true
```

Example: optional RWX filesystem backend.

```yaml
seaweedfs:
  enabled: false

artifact:
  backend: filesystem
  path: /data/artifacts
  filesystem:
    persistence:
      enabled: true
      accessMode: ReadWriteMany
      size: 50Gi
      storageClass: nfs-rwx
```

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

## Upgrade Notes

### Sign-in allowlist: every user signs in once (03e6042 and later)

With `auth.allowed_orgs` or `auth.allowed_users` configured, the allowlist is
also enforced after sign-in, on sessions, API keys and MCP (see "Restricting
sign-in"). That check uses the forge login recorded at sign-in, which users who
last signed in before this version do not have yet. Until they sign in once
through the web UI, their existing sessions, API keys (CI uploads included) and
MCP clients are refused. After upgrading, ask every user to sign in once, and
check CI tokens owned by users who rarely use the UI. `allowed_users` entries
of the form `provider:id` match without a recorded login.

### Helm chart: NetworkPolicies on the bundled services

The chart now renders ingress NetworkPolicies for the bundled SeaweedFS
(always), PostgreSQL and Trivy (`postgresql.networkPolicy.enabled`,
`trivy.networkPolicy.enabled`, both default `true`), independent of
`hibou.networkPolicy.enabled`. Only hibou server and worker pods (and the
SeaweedFS bucket job) are admitted. Anything else that connects to them, such
as a backup job or an admin tool, must be listed in
`<service>.networkPolicy.extraFrom`. The SeaweedFS policy closes the S3
gateway's gRPC port (8333+10000), which accepts unauthenticated IAM updates
and cannot be bound to loopback separately; it is effective only with a CNI
that enforces NetworkPolicy.

Other chart changes in the same release:

- Bundled images default to `tag@sha256:digest`. Overriding only `tag` with a
  plain tag drops the digest pin.
- `hibou.mcp.port` (default 8081) is exposed as the `mcp` container port. With
  `hibou.networkPolicy.enabled`, it is admitted from
  `hibou.networkPolicy.mcpFrom` (default: the release namespace).
- `hibou.networkPolicy.enabled` with `hibou.metrics.podMonitor.enabled` now
  fails to render unless `hibou.metrics.networkPolicy` is enabled too, because
  the default-deny policy would otherwise block every scrape.

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
| Webhooks (push/PR/build events) | ✅ | GitHub sends to Hibou ingress, IP allowlisted + HMAC-validated. Enable the build event (`workflow_run` on GitHub, `Pipeline Hook` on GitLab, `workflow_run` on Forgejo) so a pipeline that dies before uploading fails its snapshot immediately instead of waiting out the stale-pending window. |
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
