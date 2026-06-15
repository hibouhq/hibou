# Hibou Dogfood Runbook (Scaleway)

This runbook deploys Hibou v0.1.0 onto the single-node Scaleway k3s host in `infra/scaleway/`, then wires the `hibouhq/hibou` repository back into that deployment for dogfooding.

Set these shell variables first and reuse them through the runbook:

```bash
export HIBOU_VERSION=v0.1.0
export HIBOU_DOMAIN=hibou.example.com
export HIBOU_NAMESPACE=hibou
```

## Phase 1: Generate Release

1. Create the first release from `main`:

```bash
gh release create v0.1.0 --generate-notes --target main
```

2. What CI does automatically after the release is published:
   - Runs the main `CI` workflow because `.github/workflows/ci.yml` triggers on the `release` event with type `published`.
   - Builds and tests in the devcontainer.
   - Generates binaries under `dist/hibou-*`.
   - Updates the existing GitHub Release with those binaries.
   - Builds and pushes a multi-arch image to `ghcr.io/hibouhq/hibou:0.1.0`, `ghcr.io/hibouhq/hibou:0.1`, and `ghcr.io/hibouhq/hibou:sha-<short>`.
   - Publishes the Helm chart to `oci://ghcr.io/hibouhq/charts/hibou` with OCI annotations, tagged `0.1.0`.
   - Signs pushed image tags with `cosign`.
   - Generates image SBOM and Trivy scan output.

   Note: CI also publishes images on every push to `main` with `sha-<short>` tags and charts with `0.0.0-sha-<short>`.

3. Verify the release succeeded:

```bash
gh run list --workflow CI --limit 5
gh release view v0.1.0
docker manifest inspect ghcr.io/hibouhq/hibou:0.1.0 >/dev/null
```

Check that the GitHub Release contains the `dist/hibou-*` artifacts and the image tag exists in GHCR.

## Phase 2: Scaleway Account Setup

1. Create a Scaleway account at https://console.scaleway.com/.
2. Create an API key in IAM -> API Keys. You need:
   - Access Key (`SCW_ACCESS_KEY`)
   - Secret Key (`SCW_SECRET_KEY`)
   - Default Project ID (from Organization -> Settings)
3. Generate a dedicated SSH keypair if needed:

```bash
ssh-keygen -t ed25519 -C "hibou-dogfood" -f ~/.ssh/id_ed25519_hibou
```

4. Keep these ready:
   - Access Key
   - Secret Key
   - Project ID
   - SSH public key path, for example `~/.ssh/id_ed25519_hibou.pub`
   - Domain name that will point at the server

## Phase 3: Provision Server

1. Prepare Terraform variables:

```bash
cd /workspaces/new_project/infra/scaleway
cp terraform.tfvars.example terraform.tfvars
```

2. Edit `terraform.tfvars` and fill at least:
   - `scw_access_key`
   - `scw_secret_key`
   - `scw_project_id`
   - `ssh_public_key_path`
   - `server_name`
   - `zone`
   - `ssh_allowed_ips`
   - `enable_k8s_api_access = true`

`enable_k8s_api_access = true` is the simplest option for remote `kubectl`. Restrict `ssh_allowed_ips` to your trusted source CIDRs before enabling it.

3. Provision the server:

```bash
make deploy
```

4. Fetch kubeconfig:

```bash
make kubeconfig
export KUBECONFIG=$PWD/kubeconfig.yaml
```

5. Verify the server and k3s:

```bash
terraform output -raw server_ip
kubectl get nodes -o wide
kubectl get pods -A
```

6. Point DNS at the server IP:
   - Create an `A` record for `$HIBOU_DOMAIN`
   - Set it to the `server_ip` Terraform output
   - Since your domain is on Scaleway, you can create the A record directly in the Scaleway DNS console.
   - Check scaleway DNS return the right IP `dig +short "$HIBOU_DOMAIN" @ns0.dom.scw.cloud`
   - Wait until `dig +short "$HIBOU_DOMAIN"` returns the server IP

## Phase 4: Deploy Hibou

1. Install cert-manager:

```bash
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.17.2/cert-manager.yaml
kubectl rollout status deploy/cert-manager -n cert-manager --timeout=180s
kubectl rollout status deploy/cert-manager-webhook -n cert-manager --timeout=180s
kubectl rollout status deploy/cert-manager-cainjector -n cert-manager --timeout=180s
```

2. Apply the ClusterIssuer after replacing the hostname placeholder email:

```bash
sed "s/HIBOU_DOMAIN/${HIBOU_DOMAIN}/g" /workspaces/new_project/infra/dogfood/cluster-issuer.yaml | kubectl apply -f -
kubectl get clusterissuer letsencrypt-prod
```

3. Create namespace and secrets:

```bash
kubectl create namespace "$HIBOU_NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -

export HIBOU_SESSION_SECRET="$(openssl rand -hex 32)"

kubectl create secret generic hibou-session \
  -n "$HIBOU_NAMESPACE" \
  --from-literal=HIBOU_SESSION_SECRET="$HIBOU_SESSION_SECRET" \
  --dry-run=client -o yaml | kubectl apply -f -

export HIBOU_DB_PASSWORD="$(openssl rand -hex 24)"

kubectl create secret generic hibou-db-url \
   -n "$HIBOU_NAMESPACE" \
   --from-literal=password="$HIBOU_DB_PASSWORD" \
   --from-literal=url="postgres://hibou:${HIBOU_DB_PASSWORD}@hibou-postgresql:5432/hibou?sslmode=disable" \
   --dry-run=client -o yaml | kubectl apply -f -
```

4. Install or upgrade Hibou:

```bash
sed "s/HIBOU_DOMAIN/${HIBOU_DOMAIN}/g" /workspaces/new_project/infra/dogfood/values-dogfood.yaml > /tmp/hibou-values-dogfood.yaml

helm upgrade --install hibou /workspaces/new_project/chart/hibou \
  -n "$HIBOU_NAMESPACE" \
   -f /tmp/hibou-values-dogfood.yaml
```

Dogfood expects a pre-created `hibou-db-url` Secret with both `url` and `password` keys. Helm uses that secret for the application database URL and, when bundled PostgreSQL is enabled, the PostgreSQL StatefulSet also reads `POSTGRES_PASSWORD` from the same secret. That keeps the password out of Git while still letting Argo CD render from `infra/dogfood/values-dogfood.yaml` after bootstrap.

5. Verify workloads:

```bash
kubectl get pods -n "$HIBOU_NAMESPACE"
kubectl get svc,ingress -n "$HIBOU_NAMESPACE"
kubectl rollout status deploy/hibou -n "$HIBOU_NAMESPACE" --timeout=180s
kubectl rollout status statefulset/hibou-postgresql -n "$HIBOU_NAMESPACE" --timeout=180s
```

6. Verify TLS:

```bash
kubectl get certificate -n "$HIBOU_NAMESPACE"
kubectl describe certificate hibou-tls -n "$HIBOU_NAMESPACE"
curl -I "https://${HIBOU_DOMAIN}"
```

## Phase 4.5: Recommended Argo CD Control Loop

After the first bootstrap, prefer Argo CD for ongoing dogfood deploys from `main`.

Recommended control loop:

- Argo CD tracks Git `main` from `https://github.com/hibouhq/hibou.git` for `chart/hibou` and `infra/dogfood/values-dogfood.yaml`. Template changes, chart dependency changes, and committed dogfood values changes reconcile from Git.
- Argo CD Image Updater tracks `ghcr.io/hibouhq/hibou`, selects the newest allowed `sha-<short>` tag built from `main`, and writes that tag back to the Argo CD `Application` object with an Argo CD parameter override.
- Keep Git as the source of truth for chart/templates and baseline dogfood values on `main`. In this setup, `infra/dogfood/values-dogfood.yaml` is not mutated automatically when the running image tag changes.
- OCI charts in `oci://ghcr.io/hibouhq/charts/hibou` remain appropriate for immutable releases such as `v0.1.0`, but they should not be the primary dogfood source for `main` because dogfood needs the mutable branch chart/templates.

Example `Application`:

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
   name: hibou-dogfood
   namespace: argocd
   annotations:
      argocd-image-updater.argoproj.io/image-list: hibou=ghcr.io/hibouhq/hibou
      argocd-image-updater.argoproj.io/write-back-method: argocd
      argocd-image-updater.argoproj.io/hibou.allow-tags: regexp:^sha-[0-9a-f]{7}$
      argocd-image-updater.argoproj.io/hibou.update-strategy: newest-build
      argocd-image-updater.argoproj.io/hibou.helm.image-tag: hibou.image.tag
spec:
   project: default
   source:
      repoURL: https://github.com/hibouhq/hibou.git
      targetRevision: main
      path: chart/hibou
      helm:
         valueFiles:
            - ../../infra/dogfood/values-dogfood.yaml
   destination:
      server: https://kubernetes.default.svc
      namespace: hibou
   syncPolicy:
      automated:
         prune: true
         selfHeal: true
      syncOptions:
         - CreateNamespace=true
```

   With `argocd-image-updater.argoproj.io/write-back-method: argocd`, Image Updater patches the live `Application` resource instead of committing a new `hibou.image.tag` into `infra/dogfood/values-dogfood.yaml` on `main`.

This removes the old Argo CD password-injection blocker without committing the password: bootstrap creates `hibou-db-url` once, then Argo CD can render and sync from Git plus that pre-created secret. Tradeoff: dogfood PostgreSQL persistence is disabled, so data survives normal syncs and ordinary container restarts in the same pod, but is lost when the PostgreSQL pod is deleted and recreated, evicted, or rescheduled/replaced. That makes the database ephemeral, not guaranteed to reset on every Argo CD sync.

## Phase 5: GitHub App Setup

1. Create a GitHub App at https://github.com/settings/apps/new with:
   - App name: `hibou-dogfood`
   - Homepage URL: `https://$HIBOU_DOMAIN/`
   - Callback URL: `https://$HIBOU_DOMAIN/api/v1/auth/callback?provider=github`
   - Webhook URL: `https://$HIBOU_DOMAIN/api/v1/webhooks/github`
   - Webhook secret: generate and save a random secret

2. Grant repository permissions:
   - Metadata: Read-only
   - Contents: Read and write
   - Pull requests: Read and write
   - Commit statuses: Read and write

3. Subscribe to webhook events:
   - Push
   - Pull request

4. Generate and save these GitHub App credentials:
   - App ID
   - Client ID
   - Client secret
   - Private key PEM
   - Webhook secret

5. Create the forge secret expected by the Helm chart:

```bash
export GITHUB_APP_ID="<app-id>"
export GITHUB_APP_CLIENT_ID="<client-id>"
export GITHUB_APP_CLIENT_SECRET="<client-secret>"
export GITHUB_APP_WEBHOOK_SECRET="<webhook-secret>"

kubectl create secret generic hibou-forge-github \
  -n "$HIBOU_NAMESPACE" \
  --from-literal=HIBOU_FORGE_0_TYPE=github \
  --from-literal=HIBOU_FORGE_0_ID=github \
  --from-literal=HIBOU_FORGE_0_CLIENT_ID="$GITHUB_APP_CLIENT_ID" \
  --from-literal=HIBOU_FORGE_0_CLIENT_SECRET="$GITHUB_APP_CLIENT_SECRET" \
  --from-literal=HIBOU_FORGE_0_WEBHOOK_SECRET="$GITHUB_APP_WEBHOOK_SECRET" \
  --from-literal=HIBOU_FORGE_0_APP_ID="$GITHUB_APP_ID" \
  --from-file=HIBOU_FORGE_0_PRIVATE_KEY=./hibou-dogfood.private-key.pem \
  --from-literal=HIBOU_FORGE_0_IP_ALLOWLIST=true \
  --dry-run=client -o yaml | kubectl apply -f -
```

6. Enable the forge config in the Helm values:
   - Uncomment the `hibou.forges` example in `infra/dogfood/values-dogfood.yaml`
   - Keep `existingSecret: hibou-forge-github`

7. Re-run the Helm upgrade:

```bash
sed "s/HIBOU_DOMAIN/${HIBOU_DOMAIN}/g" /workspaces/new_project/infra/dogfood/values-dogfood.yaml > /tmp/hibou-values-dogfood.yaml

helm upgrade --install hibou /workspaces/new_project/chart/hibou \
  -n "$HIBOU_NAMESPACE" \
   -f /tmp/hibou-values-dogfood.yaml
```

8. Open `https://$HIBOU_DOMAIN/`, sign in with GitHub, and install the GitHub App on `hibouhq/hibou`.

## Phase 6: Enable Dogfooding Loop

1. In the Hibou UI, sign in as an admin user and create an API token.
2. In the `hibouhq/hibou` repository settings, add these Actions secrets:
   - `HIBOU_SERVER_URL=https://$HIBOU_DOMAIN`
   - `HIBOU_API_TOKEN=<token from Hibou UI>`

3. Trigger CI to verify uploads work. Either rerun the latest main branch workflow or push an empty commit:

```bash
gh workflow run ci.yml --ref main
```

Or:

```bash
git checkout main
git pull --ff-only origin main
git commit --allow-empty -m "test: verify hibou dogfood upload"
git push origin main
```

4. Watch the workflow and confirm the `Upload to Hibou` step runs instead of being skipped.

## Phase 7: Verify

1. Open the Hibou UI and confirm the `hibouhq/hibou` repository appears.
2. Open the latest snapshot and verify these artifact types are present:
   - Go coverage (`coverage.out`)
   - Frontend coverage (`site/coverage/lcov.info`)
   - SARIF (`gosec.sarif`, `trivy-fs.sarif`)
   - SBOM (`go-sbom.cdx.json`, `frontend-sbom.cdx.json`)
3. Confirm repository pages show imported findings and associated repo metadata.
4. Confirm HTTPS works without browser warnings and the ingress presents a Let's Encrypt certificate.

## Operational Notes

- Release image tag for this deployment: `ghcr.io/hibouhq/hibou:0.1.0`
- k3s ingress class expected by this setup: `traefik`
- The public API callback path is `/api/v1/auth/callback`
- The public webhook path is `/api/v1/webhooks/github`
