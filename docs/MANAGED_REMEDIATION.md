# Dependency remediation: local and Kubernetes execution

## Current status

**Managed execution is opt-in and disabled by default.** Do not install a nested
container runtime or add a runtime socket to a Hibou pod. The Kubernetes controller
uses the cluster's native Job API; the API pod has no Job authority and never
executes package managers.

[ADR-056](adr/056-secure-kubernetes-workload-execution.md) records the shared Job,
controller, user-namespace and transport design. The initial adapter supports
independent npm package-lock v3 modules through an approved internal mirror.
The [threat model](THREAT-MODEL.md) describes the implemented boundaries, residual
risks and required cluster qualification. Fake API/native fixture/chart tests do
not prove live admission, CNI or runtime enforcement.

Capabilities remain unavailable and preparation/generation return HTTP 503
unless an enabled installation has a live controller for its exact image,
toolchain and mirror profile. Historical runtime-controller heartbeats do not
count. Source SHA and profile are bound to drafts; changing the profile requires
new preparation. Existing artifact read, cancellation and publication retain their
state, verification, expiry and authorization checks independently.

The controller performs committed-data discovery without native tools, then
launches generation and a fresh verification Job. Inputs are bounded dependency
files over an authenticated HTTPS attempt broker, not controller bind mounts or
Git credentials. The controller independently reconstructs candidate patches and
rechecks source hashes, versions and advisory/policy decisions before storing a
ready artifact. A worker's `verified` flags do not authorize a patch or PR.

## Local IDE execution

Local-first VS Code remediation remains available through the shared CLI/LSP
engine after workspace trust and execution consent. The qualified initial
adapter supports independent public npm modules with committed `package.json`
and package-lock v3 inputs. It uses preinstalled Node/npm, temporary workspaces,
automatic/exact/Gossip choices, strict dependency-file verification and a
reviewed patch/apply step. It never silently installs tools, uploads source,
stages changes, commits or pushes.

Custom registries, private namespaces, aliases, workspaces, repository npmrc,
unqualified runtime pins and fully offline resolver closure remain unsupported
by that initial local profile. They fail explicitly, not by using another
manager or leaving a stale lockfile. Builds/application tests are not run.

A failed baseline check, relock, advisory/policy lookup or final verification
produces no ready patch. Managed regeneration from the IDE uses the same server
capabilities and separately reviewed publication flow as the website; it never
falls back to API-pod execution or uploads a local patch.

## Disconnected deployments

The Kubernetes mirror profile supports environments with **no public
Internet access**, using internal OCI registries and approved package mirrors
such as Artifactory/Nexus. The local IDE public-registry profile is unchanged;
it does not automatically inherit installation registry credentials.

Prepare exact-version toolchain images and their runtime layers ahead of jobs.
Also mirror the version/dependency metadata, archives, checksums, parent/plugin/
build-backend dependencies and advisory/policy evidence needed to resolve and
verify the selected changes. An executable image or tarball cache alone is not
an offline dependency closure.

Mirror-only means internal services are reachable; fully zero-network execution
requires a separate validated staging/collection profile. Both must fail on
missing data, unsupported profiles, failed integrity or stale mandatory evidence.
The implemented mirror profile never falls back to public registries, executable installers, live Gossip,
image tags or external signature services. See ADR-056 for trust, egress,
credentials, freshness and negative-test requirements.

The initial adapter supports public npm package identities acquired internally,
including approved mirror locations in lockfiles. Private namespaces, repository
registry overrides, workspaces/aliases and zero-network execution need separate
qualified adapters. Import complete advisory/package-signal evidence ahead of
time; missing/stale required approvals fail generation rather than call public
policy providers. Cached fresh Gossip recommendations may be used, but no live
Gossip lookup is performed by managed execution.

## Helm interface and installation

The chart follows existing release labels, resource and Secret conventions.
Two explicit switches separate the reusable execution facility from its initial
remediation adapter. Both default to false:

```yaml
workload:
  enabled: true
  namespace:
    create: true
    name: "" # default: release-derived dedicated execution namespace
  image: registry.internal/hibou-npm@sha256:<approved-64-hex-digest>
  imagePullSecrets:
    - name: internal-oci-auth
  runtimeClassName: your-qualified-userns-compatible-runtime
  runtimeValidated: true # only after the actual cluster qualification
  tls:
    existingSecret: hibou-workload-tls
  caBundle: |
    <public PEM CA bundle for the broker certificate>
managedRemediation:
  enabled: true
  registry:
    url: https://artifactory.internal/artifactory/api/npm/packages
    existingSecret: hibou-remediation-registry
    tokenEnabled: true
    caEnabled: true
  profile:
    npmPath: /usr/local/bin/npm
    npmVersion: "<exact npm --version output>"
    nodePath: /usr/local/bin/node
    nodeVersion: "<exact node --version output>"
    toolPath: /usr/local/bin:/usr/bin:/bin
```

Use normal values files/`helm upgrade --install`, not plaintext credentials in
`--set`, arbitrary Pod templates or runtime security-context overrides. The
registry Secret uses `token` and `ca.crt` by default, configurable through
`tokenKey`/`caKey`; it mounts only on the controller. Disable the corresponding
flag when the mirror needs neither bearer auth nor a private CA.
The TLS Secret uses `tls.crt`/`tls.key` in the application namespace and must
cover the controller Service DNS name. Supply it through the installation PKI
or certificate manager; the chart does not silently generate ephemeral trust.

`workload.imagePullSecrets` names existing pull credentials in the **execution
namespace**, not the application namespace. They are approved kubelet pull
references, never workload credential mounts or controller Secret-read authority.
Omit that list when no pull credential is needed. Internal OCI registry CA trust
must also be configured on the node/container runtime; the broker CA and npm
mirror CA do not configure image-pull trust.

For an existing execution namespace, set `workload.namespace.create: false`
and its explicit `name`. It must be dedicated, distinct from the application
namespace and have operator-managed restricted PSA labels. This is one execution
namespace per installation, not one per repository; Helm still manages the
release's scoped policies. Cluster-scoped native admission policy installation
requires appropriate installer rights, not additional controller rights.

Jobs require `hostUsers: false` with a fixed non-root UID, dropped capabilities,
read-only rootfs and no privilege escalation. There is no host-user/root fallback.
Qualify Linux kernel, idmapped volume filesystems, CRI/OCI runtime, RuntimeClass,
CNI and Kubernetes version as described in ADR-056. Tune bounded class resources
under `workload.job.resources`, controller resources under
`workload.controller.resources`, `workload.deadlineSeconds`, namespace job/pod
quotas and the explicit DNS policy; do not broaden workload egress to fix a
mirror or TLS error.

The controller needs the same private artifact backend as the API. Prefer the
existing S3 configuration/Secret interface; filesystem mode needs the supported
shared RWX PVC and matching safe mount path. Controller failures, cleanup backlog,
quota exhaustion and missing mirrored images/packages must be observable.
Helm lint/template validation does not replace the live negative tests in ADR-056.
The initial broker uses one controller replica with non-overlapping replacement;
do not attach an HPA or manually scale that Deployment. Restart recovery uses
durable leases and attempt fencing, not shared in-memory sessions.

Build the workload image ahead of jobs using
[Dockerfile.workload](../Dockerfile.workload) and an approved internal toolchain
base containing Git, Node and npm. Import the resulting digest, SBOM and required
layers into the internal registry. Neither image execution nor this recipe
bootstraps tools at job runtime.

## Preserved managed API contract

Paths are below
`/api/v1/orgs/{provider}/{slug}/repos/{repoSlug}/remediation`.
These interfaces use installation-managed execution, not per-repository CI.

* `GET /capabilities`: explicit execution readiness and caller permissions,
  maintenance settings and publication conditions.
* `POST /prepare`: returns 202 when ready, or **503 after authorization with no
  enqueue** when unavailable. The
  source contract has optional release, existing target branch, explicit
  maintenance mode, canonical advisory IDs and branch `expected_head_sha`.
  Future activation must retain immutable-source and stale-head rejection.
* `GET /{id}`: authorized draft phase/summary; expired objects are not ready.
* `POST /{id}/generate`: returns 202 when ready, or **503 after authorization with
  no enqueue** when unavailable. The selection contract uses a revision, server-owned unit IDs,
  permitted upgrade ceilings and exact/Gossip version targets.
* `POST /{id}/cancel`: revoke a claim, terminate/fence active work and schedule
  private cleanup. The controller reconciles expiry and cleanup every 30 seconds.
* `GET /{id}/patch`: current authorized, verified, unexpired artifact only.
* `PUT /consent`: organization-wide admin-only branch/PR consent. Consent
  does not enable an execution backend.
* `POST /{id}/publish`: separately authorized current-revision branch/PR
  publication for a ready verified artifact, never arbitrary client patches.

Migrations `00079_managed_remediation`, `00080_remediation_artifact_expiry` and
`00081_remediation_workload_identity` persist job/artifact state and immutable
fenced Job/Pod identities. A matching live heartbeat is readiness evidence, not
permission to bypass caller authorization or a proof of node isolation.

## Branch and pull request boundary

Publication requires current repository admin authorization and mutation
capability, explicit organization consent, a GitHub App propose-tier installation
with contents/PR write permissions, live immutable repository identity and an
unchanged target head. Exact-release source must not silently rebase.

The proposal branch uses `hibou/fix-<target>-<digest>` with one slash.
Publication creates a complete Git tree/commit and an atomic ref, without
file-by-file partial commits, force updates or overwriting user work. Intents
and outcomes are audited; retries reconcile deterministic refs/PRs. No
automatic merge, release tag, package/image or release publishing occurs.
Local artifact upload is not an implemented publication path.

## Maintenance mappings and creation

Organization-wide administrators may configure explicit release-tag mappings
through `GET/PUT /maintenance-settings`:

```json
{
  "allow_creation": true,
  "mappings": [
    {
      "id": "line-1-2",
      "tag_pattern": "v1.2.*",
      "target_template": "support/{major}.{minor}"
    }
  ]
}
```

These are not dependency-inventory branch patterns. Suggestions from
`GET /maintenance-targets?release_id=<UUID>` include source tag/SHA, matching
mapping, current target and ancestry evidence. Unverified evidence requires
explicit choice; selecting a suggestion does not execute a workload.

Maintenance creation remains disabled by default. The operator's independent
`HIBOU_REMEDIATION_MAINTENANCE_BRANCH_ALLOWLIST`, or Helm
`managedRemediation.maintenanceBranchAllowlist`, must allow the new name.
This only permits a confirmed create operation, never general writes outside
`hibou/`. Organization creation consent, branch/PR consent, caller permission,
App permission and exact release/snapshot/tag identity are all rechecked.

`POST /maintenance-targets` takes `release_id`, `mapping_id`, `target_branch`,
`source_tag` and `source_sha`. Names/tag sources are confirmed; existing branches
are not repointed and moved/missing tags fail. Durable creation intents allow
safe reconciliation only at the same exact source SHA. This forge operation
is independent of package-manager execution and does not start generation.
