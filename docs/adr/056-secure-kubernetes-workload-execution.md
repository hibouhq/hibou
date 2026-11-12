# ADR-056: Secure Kubernetes execution for untrusted analysis and remediation

## Status

**Accepted for implementation (2026-11-11); production qualification pending.**

The user approved implementation with simple namespace management and mandatory
Linux user namespaces. The initial implementation is **opt-in and disabled by
default**. API availability requires a live Kubernetes controller for the exact
configured image/toolchain/mirror profile; historical controller heartbeats and
organization consent alone cannot activate it. Local IDE execution is independent.

The shared workload facility supports remediation generation and independent
verification first, not managed SAST or every existing read-only worker.
The chart includes a separate controller, namespace, native admission, RBAC,
network policy and resource quotas. Enabling it requires operator-qualified
runtime/node, admission and network controls; fake-API/unit/chart tests are
not evidence that a real cluster enforces those controls.

The [threat model](../THREAT-MODEL.md) records the new boundaries and residual
risks. The cluster validation gates below still apply before production rollout.

Related: [ADR-015](015-stateless-processing-and-worker-scaling.md),
[ADR-025](025-instance-jobs-observability.md),
[ADR-035](035-bundled-scanners-and-coverage-policy.md),
[ADR-042](042-ide-extensions.md),
[ADR-045](045-built-in-dependency-inventory.md),
[ADR-050](050-guided-remediation-pull-requests.md),
[ADR-052](052-forge-write-access-least-privilege.md),
[ADR-055](055-headless-library-boundaries-and-dependency-footprint.md).

## Context and goals

Hibou deploys on Kubernetes with a shell-free API image. Dependency resolution,
lockfile regeneration and some scanner/build integrations need larger
toolchains and may evaluate repository-controlled code. A temporary checkout,
minimal subprocess environment or container image alone is not isolation.

Use the cluster's native Job lifecycle rather than install another container
runtime, mount a runtime socket, nest privileged containers or ask every
repository to create a CI workflow. Keep local IDE execution independent,
using the same domain engine and explicit developer trust.

The initial supported deployment must work **without public Internet access**,
using internal OCI registries and approved package mirrors such as Artifactory
or Nexus. This is a required acceptance case, not a later convenience.

## Proposed architecture

```text
Website / IDE requesting managed work
                 |
          authorized durable job
                 |
    dedicated trusted workload controller
                 |
          Kubernetes batch/v1 Job
                 |
       disposable untrusted workload
                 |
    bounded candidate result + verification
                 |
    trusted validation / private artifact store
                 |
       download / separately authorized PR
```

### 1. Shared controller, explicit workload classes

The API authorizes intent and persists immutable source, selection and policy
references. It receives no Job-creation credentials and executes no package
manager or repository build script.

A separately deployed controller claims fenced jobs and creates namespaced
`batch/v1` Jobs from operator-approved templates. It manages lifecycle and
bounded transport; domain adapters retain discovery, dependency/scanner
semantics, policy and result validation. Reuse existing leases, artifact
contracts, Git/process helpers and observability instead of duplicating them
per feature.

Each class declares fixed entry points, supported manager/runtime/profile
versions, required input/output kinds, permitted network destinations and
resource limits. Dependency relocking, source scanners, bytecode builds and
targeted dynamic testing have different capabilities; they must not inherit
one another's permissions. Plain bounded, non-executing parsing need not
become a Kubernetes Job.

Clients submit typed intent, not Pod specs, executable URLs, shell commands,
images, mounts, service accounts or arbitrary environment variables.

The initial controller uses one replica with non-overlapping replacement because
attempt broker state is in memory. Durable leases and UID bindings support
restart/retry, not load balancing attempt traffic between independent brokers.
HA requires explicit session routing or shared fenced broker state; do not expose
an unsupported replica/HPA setting. The shared Go runner uses a narrowly typed,
bounded standard-library client for the required Kubernetes API operations,
not a second general-purpose Kubernetes SDK or per-feature orchestrator.

### 2. Narrow RBAC plus independently enforced admission

Use a dedicated execution namespace, isolated from API/database/forge-secret
namespaces and unrelated tenant workloads. This is one execution namespace per
installation by default, **not one namespace per repository or job**.

Helm manages the namespace by default, with a release-scoped generated name.
Operators may choose a name or use an existing dedicated namespace. The chart
must reject the application's namespace and never silently relax isolation.
An existing namespace requires operator-managed restricted Pod Security labels;
the release still installs its scoped execution policies. Namespace creation,
RBAC/admission policy and job lifecycle are installation concerns, not repository
setup. Kubernetes namespaces group policy/authority; they are not kernel sandboxes.

- Controller identity: only the required Job/pod read/watch/create/delete
  lifecycle verbs in that namespace. Add patch/log/event access only if the
  implementation demonstrates a need. No cluster-admin, wildcard resources,
  Secret read/list, `pods/exec`, attach, ephemeral-container injection, node
  access, role binding, impersonation or arbitrary namespace creation.
- Workload identity: no Kubernetes API permissions; disable automatic
  service-account token mounting. If broker identity uses a projected token,
  use a short-lived, explicitly broker-audience-bound token and dedicated
  service account with no Kubernetes API role.
- Keep operator-managed runtime classes, admission rules, network policy and
  service accounts outside controller write permissions.

**RBAC granting Job creation does not constrain the resulting Pod spec.**
Enforce restricted Pod Security and admission rules independently of controller
code: approved digest-pinned images/templates/service accounts, fixed commands,
required limits, permitted volume types/references and no privilege expansion.
Choose the supported admission mechanism during validation (for example
ValidatingAdmissionPolicy or an existing operator policy engine); do not
require an additional engine if native controls suffice.

A compromised controller must not be able to create a privileged pod, mount
API Secrets/PVCs, select a stronger service account or use an arbitrary image.
Labels supplied by a workload are routing metadata, never tenant authority.

### 3. Workload isolation baseline

Default workload templates must support:

- `runAsNonRoot`, fixed non-root UID/GID, read-only root filesystem,
  `allowPrivilegeEscalation: false`, all capabilities dropped and an approved
  seccomp profile. Do not copy the retired supervisor's CHOWN/SETUID/SETGID
  assumptions into a Kubernetes template.
- `hostUsers: false` is required. Linux user namespaces map pod UIDs/GIDs to
  separate host IDs; the fixed non-root UID still applies **inside** the pod.
  Do not disable this field or retry with host users when admission, scheduling,
  the kernel, a volume filesystem or the runtime cannot support it.
- No host PID/IPC/network namespaces, privileged mode, host paths, runtime
  sockets, device mounts or broad credentials.
- Dedicated writable per-job scratch and narrowly bound input/output volumes;
  no shared writable home, repository clone or trusted tool cache.
- CPU/memory/ephemeral-storage requests and limits, PID constraints at the
  supported runtime/node policy, active deadlines, bounded retry/backoff,
  concurrency quotas and tenant fairness. `emptyDir.sizeLimit` alone is not
  a complete node-storage scheduling/eviction policy.
- A validated sandbox runtime class, or a separately justified node/isolation
  boundary, for hostile repository execution. Containers share a kernel;
  do not call the namespace/cgroup baseline equivalent to a VM sandbox.

The minimum Kubernetes/CNI/runtime versions and supported security features
must be recorded by the implementation. If a profile cannot run under the
baseline, it is unavailable until an explicit reviewed class exists; no
automatic privileged/root exception.

The initial implementation requires Kubernetes 1.33 or later, Linux nodes and
an explicitly selected compatible RuntimeClass. User namespaces are stable
since Kubernetes 1.36; earlier supported clusters must keep
`UserNamespacesSupport` enabled. Typical node prerequisites include Linux 6.3+
for tmpfs idmapped mounts, compatible volume filesystems, and containerd 2.0+
with runc 1.2+ or compatible CRI-O/crun versions. See the upstream
[user namespace documentation](https://kubernetes.io/docs/concepts/workloads/pods/user-namespaces/).
The API version or RuntimeClass name alone does not prove node compatibility.
Test the actual runtime/node pool and deployed filesystems. User namespaces
reduce host-UID/capability exposure, not every kernel/runtime escape; retain
the qualified sandbox boundary and prompt kernel/runtime security updates.

### 4. Inputs, broker access and outputs are separate trust boundaries

The controller binds work to immutable tenant/repository identity, source SHA,
profile digest, policy/advisory revisions, job attempt and fencing token.
Trusted source acquisition uses approved forge endpoints and read-only
credentials. Materialize only complete required inputs; reject truncated
trees, path escapes, symlinks/submodules or unsupported layouts rather than
resolve a different graph.

Do not bind-mount a controller's checkout or Unix socket into pods as if they
share a filesystem. Select and validate a Kubernetes-native transport:
short-lived scoped object transfers, job-specific storage or a narrow internal
broker. Inputs are read-only; candidate outputs are private and bounded.
Any PVC/Secret/ConfigMap reference must be controller-created or explicitly
approved and bound to this job/attempt, never selected by repository content.

Treat the **entire workload and its credentials as potentially compromised**.
Any broker capability may access only that job's approved inputs, registry/
advisory operations and candidate-output upload. It must not grant DB access,
forge writes, general API access, Secret reads or cross-job object access.
Validate audience, expiry, attempt/fence and immutable workload identity
(including Job/Pod UID where applicable); copied labels are insufficient.
Do not assume another container in the same pod is a separate network-policy
boundary or that a hidden environment variable is an adequate secret boundary.

Candidate results cannot mark themselves trusted, resolve findings or publish
PRs. The trusted side validates source hashes, allowed file set/modes, size,
patch applicability, requested versions, complete graph/lock consistency and
policy evidence. Where a native verifier is required, use a separately
qualified verification profile/step with equally narrow authority; an uploaded
`verified: true` flag or successful Job exit is not sufficient evidence.

### 5. Network and mirror policy

Apply default-deny ingress/egress to execution workloads. Permit only required
internal broker/data endpoints and narrowly scoped DNS where necessary.
Block cloud/node metadata, Kubernetes API access, unrelated cluster services,
other jobs and unrestricted Internet access. Verify that the deployed CNI
actually enforces the policy.

Standard NetworkPolicy is not a DNS-name allowlist. Prefer a broker or approved
egress gateway that validates package identity, namespace policy, registry/
mirror origin, redirects, artifact hashes and credential scope on every
relevant request. Workloads must not redirect acquisition through `.npmrc`,
POM repositories, wrappers, install hooks or tool bootstrap metadata.
Allow only explicitly supported project configuration; never silently ignore
a required private registry and query a public one.

Package-manager lifecycle scripts/plugins/post-upgrade commands are disabled
where supported. Some build tools still evaluate project code; disabling
scripts does not lower the isolation class.

### 6. Internet-disconnected and offline operation

Distinguish these modes in capabilities and UI:

| Mode | Allowed acquisition | Required preparation |
| --- | --- | --- |
| Connected, approved endpoints | Only operator-approved image/package/data locations | Pinned profiles, scoped credentials, verified metadata/artifacts |
| Mirror-only / no public Internet | Internal OCI registry, Artifactory/Nexus/package mirrors, internal forge and Hibou data services only | Import all toolchains and required registry/advisory data; no upstream fallback |
| Fully network-disconnected execution | No workload network requests, including DNS, telemetry or live advisory matching | Complete source, executable, package/metadata and policy/advisory closure plus an approved data-only staging/collection design |

Mirror-only is the initial required disconnected deployment. It still uses an
internal network; do not market it as zero-network execution. Artifactory
can itself proxy upstream: a truly Internet-disconnected deployment needs its
mirrors populated/cache-only or otherwise prevented from fetching externally.

Toolchains are built/imported ahead of jobs in exact-version, architecture-
qualified OCI profiles pinned by digest. All layer/runtime prerequisites,
licenses/SBOMs and offline signature/trust material must be available internally.
Do not bootstrap Node/Python/JVMs/managers, install OS packages, resolve `latest`,
contact transparency logs or use public image pulls during a job. An OCI image
pull from an approved internal registry is deployment transport, not permission
for an executable installer inside the workload.

The dependency closure includes **metadata as well as downloaded archives**:
version lists, dependency graphs, checksums, target/platform/feature information,
parent POMs/BOMs/plugins/build backends and every transitive package needed by
resolution and verification. A package-manager cache or one tool executable is
not proof that an offline update can resolve.

An operator-controlled catalog maps distributions to approved locations.
Location overrides preserve artifact identity; custom builds need explicit
approval. Validate mirror URL/path, TLS/internal CA trust, authentication
scope and redirects. Brokers inject narrowly scoped credentials only at the
approved origin, never in patches, logged URLs or generic job environments.
Registry metadata may contain tarball URLs: rewrite approved mirror transport
where identity is preserved or reject it; never follow an external URL merely
because it came from an internal mirror.

Preflight reports required profile/artifact IDs, metadata/cache format,
architecture and freshness, distinguishing missing toolchain, missing package
closure and unavailable advisory/policy evidence. Cache misses fail explicitly;
no public fallback, manager substitution, stale-lockfile patch or success-shaped
partial result. Gossip may be unavailable in disconnected installations; explain
that and retain supported Automatic/Exact choices with the required local evidence.

Fully disconnected profiles additionally need a validated staging/collection
mechanism: for example separate trusted staging/collection jobs and narrowly
bound job storage. Do not claim zero network while a tool still calls a broker.
Define freshness limits for policy/advisory snapshots; never silently discard
mandatory policy, triage or verification because an online source is absent.

### 7. Lifecycle, resource ownership and audit

Persist Kubernetes resource UIDs and expected owner references with fenced
attempts. Reconcile current state after controller restart; do not replay writes
based only on pod names or labels. Cancel, deadline, lost claim and repository/
installation revocation prevent new result acceptance and terminate/reconcile
the owning Job. A late successful pod cannot publish a stale attempt.

Kubernetes deletion/TTL is not immediate secure erasure. Coordinate Job/pod,
scratch/PVC and private object cleanup, retry failures and observe orphaned
resources. Retention and quotas cover queued inputs, logs, images/node caches,
artifacts and failed attempts; tenant private caches cannot be shared writable.
No database or object-store deletion is assumed just because a pod exited.

Audit actor, intent, tenant/repository/source, profile/adapter and Job/Pod UIDs,
attempt/fence, acquisition mode/mirrors, verification outcomes, lifecycle,
downloads and separately authorized forge publication. Sanitize logs and
bound output; do not record tokens/source bodies as routine diagnostics.

## Validation and adoption gates

Before production rollout:

1. Review the trust-boundary diagram, controller privileges, workload classes,
   result-verification authority and supported Kubernetes/CNI/runtime matrix.
2. Prototype native Jobs in a representative cluster; test restart/reclaim,
   cancellation/timeout/late results, admission denial, resource exhaustion,
   storage cleanup and cross-tenant/resource binding.
3. Demonstrate that arbitrary images, privileged pods, extra service accounts,
   Secrets/PVCs, host mounts, exec/attach and API/metadata endpoints are denied
   independently of controller code.
4. Run connected and **public-egress-blocked internal Artifactory/OCI mirror**
   fixtures. Verify metadata and archives both stay internal, private names
   never reach public APIs, TLS/auth work and every missing-data case fails
   without an external request. Separately qualify any zero-network profile.
5. Run the unchanged domain tests: dependency/lockfile consistency,
   exact/Gossip targets, no-introduce checks, patch integrity, Git scope,
   authorization and idempotent PR publication.
6. Approve an implementation/configuration plan with no API-pod execution or
   runtime sockets and no per-repository CI requirement.

**Implementation and rollout records:**

- Maintain [THREAT-MODEL.md](../THREAT-MODEL.md) with the controller-to-Kubernetes,
  workload-to-broker/storage and result-verification boundaries; source,
  registry/image and workload-identity assets; STRIDE cases for controller/job
  compromise, sandbox escape, confused deputy, cross-tenant reads, cache/
  metadata poisoning, result forgery, credential leakage and resource DoS.
- Record implemented controls, operational responsibilities and residual
  risks; do not present proposed controls as deployed mitigations.
- Add deployment/RBAC/admission/network manifests and automated negative tests,
  rollout/rollback instructions and capability readiness checks.
- Keep execution disabled by default. Operators enable only a qualified profile;
  readiness must use that exact configuration, never a generic controller heartbeat.

## Alternatives

- **Podman/Docker nested runtime or a host runtime socket:** rejected for the
  managed Kubernetes path; duplicates orchestration and expands the boundary.
- **Package managers in API/ordinary workers:** rejected; breaks separation
  of untrusted execution and application credentials.
- **Privileged/root workload because a tool needs it:** rejected as a default;
  redesign the transport/ownership or qualify a separate reviewed class.
- **Public fallbacks when a mirror misses data:** rejected; violates no-public-
  Internet/private-package policy and makes disconnected operation unreliable.
- **Per-repository CI as a prerequisite:** rejected; installation-managed
  infrastructure is the website path; local IDE tools remain an independent option.
