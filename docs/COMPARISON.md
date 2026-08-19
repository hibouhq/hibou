# Hibou vs. the field

An honest comparison of Hibou against the tools an organization would
realistically consider instead: SonarQube, GitHub Advanced Security, GitLab
Ultimate, Snyk, Veracode, OWASP Dependency-Track, and DefectDojo.

*Written 2026-08-19 from Hibou's actual code and specs; competitor claims
reflect publicly documented capabilities and may lag their releases. Corrections
welcome.*

**The one-paragraph honest version:** Hibou is a pre-1.0, self-hosted security
intelligence platform. It does not compete with CodeQL or Snyk on *scanning* —
it has no SAST engine of its own and never claims to. It competes on the layer
above: ingesting what your scanners already produce (SBOM, SARIF, coverage,
secrets), normalizing it across repos, branches, PRs, releases, and deployed
clients, and gating/reporting on it — across multiple git forges, on your own
infrastructure. If you want a turnkey, mature, certified product today, buy
GitHub Advanced Security, GitLab Ultimate, Snyk, or Veracode. If all you need
is a hardened SBOM component inventory — and only an inventory — run
Dependency-Track. Hibou's case is the combination nobody else covers well:
commit-anchored snapshots of *all* security state (diffable across any two
branches, tags, or points in time) + multi-forge + self-hosted/air-gap +
VEX-first triage + release/client impact — at the cost of maturity.

## Capability matrix

Legend: ✅ built-in and functional · ⚠️ partial, indirect, or paid-tier-only ·
❌ absent or out of scope.

| Capability | **Hibou** | SonarQube | GitHub Adv. Security | GitLab Ultimate | Snyk | Veracode | Dependency-Track | DefectDojo |
|---|---|---|---|---|---|---|---|---|
| **Positioning** | Security intelligence / ASPM | Code quality + SAST | Forge-native AppSec | Forge-native DevSecOps | Developer security (SaaS) | Enterprise AppSec suite (SaaS) | SBOM vuln management | Findings aggregation / ASPM |
| **Setup & config burden** | ✅ single binary + env vars<br>optional schema-validated `.hibou.yaml`<br>onboarding PR auto-created<br>gates advisory by default | ⚠️ server, quality profiles<br>per-project setup | ✅ one-click enable<br>(on its own turf) | ⚠️ CI templates per repo | ✅ SaaS onboarding, repo import | ❌ heavyweight enterprise onboarding<br>packaging rules for binary upload | ⚠️ you build the CI→API pipelines yourself | ❌ per-scanner import wiring<br>product/engagement modeling first |
| **Own SAST engine** | ❌ ingests SARIF only | ✅ incl. taint analysis | ✅ CodeQL | ✅ largely wrapped OSS scanners | ✅ Snyk Code | ✅ binary/static analysis<br>policy + pipeline scans | ❌ | ❌ |
| **SAST aggregation (any SARIF producer)** | ✅ SARIF 2.1.0 | ⚠️ external-issues import | ✅ SARIF upload | ⚠️ own report format | ❌ | ❌ own scans only<br>exports SARIF, doesn't ingest it | ❌ | ✅ 150+ parsers (OSS)<br>⚠️ smarter dedup & modern UI paywalled in Pro |
| **SCA / dependency vulnerabilities** | ✅ OSV, NVD, GHSA, Trivy, OSS Index<br>canonical alias merging | ⚠️ commercial add-on, newer | ✅ Dependabot | ✅ | ✅ best-known proprietary DB | ✅ SourceClear lineage | ✅ | ⚠️ via imported scanner output |
| **SBOM ingest (CycloneDX / SPDX)** | ✅ both<br>async pipeline + dedup | ❌ produces, doesn't manage | ⚠️ export-oriented | ⚠️ CycloneDX export/ingest | ⚠️ export-oriented | ⚠️ export-oriented (SBOM API) | ✅ CycloneDX-native<br>reference implementation | ⚠️ as findings import |
| **VEX (create / import / export)** | ✅ OpenVEX, CSAF, CycloneDX<br>auto-generation on upgrade/removal<br>supplier VEX propagation with expiry | ❌ | ⚠️ dismissals<br>no VEX docs | ⚠️ vuln states<br>no VEX docs | ⚠️ ignores/policies | ⚠️ mitigation/annotation workflow<br>no VEX docs | ✅ consume + author | ⚠️ risk acceptance<br>no VEX docs |
| **Reachability analysis** | ⚠️ Go: server-side (RTA/VTA)<br>Java + Rust: CI-side<br>feeds auto-VEX | ❌ | ⚠️ CodeQL dataflow ≠ dep reachability | ⚠️ limited | ✅ several ecosystems | ✅ vulnerable-method analysis (SCA) | ❌ | ❌ |
| **Secret scanning** | ⚠️ orchestrates Gitleaks/TruffleHog<br>+ GitHub secret-scanning API<br>opt-in worker, still stabilizing | ✅ recent versions | ✅ best-in-class<br>push protection<br>partner revocation | ✅ incl. push protection | ⚠️ | ⚠️ not a core product | ❌ | ⚠️ via imports |
| **Malware / typosquat / dep-confusion flags** | ✅ OSV feed<br>OpenSSF Package Analysis feed | ❌ | ⚠️ advisory-dependent | ⚠️ | ✅ | ⚠️ | ⚠️ policy-dependent | ❌ |
| **Coverage ingestion + gates** | ✅ 5 formats<br>PR deltas<br>quality gates<br>ingested async — tests upload when done | ✅ display + gates, its home turf<br>⚠️ but read by the scanner's single memory-heavy pass, which must run *after* tests — serializes the pipeline | ❌ third-party apps | ✅ | ❌ | ❌ | ❌ | ❌ |
| **PR/MR delta analysis & quality gates** | ✅ new/resolved deltas<br>advisory-by-default<br>live re-check on dismissal, no CI re-run | ✅ PR decoration | ✅ native checks | ✅ native MR widgets | ✅ PR checks | ⚠️ via CI plugins (pipeline scan)<br>not live forge checks | ❌ | ⚠️ |
| **Multi-forge (GitHub + GitLab + Gitea/Forgejo)** | ✅ first-class<br>incl. self-hosted forges | ✅ decorates all major forges | ❌ GitHub only<br>(+ ADO variant) | ❌ GitLab only | ✅ major SaaS forges | ⚠️ CI-plugin integrations<br>GitHub/GitLab/ADO/Bitbucket | ❌ n/a | ⚠️ n/a<br>tracker-oriented |
| **Multi-tenancy (org → team → repo, RBAC)** | ✅ foundational<br>5 roles | ⚠️ projects/permissions, flatter | ⚠️ GitHub org model | ✅ groups | ✅ orgs/groups | ⚠️ business units / teams | ⚠️ teams/portfolios | ✅ product hierarchy |
| **Branch/commit history & comparison ("what changed between these two refs?")** | ✅ immutable snapshot per commit<br>compare any two branches/tags/snapshots<br>trends over time (tiered retention) | ⚠️ new-code vs. baseline<br>branch analysis paid in Server editions<br>no arbitrary snapshot diff | ⚠️ alerts tracked per ref<br>no cross-branch comparison view | ⚠️ per-branch pipelines, MR diffs<br>weak history beyond that | ⚠️ mostly monitors the imported (default) branch | ⚠️ per-app scan history, sandboxes<br>no branch semantics | ❌ manual project-versions<br>no commit/branch model, no diffing | ❌ time-of-engagement model<br>no branch semantics |
| **Release / deployment / client impact ("which clients ship CVE-X?")** | ✅ releases, deployments, rollbacks<br>per-client CVE impact | ❌ | ❌ | ⚠️ environments | ❌ | ❌ | ❌ project-versions only<br>no releases/deployments/clients | ⚠️ engagement model |
| **Compliance reporting** | ⚠️ ISO 27001 mapping + SoA<br>point-in-time reports | ⚠️ quality reports | ⚠️ org security overview | ✅ compliance frameworks & pipelines | ⚠️ reports | ✅ policy compliance<br>strong in regulated industries | ⚠️ policy violations | ⚠️ reports |
| **DAST / container / IaC / fuzzing** | ❌ none — ingest-only philosophy<br>container/IaC SARIF can be ingested | ❌/⚠️ | ⚠️ container/IaC via actions | ✅ all four built in | ✅ container + IaC | ✅ DAST<br>⚠️ container/IaC newer | ❌ | ⚠️ via imports |
| **Self-hosted / air-gap** | ✅ single Go binary or Helm<br>Postgres + optional S3-compatible store<br>no phone-home requirement | ✅ mature self-host | ❌ SaaS or GHES (licensed) | ✅ self-managed | ❌ SaaS-first<br>broker for on-prem code | ❌ SaaS only<br>code/binaries upload to their cloud | ✅ | ✅ |
| **AI-assistant integration** | ✅ built-in MCP server<br>over live security state | ⚠️ emerging | ⚠️ Copilot-adjacent | ⚠️ Duo-adjacent | ⚠️ | ⚠️ AI remediation (Veracode Fix) | ❌ | ❌ |
| **License / cost** | ⚠️ **license not yet chosen**<br>no paid tier exists | Open-core<br>paid editions for serious SAST | Paid per active committer<br>two SKUs | Paid per user (Ultimate) | Paid per developer<br>free tier | Paid enterprise, per-app<br>opaque pricing | Apache-2.0 | BSD-3<br>Pro SaaS |
| **Maturity / production track record** | ❌ pre-1.0, alpha<br>dogfood-scale | ✅ ~15 years<br>huge install base | ✅ | ✅ | ✅ | ✅ ~20 years<br>audit-friendly | ✅ ~10 years | ✅ ~10 years |

## What Hibou genuinely does better

- **It follows the SDLC, not just the scan.** The same normalized data moves
  through one continuous flow: CI upload → PR delta and gate → merge →
  release → deployment → client impact. Every stage is a first-class entity,
  so the question changes shape as the code moves ("what did this PR add?" →
  "which release fixed it?" → "which clients still run the affected build?")
  without switching tools. The scanner-centric products stop at "finding
  exists"; the forge suites stop at merge.
- **The snapshot model — this is the part nothing else in the table has.**
  Hibou's core primitive is an immutable, commit-anchored snapshot holding
  *all* security state at once: SBOM, findings, coverage, secrets. Everything
  else in the product is derived from it — PR deltas are two snapshots
  diffed, gates evaluate a snapshot, releases point at one, client impact
  walks from one. So "diff these two branches", "what exactly did this tag
  ship?", or "how has this repo trended over six months?" are plain queries,
  with tiered retention keeping history affordable. The nearest analogues
  don't reach it: Sonar keeps per-analysis *metric* history, Snyk keeps
  per-test result snapshots — neither is commit-anchored across all artifact
  types nor diffable between arbitrary refs; Dependency-Track's
  project-versions are manual copies with no commit or branch model; the
  forge suites show per-ref alert lists, never a comparison between two refs.
- **Near-zero configuration.** One binary, env vars, and you're serving.
  Repos onboard through an auto-created PR adding a schema-validated
  `.hibou.yaml` — which is itself optional, because defaults are usable:
  gates ship advisory-by-default, ingestion auto-detects formats (CycloneDX,
  SPDX, SARIF, five coverage formats), and login rides your forge's OAuth so
  there is no user provisioning step. The honest comparison: GHAS is equally
  one-click *if* you live on GitHub; everything else in the table wants
  servers, profiles, CI templates, or per-scanner wiring first.
- **Your CI stays parallel.** Every input is an independent upload against
  the same snapshot: unit tests push coverage when they finish, Semgrep
  pushes SARIF when it finishes, SBOM generation runs alongside — the server
  assembles the snapshot as pieces arrive (it tracks expected vs. received
  uploads) and processes asynchronously. Contrast SonarQube, whose scanner is
  one memory-heavy analysis pass that has to run *after* tests to pick up
  coverage — a serial stage bolted onto the end of every pipeline, paid on
  every build.
- **The aggregation layer is the product, not an afterthought.** Scanner
  output goes through one normalized ingestion contract (SBOM, SARIF,
  coverage, secrets) with canonical alias merging across five advisory
  sources — instead of five dashboards disagreeing about the same CVE.
- **VEX is first-class, not a dismissal checkbox.** Create, import, export in
  OpenVEX/CSAF/CycloneDX; auto-VEX on component upgrade or removal; supplier
  VEX propagation with expiry; reachability analysis feeding auto-VEX. Nobody
  in this table except Dependency-Track treats VEX as a real object, and
  Dependency-Track doesn't generate it for you.
- **Downstream impact is modeled.** Releases, deployments, rollbacks, and
  *clients* are entities — "which customers are running a build affected by
  CVE-X" is a query, not a spreadsheet exercise. This is the feature the
  forge-native suites structurally cannot offer.
- **Forge-neutral by design.** One platform posting native checks to GitHub,
  GitLab, and Forgejo/Gitea — including self-hosted forges — with gates that
  are advisory by default and re-evaluate live when a finding is dismissed (no
  CI re-run to turn a check green).
- **Operationally small.** One binary embedding the SPA, Postgres, optional
  S3-compatible object store, Helm chart, stateless replicas with DB-leased
  workers (ADR-015). Air-gap-friendly. Compare with the JVM+Elasticsearch
  footprints common in this space.
- **AI-native.** A built-in MCP server exposes live security state to AI
  assistants with the same auth model as the API.

## Where Hibou honestly loses today

- **Maturity.** Pre-1.0, alpha-stage, LLM-assisted development explicitly
  disclosed, tested at dogfood scale — not thousands of orgs. The TODO
  backlog is public and long. Every other row in the matrix has years of
  production hardening.
- **No license yet.** The README says "License to be determined." Until that
  is fixed you cannot even legally adopt it in most companies. This is the
  single most disqualifying line in this document.
- **It scans almost nothing itself.** No SAST engine, no DAST, no container
  or IaC scanners. Hibou is only as good as the scanners you run in CI and
  upload from. If you don't already operate Semgrep/CodeQL/Trivy/etc., a
  suite that bundles scanning (GitLab, Snyk, GHAS) delivers value faster.
- **Secret scanning is young.** It orchestrates external scanners
  (Gitleaks/TruffleHog) behind an opt-in worker; no push protection at the
  forge boundary, no partner-revocation program like GitHub's.
- **No SSO/SAML/SCIM.** Authentication is OAuth through your forge. Enterprise
  identity integration doesn't exist yet.
- **Ecosystem and support.** No marketplace, no consultancy network, no paid
  support, no compliance certifications (SOC 2, etc.) of the product itself,
  community of approximately one team. Bus factor is real.
- **Operational sharp edges.** Requires PostgreSQL 18; multi-replica
  deployments need the bundled object store; some background paths (advisory
  rescans) are still not fully durable; CI currently skips DB-backed tests.

## Decision guide

- **You live entirely on GitHub / GitLab and can pay** → GHAS or GitLab
  Ultimate. Tightest UX, one vendor, mature scanning included.
- **You want best-in-class SCA + developer-first fixes, SaaS is fine** → Snyk.
- **You need code-quality gates and SAST with taint analysis, self-hosted** →
  SonarQube (and it can coexist with Hibou — Hibou ingests its findings via
  SARIF-producing wrappers or alongside Semgrep/CodeQL).
- **You're in a regulated industry needing an auditor-recognized SAST/DAST
  vendor with policy compliance reporting, and SaaS scanning is acceptable** →
  Veracode. Note the structural mismatch with Hibou's niche: your code and
  binaries upload to their cloud, so it cannot serve air-gapped environments.
- **You need an SBOM component/vulnerability *inventory*, proven and free** →
  OWASP Dependency-Track. Know what you're getting: it answers "which projects
  contain component X" very well, and stops there. Project-versions are the
  only release notion — no deployments, no client impact, no PR/SDLC flow —
  and triage is per-project alerting rather than decision support. There is
  no commit or branch model either: you can't compare two branches, and a
  "version" is whatever you manually uploaded, with no history of how a
  given ref evolved. It's an inventory you query, not a system that helps
  you decide what to do next.
- **You need to aggregate a zoo of scanner reports into a workflow/tracker,
  and you can live with the UX** → DefectDojo. The parser coverage is real,
  but the OSS experience is dated and cumbersome (a common complaint, not
  just ours), and the polished UI, smarter dedup, and automation are being
  moved into the paid Pro tier — so the free product is increasingly the
  demo, not the tool.
- **You self-host across multiple forges (including Forgejo/Gitea), need
  air-gap, care about VEX and about which deployed clients a CVE hits, and
  can tolerate pre-1.0 software** → this is exactly the gap Hibou exists to
  fill. Run it beside your existing scanners; don't run it *instead* of them.

## Non-goals (so this stays honest both ways)

Hibou deliberately does not aim to be: a scanner vendor, a SaaS, a ticketing
system, or a runtime/DAST product. Its bet is that scanning is being
commoditized by open source (Semgrep, Trivy, Gitleaks, OSV…) and the durable
value is the normalized intelligence layer above them. Whether that bet pays
off depends on execution on the maturity gaps above — the architecture is in
place; the track record is not.
