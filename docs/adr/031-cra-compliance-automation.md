# ADR-031: CRA (EU 2024/2847) compliance automation

## Status
Partially implemented roadmap (status verified 2026-11-09).

- **Implemented:** exploited-catalog feeds (ADR-032), exploitation-triggered
  incident evaluation, reporting clocks/drafts and client document
  sets/deliveries (ADR-053).
- **To be implemented:** canonical server-side snapshot/release SBOM export,
  support-period/component-EOL modelling, release-readiness policy, public
  fixed-delta advisory generation, the CRA compliance lens and upstream
  notification recording (Phase 2). A full EUVD advisory provider is also
  still proposed; the exploited set is already mirrored.
- **Superseded, not pending implementation:** Phase 1's separate `report`
  entity and a bespoke KEV-diff trigger; ADR-053 uses incidents and rule
  sweeps after catalogue sync/advisory refresh instead.
- **Not in scope:** automatic legal filing to the reporting platform. This
  was deliberately excluded, not promised as unfinished implementation.

The original regulatory summary is context, not the current clock algorithm:
ADR-053 defines the implemented regimes, triggers and final-report anchors.

## Context

The EU Cyber Resilience Act (CRA, Regulation (EU) 2024/2847) applies to every "product
with digital elements" placed on the EU market. Two dates matter:

- **11 September 2026 (already in force)** — Article 14 reporting obligations:
  manufacturers must notify any **actively exploited vulnerability** and any **severe
  incident** to their coordinating CSIRT and ENISA via the single reporting platform, on
  fixed clocks: early warning within **24 h**, notification within **72 h**, final report
  within **14 days** (vulnerabilities) or **1 month** (incidents). Per Article 69(3) this
  applies to *all* in-scope products, including those placed on the market before 2027.
- **11 December 2027** — everything else: essential requirements (Annex I), vulnerability
  handling processes, SBOM, support period, technical documentation, CE marking.

Hibou's customers are exactly the population this regulation targets: teams shipping
software who must now *prove* they identify, document, triage, remediate, and disclose
vulnerabilities across the whole SDLC. Most of the Annex I Part II vulnerability-handling
requirements describe workflows hibou already implements or is uniquely positioned to
automate — that is the product opportunity. The Commission's FAQ (v1.4, 04/09/2026)
further confirms a **risk-based** reading: manufacturers do *not* have to patch every CVE;
they must assess exploitability and document the justification — which is precisely a
triage + VEX workflow.

### What hibou already covers (per CRA requirement)

| CRA requirement | Hibou today |
|---|---|
| Annex I Part II (1): identify and document vulnerabilities and components, incl. an SBOM in a machine-readable format | SBOM ingestion (CycloneDX/SPDX) anchored to immutable per-commit snapshots; canonical advisory model (ADR-007); unified vulnerability model (ADR-012) |
| Annex I Part II (2): address and remediate vulnerabilities without delay, *in relation to the risks posed* | Triage/acceptance workflow (ADR-023), in-source suppressions (ADR-026), VEX with justifications (ADR-009), auto-VEX on upgrade/removal |
| Annex I Part I (2)(a): no *known exploitable* vulnerabilities at placement on the market | Quality gates on PRs (ADR-018); FAQ 4.2.2 confirms "exploitable" is assessed case-by-case — a `not_affected` VEX statement with justification is the documented form of that assessment |
| Annex I Part II (3): effective and regular security tests and reviews | Coverage, test, secret-scan and SARIF ingestion with per-snapshot evidence and gates (ADR-008/018/019, ADR-010) |
| Art. 13(5) + Recital 34: due diligence on third-party components (update history, vuln databases, SCA, component SBOM review) | Advisory freshness, malware/typosquat detection, license policy (ADR-029/030), release tracking (ADR-024) |
| Art. 13(7): systematically document relevant cybersecurity aspects | Audit log (30+ action types), immutable snapshots, compliance export (ISO 27001 mapping) |
| Art. 13(6): report component vulnerabilities upstream | Partially — we know the component, the advisory, and the fix, but there is no upstream-notification workflow |

### Remaining gaps and closed items (verified 2026-11-09)

1. **Canonical server-side SBOM export remains open.** ADR-046 already emits
   CycloneDX (including VEX) from local scans. That is not the proposed API
   export of the stored canonical per-snapshot/per-release inventory for
   technical documentation (Annex VII).
2. **No support-period / EOL model.** Art. 13(8) mandates a support period ≥ 5 years;
   Art. 13(19) requires displaying its end date; FAQ 4.3.7 makes component EOL a
   compliance risk during the product's support period. Hibou tracks releases and
   deployments but has no notion of a support window, nor component end-of-life data.
3. **Article 14 workflow implemented by ADR-053.** ADR-032 supplies the
   exploited signal; incident rules evaluate released snapshots after
   catalogue sync and advisory refresh. Incidents track deadlines, drafts,
   decisions, client documents and recorded deliveries. The original missing
   workflow is closed, not a second reporting feature to build.
4. **No EUVD source** — *partially closed*. Recital 34 and Art. 17(5) name the ENISA
   European vulnerability database (established under NIS2 Art. 12(2)) as the reference
   database for due diligence. ADR-032 ingests the EUVD **exploited set** (the Art. 14
   trigger); the EUVD as a full advisory *source* alongside OSV, NVD, GHSA, Trivy,
   OSS Index remains open.
5. **No public-disclosure artifact.** Annex I Part II (4) requires publishing, once a fix
   ships, a description of the vulnerability, affected products, impacts, severity, and
   remediation info. We export VEX (incl. CSAF) but do not generate full security
   advisories from a release's fixed-vulnerability delta.
6. **No CRA lens in the compliance module.** `internal/compliance` maps evidence to
   ISO 27001:2022 controls but not to Annex I / Annex VII items.
7. **Advanced deployment reconciliation remains design-only** (ADR-024 §8).
   Basic client/deployment recording already supports ADR-053's impact scope
   and client notifications. GitOps, cluster observations and client
   self-report reconciliation are the remaining extension, not a prerequisite
   missing from the shipped reporting workflow.

## Decision

Position hibou as the system of record for a manufacturer's CRA vulnerability-handling
process (Annex I Part II) and automate the obligations that have deadlines. Work is
ordered by regulatory date, not by feature size.

### Phase 1 — Article 14 is already live (target: ASAP)

**1. Exploitation-awareness feed.** ✅ **Shipped** — see
[ADR-032](032-kev-catalog-and-exploited-gate.md). CISA KEV and the ENISA EUVD
exploited set are mirrored locally (not as advisory *sources*: a joined
`kev_entries` table rather than an `actively_exploited` column, so withdrawal
needs no backfill — the rationale is ADR-032's). The signal gates PRs
unconditionally and surfaces on the finding detail. **The released-snapshot
trigger is also implemented by ADR-053:** incident rule sweeps run after
catalogue sync and advisory refresh, selecting matched findings on released
snapshots. The original proposal for a separate KEV-diff event pipeline is
superseded, not remaining work.

**2. Reporting-clock workflow.** ✅ **Shipped as the incident of
[ADR-053](053-incidents.md)**, which supersedes the sketch below.
The original sketch below is superseded by ADR-053's incident entity and
regime-specific clock calculations; it is not another entity to implement.
A `report` entity was proposed attached to an advisory + release:
created manually or from the exploitation event, it tracks the Art. 14 deadlines
(24 h early warning → 72 h notification → 14 d final report; the incident variant with
its 1-month final report) with countdown surfacing in the UI and escalation through the
existing notification dispatcher (Slack/Teams/webhook/email). Hibou pre-fills the
notification content it already knows — product, version, affected component, advisory
description, corrective measures taken (fix PR, VEX statement, patched release) — as a
draft for the ENISA single reporting platform. Hibou does **not** submit to the platform
itself: the platform's API surface is not yet stable, submission is a legal act of the
manufacturer, and a wrong automated filing is worse than a late one. Revisit when the
Art. 16 platform publishes a machine interface.

**3. User notification via CSAF.** ✅ **Shipped in [ADR-053](053-incidents.md) §5**
(client document sets and recorded deliveries). Incident documents use the
existing VEX/CSAF export and the recorded deployments/client scope for the
Art. 14(8) notice. ADR-024 §8's advanced reconciliation is a later extension,
not a blocker for this implemented path.

### Phase 2 — Annex I Part II evidence (target: well before 2027-12-11)

**4. SBOM export.** Emit a canonical per-snapshot/per-release SBOM (CycloneDX JSON first,
SPDX second) built from the ingested component graph — at minimum top-level dependencies
(the Annex I Part II (1) floor), full graph when available. Exposed per release and via
the existing fine-grained token API so it can be attached to release artifacts in CI.

**5. Support-period and EOL model.** Per-repo (or per-release-line) `support_until` date;
component end-of-life ingestion (endoflife.date as first source). Two alerts through the
notification rules: a component's support ends inside the product's support window
(FAQ 4.3.7 — the manufacturer must then patch or replace it autonomously), and the
product's own end-of-support approaches (Art. 13(19) display obligation).

**6. Release-readiness check.** A release-scoped gate implementing Annex I Part I (2)(a):
the release view lists open vulnerabilities that are neither remediated nor covered by a
VEX `not_affected`/accepted-risk statement — i.e. *known exploitable and undocumented*.
This reuses the ADR-018 gate machinery at the release boundary instead of the PR boundary.

**7. Security-advisory generation.** From the fixed-vulnerability delta between two
releases (ADR-016 comparison + ADR-024 release tracking), generate the Annex I Part II (4)
public disclosure document (CSAF advisory + human-readable rendering): description,
affected versions, severity, remediation. Publication remains a customer action.

**8. CRA compliance lens.** Mirror the ISO 27001 approach in `internal/compliance`: map
hibou evidence (snapshots, gates, VEX, triage decisions, audit log, SBOMs, reports) to
Annex I Part I/II items and produce an Annex VII-oriented technical-documentation export.
The FAQ stresses that non-applicable requirements need a *documented justification*
(Art. 13(4)) — the export includes explicit "not applicable because…" slots rather than
silently omitting items.

**9. Upstream notification helper (Art. 13(6)).** When a customer triages a vulnerability
in an open-source component (especially with a local patch), surface the maintainer
contact / security policy of the component and record that upstream notification happened
— it is an obligation, and today nothing captures it.

### Explicit non-goals

- Hibou does not perform conformity assessment, does not issue or verify EU declarations
  of conformity, and does not decide product classification (default / important Class
  I-II / critical). It produces the evidence; the manufacturer (or its notified body)
  makes the legal claims.
- No automated submission to the single reporting platform (see Decision 2).
- Auto-VEX stays deterministic (upgrade/removal, as shipped). Reachability-based
  auto-justification ("library function never called" — the FAQ's own example of a
  documented non-exploitable vulnerability) is attractive but is a separate research
  track, not part of this ADR.

## Consequences

- Hibou gains a compliance narrative with a hard external deadline: reporting support is
  sellable *now* (obligation live since 2026-09-11), the rest before 2027-12-11.
- ~~The canonical advisory model grows two sources (KEV, EUVD) and one flag
  (`actively_exploited`)~~ Superseded by ADR-032: exploitation lives in a
  side-table joined on CVE identifiers, not on the advisory model. ADR-007's
  alias merging still must reconcile EUVD identifiers if the EUVD becomes a
  full advisory source (EUVD exploited entries without a CVE alias are skipped
  today).
- Recorded client/release deployments support Art. 14(8) notification today;
  ADR-024 §8 adds further sources of deployment evidence.
- The VEX investment (ADR-009) becomes the legal backbone of risk-based remediation —
  triage justifications should be reviewed for CRA-quality wording (they may end up in
  technical documentation shown to authorities).
- SBOM export makes hibou both consumer and producer of SBOMs; round-trip fidelity
  (ingest → export) needs tests to avoid laundering incomplete data into a compliance
  artifact.
- Hibou itself, if ever placed on the EU market in the course of a commercial activity,
  becomes a product with digital elements under the CRA (likely default category,
  Module A self-assessment). Internal or own-use deployment is out of scope (Blue Guide
  §2.3, FAQ 1.5). The original self-readiness gap list is not current:
  [SECURITY.md](../../SECURITY.md) defines private reporting and response
  expectations, [LICENSE](../../LICENSE) selects AGPL-3.0, and
  [CI](../../.github/workflows/ci.yml) contains signing/attestation steps
  (conditional on repository visibility). Configuration in CI is not proof
  that every published artifact is signed. Remaining release-evidence and
  operational readiness must be verified separately; this ADR does not certify
  market-placement compliance.

## References

- Regulation (EU) 2024/2847 (CRA), esp. Art. 13, 14, 16, 24–25, 69(3), 71(2);
  Annex I (essential requirements), Annex II (user information), Annex VII (technical
  documentation) — https://eur-lex.europa.eu/eli/reg/2024/2847/oj
- Commission services, *FAQs on the Cyber Resilience Act*, v1.4 (2026-09-04) —
  https://ec.europa.eu/newsroom/dae/redirection/document/123307
- ADR-007 (canonical advisories), ADR-009 (VEX), ADR-012 (unified vulnerability model),
  ADR-016 (snapshot comparison), ADR-018 (quality gates), ADR-023 (triage acceptance),
  ADR-024 (release tracking), ADR-026 (in-source suppressions)
