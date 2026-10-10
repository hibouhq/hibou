# ADR-041: Regulated environments — a path to replacing Veracode-class platforms

## Status

Proposed (2026-10-10). A roadmap ADR: it fixes the target and the order of
work, and each item lands through its own ADR. Builds on the CRA automation
([ADR-031](031-cra-compliance-automation.md)), the ISO 27001 evidence export
(`internal/compliance/iso27001.go`), the CWE model
([ADR-037](037-cwe-weakness-model.md)), the risk metrics
([ADR-038](038-cvss-and-epss-risk-metrics.md)), triage acceptances
([ADR-023](023-triage-acceptance-ux.md)), bundled scanners
([ADR-035](035-bundled-scanners-and-coverage-policy.md),
[ADR-036](036-automatic-scan-planning-and-verification.md)) and reproducible
builds ([ADR-011](011-reproducible-builds.md)).

## Key points (read this first)

This section is the contract for anyone, person or agent, implementing an item
of this ADR. Keep these points when an item is designed, re-scoped or
reviewed; an item that contradicts one of them needs an ADR that amends this
one first.

**Positioning**

- Hibou is **self-hosted, not SaaS**, and stays that way as the primary
  model. It competes as the evidence and governance layer an auditor
  accepts, running where the code already is. It does not become a cloud
  scanning vendor.
- **FedRAMP does not apply to self-hosted hibou.** FedRAMP authorizes cloud
  services; software inside a customer's boundary is covered by that
  system's own authorization (FISMA / NIST RMF ATO). The work is making
  hibou easy to authorize there, not obtaining FedRAMP.
- For air-gapped and classified environments, self-hosting beats any SaaS
  clearance: a SaaS scanner cannot be used there at all.

**The trust gap, and how it is closed**

- A self-hosted instance is controlled by the customer, so a report signed
  with the instance's own key proves only that the file was not changed
  after export, **not that the results are honest**. Never present an
  instance signature as third-party trust.
- Auditors already accept self-hosted scanners (on-prem Fortify, Checkmarx,
  SonarQube): they test the controls around the tool. The bar is
  **tampering is detectable and results are checkable by someone else**.
- Trust is moved off the hibou administrator by layers (§ "Trust without
  SaaS"): reproducible scans, CI-signed scan provenance, a tamper-evident
  log anchored outside, an auditor role, a digest-only notary, and later a
  vendor-operated single-tenant option. **Code and findings never leave the
  customer**; at most, digests do.
- What remains is stated, not hidden: a customer controlling both its CI
  and hibou could fake results before anything is signed, exactly as with
  every on-prem scanner auditors accept today.

**The plan** (numbers refer to the Decision section)

- *Short term, 0–3 months — make the evidence auditable:* compliance
  frameworks as versioned data with honest covers / supports / does-not-
  address status (PCI DSS v4.0, OWASP, NIST SSDF, NIST 800-53, ISO 27001,
  SOC 2, HIPAA; CRA moved onto the same model) (1); continuous per-application
  policy status with history (2); remediation SLAs with KEV due dates first
  (3); reports that record everything needed to recompute them (4); scan
  provenance signed by the CI platform (5); a hash-chained audit log anchored
  by an external timestamp (6); four-eyes risk acceptance (7); SSO and SCIM (8).
- *Medium term, 3–9 months — make hibou easy to authorize:* reproducible
  scans with `hibou reproduce` (9); an auditor role (10); bundled scanning
  coverage including DAST (11); an air-gap kit (12); a FIPS 140-3 build (13);
  a hardened deployment baseline (14); NIST 800-53 control statements (15);
  hibou's own supply chain and PSIRT (16); evidence for customers' own
  attestations (17); Veracode import and parallel-run comparison (18).
- *Long term, 9–24 months — third-party trust:* a digest-only notary run by
  whoever backs hibou (19); a vendor-operated single-tenant option in the
  customer's cloud account (20); published detection benchmarks per CWE (21);
  independent penetration tests, and SOC 2 / ISO 27001 for the organisation
  behind hibou (22); Iron Bank, and FedRAMP only for a hosted offering (23);
  mappings reviewed by practising auditors (24).

**Non-negotiables**

- No SaaS scanning business; no proprietary SAST engine; no certificate or
  report that claims more than it proves.
- Certifications (SOC 2, ISO 27001) attest an organisation, not a
  self-hosted product. Never write that hibou "is SOC 2 certified".
- Every framework requirement states covers / supports / does not address;
  no implied coverage.
- Success means: an audit closed with hibou as the only evidence; hibou
  authorized inside a federal boundary; no unexplained detection gap in a
  parallel run against the incumbent.

## Context

### The argument we lose today

In regulated organisations the case for Veracode (and Checkmarx, Fortify,
Black Duck in the same seat) goes:

> Built for CISO-level governance and compliance. Maps vulnerabilities to
> PCI DSS, HIPAA, FISMA and OWASP with official, exportable compliance
> certificates. Holds clearances like FedRAMP authorization, an absolute
> requirement for many government contracts.

`docs/COMPARISON.md` concedes it: hibou has "no compliance certifications of
the product itself", no SSO/SAML/SCIM, and depends on scanners it does not
run. Split into separate claims, the argument is five different needs, and
they are not equally hard:

| # | What the buyer needs | What actually satisfies an auditor |
|---|---|---|
| 1 | **Mapping** findings and controls to frameworks (PCI DSS, OWASP, NIST, HIPAA, ISO, SOC 2) | Evidence per control requirement, not a logo. Auditors test the process: scanned on a defined cadence, against a defined policy, remediated within defined times, exceptions approved |
| 2 | **Exportable reports / "certificates"** | A dated, scoped, tamper-evident report a third party can verify and re-derive. A vendor-issued "certificate" is a policy-pass attestation, not a regulatory certification |
| 3 | **Clearances** (FedRAMP) | FedRAMP authorizes *cloud services* sold to US federal agencies. It applies to Veracode because Veracode is SaaS: customer code is uploaded to Veracode's cloud. Self-hosted software deployed inside an agency's own boundary is covered by that system's authorization (FISMA / NIST RMF ATO), not by FedRAMP; what it needs is to be easy to authorize: FIPS-validated crypto, hardened images, NIST 800-53 control statements, a trustworthy supply chain |
| 4 | **Independent testing** | Scans run by a defined, consistent toolchain with known detection quality, and results that cannot be quietly edited |
| 5 | **Governance** | Roles, separation of duties, approval of risk acceptance, SSO, an immutable audit trail, retention matching the regime |

Need 3 is the one that looks fatal and is not: **hibou's deployment model is
the stronger answer for the most sensitive buyers**. Code that never leaves
the customer's network needs no third-party cloud authorization, and
air-gapped and classified environments cannot use a SaaS scanner at all,
whatever its clearances (`COMPARISON.md` already notes Veracode "cannot serve
air-gapped environments"). The work for need 3 is making hibou *easy to put
inside a customer's authorization boundary*, not obtaining FedRAMP.

### The trust gap of a self-hosted tool

Veracode's reports carry weight for a reason the table above understates:
**the scan runs on a third party's infrastructure**. The customer uploads
code; Veracode runs the analysis and issues the result. The customer can
choose what to upload but cannot edit what comes back.

Hibou inverts that. It runs in the customer's environment, under the
customer's administrators, with the customer's keys. Anything hibou signs
with an instance key, the customer could have signed with any content: the
signature proves integrity after export, not honesty. A naive "signed
compliance certificate" from a self-hosted tool is therefore weaker than it
looks, and an informed auditor knows it.

Two facts keep this from being fatal:

- **Auditors already accept customer-run tools.** On-premise Fortify,
  Checkmarx and SonarQube are standard evidence in PCI DSS and ISO 27001
  audits. The auditor does not trust the tool; they test the controls
  around it: who can change results, whether there is an audit trail,
  whether exceptions are approved, whether scans ran on the stated cadence.
  Vendor "verified" badges are the vendor's own attestation; no PCI DSS or
  HIPAA requirement asks for one.
- **Trust can be moved off the administrator** without moving the code: by
  making results reproducible by someone else, by having the CI platform
  rather than hibou vouch for each scan, and by anchoring history outside
  the instance so it cannot be rewritten unnoticed. That is the § "Trust
  without SaaS" below.

### What hibou already has

| Need | Already in hibou |
|---|---|
| 1 Mapping | CWE on every finding with OWASP Top 10 2021 and CWE Top 25 sets (ADR-037); ISO 27001 evidence export; CRA automation (ADR-031) |
| 2 Reports | Compliance report export per repository and date (`internal/compliance`); VEX (ADR-009); SBOM ingestion and comparison |
| 3 Clearance | Single binary (ADR-001); self-hosted Helm chart (ADR-006); configurable mirrors for KEV, EPSS, CVE feed; reproducible builds (ADR-011) |
| 4 Testing | Quality gates with fail-closed CWE policy; KEV block (ADR-032); bundled scanners and coverage policy (ADR-035, ADR-036); CVSS computed from vectors, EPSS (ADR-038) |
| 5 Governance | Audit log; fine-grained tokens and service principals (ADR-020, ADR-022); acceptances with reasons and expiry (ADR-023); tiered retention (ADR-014) |

### What is missing

- **Framework mapping as a product**: no PCI DSS, NIST SSDF, NIST 800-53,
  SOC 2, HIPAA or DORA/NIS2 views; ISO 27001 and CRA are one-offs, not a
  model.
- **Application policy status**: gates judge a pull request; nobody can ask
  "does application X pass policy today, and since when?", which is what a
  Veracode policy scan answers.
- **Remediation SLAs** per severity, with breach tracking.
- **Verifiable reports**: exports are not signed, and do not record enough
  (scanner versions, ruleset hashes, snapshot ids) to be re-derived.
- **Separation of duties**: whoever can accept a risk can approve it.
- **Enterprise identity**: no SAML/OIDC SSO, no SCIM.
- **Authorization package for hibou itself**: no FIPS mode, no hardened image
  baseline, no control statements, no PSIRT.
- **Detection credibility**: no published detection benchmarks for the
  bundled scanner configuration.

## Decision

Hibou competes as a **self-hosted evidence and governance platform**: it runs
inside the customer's boundary, orchestrates or ingests scanners, applies one
policy, and produces evidence an auditor can verify without trusting the
customer's administrators. It does not try to become a cloud scanning vendor.

### Trust without SaaS

The layers below close most of the gap described in Context. None of them
sends code or findings out of the customer's environment; layer 5 sends
digests only. Each layer is an item of the plan.

| Layer | What it proves | Who must be trusted instead of the hibou admin | Item |
|---|---|---|---|
| **Reproducible scans** — scanner images pinned by digest, ruleset digests and an advisory-database snapshot recorded per report; `hibou reproduce --commit X --report R` re-runs the scan elsewhere and compares result digests | The result follows from the commit and the pinned toolchain | Nobody: anyone with repository access can re-run it ("don't trust, re-run") | 9 |
| **CI-signed scan provenance** — scans emit in-toto / SLSA attestations signed with the CI job's identity (Sigstore keyless with GitHub Actions or GitLab OIDC tokens); hibou verifies and stores them on upload | Workflow W at commit X ran scanner Y and produced this SARIF digest | The CI platform (weaker when the CI is self-hosted too) | 5 |
| **Tamper-evident history** — scans, results, acceptances and approvals in an append-only hash chain whose head is regularly timestamped by an RFC 3161 timestamp authority or Sigstore's public log; air-gapped instances export the head and anchor it from a connected machine | History was not rewritten after time T | The timestamp authority | 6 |
| **Auditor role** — time-limited read-only access for an external auditor to check signatures and anchors, sample findings and trigger a reproduction | The auditor checks instead of receiving a PDF | The auditor | 10 |
| **Digest-only notary** — a small service run by whoever backs hibou receives hashes and signed manifests, never code or findings; it verifies the provenance chain, countersigns and timestamps the report, and publishes a verification page | An independent party vouches for the report's chain | The notary operator | 19 |
| **Vendor-operated single tenant** — hibou run by the vendor inside the customer's own cloud account (e.g. GovCloud) | The scan ran on infrastructure the vendor operates | The vendor, as with Veracode, while the code stays in the customer's tenancy | 20 |

What remains, stated in every report's methodology section: a customer that
controls both its CI and hibou could fake results before anything is
signed. That holds for every on-premise scanner auditors accept today; the
layers make faking detectable and checkable, which is what an audit tests.

### Short term (0–3 months): make the evidence auditable

1. **Compliance frameworks as data.** Like the embedded CWE catalog, each
   framework is a versioned catalog of requirements, and each requirement
   maps to evidence hibou can compute:
   - finding queries (the filter grammar, so a mapping is inspectable:
     `cwe-set:owasp-a03 status:detected`);
   - process facts: scan cadence met, gate enforced on the protected branch,
     SBOM present, SLA breaches, approved exceptions, provenance verified.

   First set: **PCI DSS v4.0** (Req. 6.2–6.4, 11.3), **OWASP Top 10 / ASVS**,
   **NIST SSDF (SP 800-218)**, **NIST SP 800-53** (RA-5, SA-11, SI-2, CM-8,
   SR-3/SR-4), **ISO/IEC 27001:2022** (A.8.8, A.8.25–A.8.29; replacing the
   one-off export), **SOC 2** (CC7.1), **HIPAA Security Rule**
   (§164.308(a)(1) risk analysis and management). CRA (ADR-031) moves onto
   the same model. Each requirement says plainly whether hibou **covers**,
   **supports** (evidence for part of it) or **does not address** it, with
   no implied coverage.
2. **Application policy and status.** An org-level policy (severity caps,
   denied CWE sets, KEV, license policy, required scan types and cadence)
   evaluated continuously per application, the default branch's latest
   snapshot, with the result kept as history: *passes*, *passes within
   grace*, *does not pass*, and since when. This is the "policy scan"
   verdict regulated teams report upward, built from the gates that
   already exist.
3. **Remediation SLAs.** Time-to-fix targets per severity, with KEV due
   dates taking precedence (ADR-032). Breaches surface in the policy
   status, the dashboards and the reports; the clock starts at
   `first_seen_at` and stops at resolution or approved acceptance.
4. **Recomputable reports.** Every compliance export (PDF for people, JSON
   for tools) records its scope, the snapshot ids, the scanners with their
   image and ruleset digests, the advisory snapshot, the policy version and
   the provenance and anchor references of what it summarizes. A verifier
   (`hibou verify-report`) recomputes the summary from that data and checks
   every reference. The report is signed with the instance key **for
   integrity only**, and its methodology section says so: the trust comes
   from items 5, 6, 9, 10 and 19, never from the instance signature. This is
   the honest form of an "exportable compliance certificate".
5. **CI-signed scan provenance** (Trust layer). Hibou's upload action and
   bundled scan steps emit in-toto attestations signed keylessly with the
   CI job's OIDC identity; hibou verifies the signature, the workflow
   identity and the SARIF digest on upload, records the result per scan,
   and policy can require verified provenance for protected branches.
6. **Tamper-evident history** (Trust layer). An append-only hash chain over
   scans, results, acceptances, approvals and policy changes; the chain head
   is timestamped at least daily by a configurable RFC 3161 authority or
   Sigstore's public log, with a manual export/import path for air-gapped
   instances. The audit log export includes the chain and its anchors.
7. **Four-eyes risk acceptance.** Accepting a high or critical finding,
   or extending an expiry, requires an approver other than the requester,
   configurable per severity. Approvals land in the hash chain and in the
   reports.
8. **SSO and provisioning.** OIDC and SAML 2.0 login, SCIM 2.0
   provisioning, group-to-role mapping. Without it a regulated buyer stops
   reading.

### Medium term (3–9 months): make hibou easy to authorize

9. **Reproducible scans** (Trust layer). Scanner images pinned by digest,
   rulesets by digest, and the advisory database by snapshot; each report
   records them. `hibou reproduce --commit X --report R` re-runs the scan in
   any environment with repository access and compares result digests,
   explaining any difference (a non-deterministic rule, a missing snapshot).
   Deterministic analysers (pattern SAST, secrets, IaC) reproduce exactly;
   dependency analysis reproduces once the advisory snapshot is pinned.
10. **Auditor role** (Trust layer). A time-limited, read-only role an
    organisation grants to an external auditor, scoped to applications and a
    period, able to verify reports, provenance and anchors, sample findings
    and request a reproduction. Its own access is in the hash chain.
11. **Scanning coverage parity by default.** Finish ADR-035/036: SAST for
    the mainstream languages, SCA, secrets, IaC, containers, and a DAST
    baseline (OWASP ZAP), all bundled, version-pinned and offline-capable.
    Coverage policy proves "every application scanned by every required
    scan type within its cadence", the first thing an auditor asks.
12. **Air-gap kit.** One documented bundle: images, the advisory
    databases (OSV export, Trivy DB, CVE list, KEV, EPSS) and an update
    procedure for disconnected networks, including the anchor export of
    item 6. The mirror URLs exist; the kit and its runbook do not.
13. **FIPS 140-3 mode.** A build using Go's native FIPS 140-3 cryptographic
    module (`GOFIPS140`), restricted to approved algorithms, documented with
    the module's CMVP status as of each release. Required by US federal and
    many financial environments.
14. **Hardened deployment baseline.** Minimal non-root images, read-only
    root filesystem, network policies, Helm values aligned with CIS
    Kubernetes and the DISA container hardening guidance, and the deviations
    listed.
15. **"Hibou in your authorization package".** Customer-facing
    documentation: NIST 800-53 control implementation statements for the
    controls hibou implements or supports, a shared-responsibility matrix,
    data flow and threat model (`docs/THREAT-MODEL.md`), ready to paste into
    a System Security Plan.
16. **Hibou's own supply chain.** Signed releases, SBOM and SLSA provenance
    for every artifact, VEX for hibou's own dependencies, a security policy
    and PSIRT process with published advisories. Hibou has to meet the bar
    it checks.
17. **Evidence for customers' own attestations.** Generate the evidence
    behind the CISA Secure Software Development Attestation (NIST SSDF
    practices) and the CRA technical documentation from hibou data, so the
    tool helps its users attest, not just itself.
18. **Migration path.** Import Veracode results (SARIF, or its JSON
    exports via a converter) and run both in parallel for a period, with
    a parity report: findings each platform reports that the other does
    not, by CWE and severity. Replacing an incumbent is a measured
    decision, not a leap.

### Long term (9–24 months): third-party trust

19. **Digest-only notary** (Trust layer). A small hosted service operated
    by whoever backs hibou: instances submit report manifests, provenance
    attestations and chain anchors (hashes and signatures only); the notary
    verifies the chain, countersigns, timestamps and publishes a
    verification page an auditor can open without access to the customer.
    Its compliance footprint is that of a metadata service, far smaller
    than a SaaS scanner's, but it is an operated service with an
    availability and retention commitment.
20. **Vendor-operated single tenant** (Trust layer). Hibou deployed and
    run by the vendor inside the customer's own cloud account (for example
    AWS GovCloud), for customers who want "a third party ran the scan"
    while keeping code in their tenancy. Built only with paying demand.
21. **Published detection benchmarks.** Run the bundled scanner
    configuration against public suites (OWASP Benchmark, NIST SARD/Juliet
    test cases) on each release and publish the true and false positive
    rates per CWE. This answers "how good is the testing" with data instead
    of a brand.
22. **Independent assessments of hibou.** Recurring third-party
    penetration tests with published summaries. If a company stands behind
    hibou: SOC 2 Type II and ISO/IEC 27001 certification of that
    organisation's development, support and notary operations, which is
    what those certifications attest. A self-hosted product cannot itself be
    "SOC 2 certified".
23. **Government channels where they apply.** For US DoD, a hardened image
    listed in Platform One's Iron Bank. For a hosted offering, if one is
    ever built (item 20 is the closest): FedRAMP (Moderate) or StateRAMP
    through a 3PAO, a multi-year commitment taken only with paying demand.
    The self-hosted path stays primary.
24. **Auditor familiarity.** Framework mappings reviewed by practising
    assessors (a PCI QSA, an ISO 27001 lead auditor) and the review
    published with the mapping version. An auditor who has seen the mapping
    before accepts it faster.

### Non-goals

- **Hibou does not become a SaaS scanning vendor** to compete on cloud
  clearances. The self-hosted model is the differentiator; item 20 runs in
  the customer's tenancy, not a shared cloud.
- **No report or "certificate" that claims more than it proves.** An
  instance signature is integrity, not trust; reports attest testing,
  policy and evidence; certification of an organisation is an auditor's
  act, not a tool's.
- **No code or findings leave the customer** for any trust feature. The
  notary sees digests only.
- **No proprietary scanning engine** to match Veracode's binary analysis
  in this plan. Hibou orchestrates best-of-breed open scanners and ingests
  commercial ones; the benchmark (item 21) keeps that choice honest.

## Consequences

- The pitch changes from "a dashboard over your scanners" to "the evidence
  system your auditor accepts, running where your code already is".
  `COMPARISON.md` is updated as each item ships, including the rows still
  missing.
- Framework catalogs become maintained data with versions (PCI DSS v4.0.1,
  ISO 27001:2022…), like the CWE catalog: someone owns their updates.
- The trust layers add infrastructure: a timestamp authority or
  transparency log reachable (or a manual anchoring routine for air-gapped
  sites), CI identities to verify, pinned scanner images to keep available
  for reproductions, and instance keys to rotate. Each is configuration
  with a documented default, not a hard dependency.
- Reproducibility constrains the scanners hibou bundles: a scanner whose
  output is not deterministic for a pinned input is either configured to
  be, or flagged as non-reproducible in reports.
- Four-eyes acceptance and SLAs add friction teams outside regulated
  sectors do not want; both are policy settings, off by default.
- Items 19, 20, 22 and 23 cost money and organisational commitments, not
  just engineering. They are listed so the plan is honest about what full parity
  takes; they are gated on demand.
- Some buyers will still require a vendor on an approved list. Until items
  19–24 exist, hibou wins where self-hosting, air-gap or cost decide, and
  loses where procurement requires a recognised brand.

## Alternatives considered

- **Pursue FedRAMP first.** It certifies a cloud service the product does
  not offer, takes a sponsoring agency and a 3PAO, and does nothing for
  self-hosted or air-gapped buyers. Rejected as a starting point; kept as an
  option for a future hosted offering (item 23).
- **Position hibou alongside Veracode, never instead of it.** Lower
  ambition, and the current `COMPARISON.md` stance. Rejected as the goal:
  the evidence and governance layer is most of what regulated buyers pay
  for, and it is the part hibou can own.
- **Build a commercial-grade proprietary SAST engine.** Years of work
  against mature incumbents and open engines that are already strong.
  Rejected in favour of orchestration plus published benchmarks.
- **Sign reports with the instance key and call it trusted.** Simple, and
  misleading: the customer holds the key. Rejected; the instance signature
  is kept for integrity and labelled as such (item 4).
- **Ship framework mappings as static documents.** Cheaper, but a PDF
  mapping cannot produce evidence for a given date or show a gap. Rejected
  for frameworks as data (item 1).

## Success criteria

Hibou can replace a Veracode-class platform for a regulated customer when:

1. A PCI DSS, ISO 27001 or SOC 2 audit closes the secure-development and
   vulnerability-management controls with hibou reports as the only
   evidence.
2. A US federal or defence customer authorizes hibou inside its boundary
   using the FIPS build, the hardened baseline and the control statements.
3. A parallel run shows no unexplained detection gap per CWE against the
   incumbent (item 18), within the benchmark rates published (item 21).
4. An external auditor verifies a report end to end (provenance, anchors,
   a reproduction) through the auditor role, without trusting the
   customer's hibou administrators.

## Open questions

- **Which framework first.** PCI DSS v4.0 has the most precise
  secure-development requirements and the widest audience; NIST SSDF ties
  to the US federal attestation. Proposal: PCI DSS and SSDF together, since
  their evidence overlaps.
- **Anchoring default.** RFC 3161 authority or Sigstore's public log by
  default, and the cadence; air-gapped sites anchor manually either way.
- **Notary operator.** Item 19 needs an organisation to run it with a
  retention commitment; until then items 5, 6, 9 and 10 carry the trust.
- **Who stands behind hibou** for items 19, 20 and 22: certifications attest an
  organisation, and need one.
