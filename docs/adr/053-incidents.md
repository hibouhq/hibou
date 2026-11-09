# ADR-053: Incidents — a generic model, with CRA Article 14 as the first regime

## Status

Accepted — implemented (2026-10-24). Proposed 2026-10-20, revised
2026-10-23. §"Before building" stays open: the design was built as proposed,
and its questions still need the people who run the process.

Refines [ADR-031](031-cra-compliance-automation.md) Phase 1, items 2
("reporting-clock workflow") and 3 ("user notification via CSAF"): the
`report` entity sketched there becomes the **incident** described here.
Closes the item left open by [ADR-032](032-kev-catalog-and-exploited-gate.md)
(the per-advisory exploitation *event* on released snapshots). Builds on the
clients and deployments of [ADR-024](024-release-tracking.md), the VEX model
of [ADR-009](009-vex-integration.md), secret scanning
([ADR-010](010-secret-scanning.md)), the filter grammar
([ADR-013](013-boolean-filter-expressions.md)) and the tamper-evident
history of [ADR-041](041-regulated-environments-replacing-veracode.md)
item 6. Amends [ADR-009](009-vex-integration.md) (statements gain a
version axis, become insert-only, and are the export's only source) and
[ADR-023](023-triage-acceptance-ux.md) (the triage decision writes the
statement, §4a; a secret also resolves by validator-confirmed death, and
its primary action is the revocation checklist, §4). Existing tables change
shape without a compatibility path: the project is pre-alpha.

Implementation notes:

- Migrations `00069_vex_statement_versions` (version axis, supersession,
  approval, `first_party_advisories`, `finding_acceptances.vex_statement_id`)
  and `00070_incidents` (incidents, clocks, scope, actions, documents,
  deliveries, events, tracker links, settings, client delivery config,
  portal tokens, secret attestations). Domain logic is pure and lives in
  `internal/incident` (kinds, regimes and clocks, rule resolution, scope /
  action / closure derivation, vers ranges); `internal/server/incident_*.go`
  gathers facts, persists the derivation and runs the side effects.
- **Supersession** stamps the previous statement's `superseded_at` and
  nothing else: a statement's content is never edited, and a partial unique
  index still guarantees one current statement per scope (the old full
  index allowed no history). Withdrawal inserts a withdrawn row.
- **Exporters rewritten** (`internal/vex/export.go`): deterministic (sorted,
  every timestamp and id from the caller), product-centric (the release is
  the product, the component the subcomponent), CycloneDX added, CSAF uses
  the CSAF 2.0 TLP vocabulary (TLP:CLEAR is written WHITE). Export-time
  synthesis from acceptances and reachability is removed; reachability is
  the statement's evidence.
- The `product` and `incidents` sections of `.hibou.yaml` are persisted in
  `repo_incident_config` each time the file is read, so catalogue-triggered
  sweeps do not call the forge per repository.
- **Roles**: admin and release manager manage incidents; no `security` role
  was added (§"Before building" 9 stays open).
- **Portal** tokens are their own table bound to one client, not ADR-020
  tokens: an ADR-020 token belongs to a user or an organisation, a client is
  neither.
- **Trackers** authenticate with a token stored in the integration, not the
  forge App: ADR-052 grants the App no `issues: write`, and widening it for a
  mirror would contradict it.
- **Re-check** of a secret enqueues a secret scan: hibou keeps hashes, never
  the secret, so only a scanner can ask the validator again.
- **Client documents**: one `csaf_security_advisory` (carrying the per-version
  status and the VEX flags), OpenVEX, CycloneDX VEX, and the notice as HTML
  and text. The final-report filing is owed from the decision, without a
  due date until a fix is recorded.
- The **dossier** is unsigned and says so: the instance has no signing key
  and the anchored log of ADR-041 item 6 is not built, so delivery audit
  entries are ordinary audit rows.
- **The decision writes the statements** (2026-10-24, after the guidance
  C(2026) 5252 §218 confirmed the ladder): recording a ladder step records
  the VEX statement it means (`StepStatement`) for every release in scope
  without one, with the reason as impact statement or the given action
  statement; releases that have a statement keep it, and a later per-release
  statement supersedes the decision's. The form offers one choice among the
  four steps, shows each step's VEX status and justification, and asks T0 for
  the last step only; a release carrying an *affected* statement under a
  "cannot be exploited" decision is flagged. Step 3 ("not exploited here")
  derives the client notices as optional; no upstream notice is derived
  when the advisory has a public identifier, since the maintainer already
  knows (§223).
- **Reference and autolinks** (migration `00073_incident_reference_and_autolinks`):
  `incidents.external_ref` is the incident's ticket or link, edited in the
  header and written to the timeline; completing an action takes a note
  only (filings keep the platform's reference). `org_autolinks` holds the
  organisation's tracker prefixes (`prefix`, `url_template` with `<num>`,
  `alphanumeric`), managed under Settings → General; matching happens in
  the browser (`site/src/lib/autolink.ts`): longest prefix first,
  case-insensitive, word-bounded, `http(s)` targets only, bare URLs linked
  too. Applied to incident notes, timeline details, reasons, the reference
  and finding acceptance reasons. Scope rows link to the finding itself for
  a finding-subject incident and to the list filtered with
  `incident:<number>` for an advisory. The **Resolution map** on the
  Overview tab is built client-side from the detail
  (`site/src/lib/incidentFlow.ts`) and mirrors the derivation. Actions are
  served in the order the work happens (filings by step, then VEX, client
  notices, remediation, upstream notice, final report), not by state, so the
  list reads as the checklist the map shows. Regime steps carry the portal
  URL where the filing is made; the CRA steps point to ENISA's single
  reporting platform and a national regime may set its own.
- Home remembers the previous visit in the browser. **Your repositories**
  reads `user_repo_visits` (migration `00071_repo_visits`): opening a
  repository page in the UI records a visit, at most one per 30 minutes;
  API-token calls (CLI, IDE, CI) are not visits. The rank is visits divided
  by one plus the days since the last one, and every repository listed
  passes the same access check as opening it. "Needs you" shows the eight
  most urgent actions and the rest on request.
- **Merging** is limited to the same kind on the same repository, and for
  exploited vulnerabilities to the same vulnerability: the advisories share
  an identifier and, when both list CVEs, the same CVEs. An advisory that
  groups several CVEs shares an identifier with each without being any of
  them, so a shared identifier alone no longer merges, automatically or by
  hand. The survivor is picked from a list with the reason each other
  incident cannot merge, then confirmed; under four-eyes one person proposes
  (`incidents.proposed_merge`, migration `00072`) and another applies or
  rejects it. A merge moves the timeline, deliveries and completed actions;
  pending actions are dropped and the survivor recomputed. It is not
  reversible.
- `incident:true|false` filters findings by a linked incident (on the
  finding, or on its advisory in the same repository, in any state), the
  same link the finding detail shows. Each repository has an Incidents tab:
  the organization's list narrowed to it.
- `fix:available` is true when the matched affected range names a fixed
  version, read at query time, or the producer reported a remediation.
  Ingest never sets `has_remediation` for dependency findings, so the flag
  alone matched nothing.
- `hibou-server seed` also seeds incidents through the incident service:
  a reportable exploited vulnerability with its clocks running, a delivered
  notice and a statement, undecided signals, a verified secret, malicious
  packages, a manual security incident, a policy breach and a closed
  not-reachable case.

## Article 14 in plain words

This section is for readers who will never open the regulation. The legal
text is Regulation (EU) 2024/2847, Article 14, read with the Commission's FAQ
v1.4 (2026-09-04) and the Commission guidance on the application of the CRA
(Communication C(2026) 5252 of 2026-07-27, section 9.1 on reporting, 9.2.1 on
reporting upstream; approved as a draft, applicable once formally adopted).
Where the FAQ or the guidance is the source, the entry or paragraph number is
given. A user-facing version of this section is the "CRA Compliance" page of
the documentation.

### What it enforces

1. **A reporting duty, live since 11 September 2026.** A manufacturer that
   *becomes aware* of an **actively exploited vulnerability** in one of its
   products, or of a **severe incident** affecting the product's security,
   must notify the CSIRT of the Member State where it has its main
   establishment and ENISA, simultaneously, through the EU single reporting
   platform (Art. 14(1), (3), (7); Art. 16). This applies to every product
   in scope, including products placed on the market before the rest of the
   CRA applies on 11 December 2027 (Art. 69(3), FAQ 5.3).
2. **Three clocks, from the moment of awareness (T0):**

   | Step | Deadline | Vulnerability (Art. 14(2)) | Severe incident (Art. 14(4)) |
   |---|---|---|---|
   | Early warning | ≤ 24 h | that an actively exploited vulnerability exists; the Member States where the product is known to be available, where applicable | that an incident occurred; whether unlawful or malicious acts are suspected |
   | Notification | ≤ 72 h | general information on the product, the general nature of the exploit and of the vulnerability, measures taken, measures users can take | nature of the incident, initial assessment, measures taken |
   | Final report | ≤ 14 days after a corrective or mitigating measure is available | description incl. severity and impact, threat actor where available, the security update or other corrective measures | — |
   | Final report | ≤ 1 month after the notification | — | detailed description, type of threat or root cause, mitigation measures |

   The CSIRT may ask for intermediate status reports in between (Art. 14(6)).
   An incident is "severe" when it affects, or can affect, the availability,
   authenticity, integrity or confidentiality of sensitive or important data
   or functions, or leads, or can lead, to the execution of malicious code
   (Art. 14(5)). A compromised build chain or signing key is the textbook
   case.
3. **Inform the users.** After becoming aware, the manufacturer informs the
   **impacted users** (and, where appropriate, all users) of the
   vulnerability or incident and, where necessary, of the risk mitigation
   and corrective measures they can deploy, "where appropriate in a
   structured, machine-readable format" (Art. 14(8)). This duty is not
   conditioned on a fix being available. It is risk-based and proportionate
   (guidance §220–221): detailed information may be limited to the
   customers concerned and widened once the vulnerability is addressed;
   Annex I Part II point (4) then requires public information on fixed
   vulnerabilities. If the manufacturer delays, the CSIRT may inform the
   users itself (Art. 14(8), FAQ 5.3).
4. **"Actively exploited" has a definition** (Art. 3(42)): *reliable evidence
   that a malicious actor has exploited the vulnerability in a system without
   the owner's permission*. Evidence, not probability. **T0** is when, after
   a prompt initial assessment, the manufacturer has "a reasonable degree of
   certainty" that a vulnerability in its product is being actively exploited
   (guidance §213); a complete forensic investigation is not a prerequisite,
   and the assessment is to be immediate (§214). Exploitation the
   manufacturer already knew of before 11 September 2026 is not reported
   retroactively (§217).
5. **A library vulnerability counts only if it is in, exploitable in, and
   exploited in your product.** The guidance (§218) names the two exits: the
   vulnerability "(i) cannot be exploited in its product with digital
   elements (e.g. because the vulnerable code is not reachable) or (ii) has
   not been exploited in its product with digital elements"; in either case
   it "does not qualify as an actively exploited vulnerability contained in
   its product" and is not subject to mandatory reporting. The FAQ (5.4)
   states exit (i). The manufacturer still handles the vulnerability (Annex
   I Part II), owes the component's maintainer a report under Art. 13(6)
   only for a vulnerability the maintainer does not know about yet — a
   public identifier means they do (§223) — and may notify voluntarily
   under Art. 15.
6. **Awareness is what triggers the duty, however it was reached**: a
   customer report, a CSIRT, a researcher, threat intelligence, telemetry or
   scanning (FAQ 5.1).
7. **Every version users still run is covered**, support status or not. An
   attacked version that is out of support still has to be reported and its
   users informed; a workaround and an upgrade path are acceptable
   corrective measures, a fix of the old version is not required.

### What it does not enforce

- **Not every CVE.** A vulnerability that is merely present, high-severity,
  listed in a known-exploited catalogue, or scored likely-to-be-exploited is a
  reason to *analyse*, not a reporting trigger by itself. The trigger is
  reliable evidence of malicious exploitation of the vulnerability *in your
  product* (guidance §218(ii)). One nuance: a catalogue entry that names the
  manufacturer's **own** product, not a component of it, is itself evidence
  of an attack and should be qualified at once.
- **Not zero-days found in good faith.** A vulnerability reported by a
  researcher, a bug-bounty participant or a testing laboratory, with no
  evidence of prior malicious use, is not reportable (Recital 68, FAQ 5.2).
- **Not a duty to monitor** any particular channel in order to become aware
  (FAQ 5.1, footnote 10). The separate duty to *handle* vulnerabilities
  (Annex I Part II, including a vulnerability contact point and a coordinated
  disclosure policy) applies from 11 December 2027.
- **Not a fix in 24 hours.** The 24 h and 72 h clocks are about telling the
  authorities; the final report follows the fix. Users must be told what
  they can do, which may be a workaround before a fix exists.
- **Not a prescribed format for user information**; machine-readable "where
  appropriate". The regulation names neither VEX nor CSAF. CSAF is the
  obvious candidate, not a requirement. The final report to the authorities
  is filed in the platform's own form; it is not a CSAF document.
- **Not automated submission**: the platform is where a legal act of the
  manufacturer is filed; nothing requires a tool to file it, and the platform
  exposes no machine interface today.
- **Not open-source stewards, yet**: a lighter regime applies to them from
  11 December 2027 (Art. 24(3), FAQ 5.5). Open source supplied outside a
  commercial activity is out of the CRA entirely (Recitals 18–19); whoever
  integrates it into a commercial product carries the duty.
- **Not SaaS.** A service is not a product placed on the market (FAQ 1.2,
  Recital 12); it falls under NIS2 (Directive 2022/2555, Art. 23, with the
  same 24 h / 72 h / 1 month clocks) and the GDPR. A product's cloud
  back-end is in scope as *remote data processing* when the product cannot
  function without it (Art. 3(2)).
- **Not the only rule.** Some Member States add national reporting duties
  with a broader trigger (a "significant" vulnerability, with no exploitation
  criterion) and their own recipient. Legal decides whether they apply;
  the tool must be able to carry them.
- **Not the rest of the CRA**: CE marking, technical documentation, support
  period, SBOM in the documentation, essential requirements — all of that is
  the 2027 wave, covered by ADR-031 Phase 2.

### The decision ladder

Put together, the regulation and the guidelines reduce the "do we report?"
question for a component vulnerability to three steps, each with an exit:

```
component listed in KEV / EUVD
  │
  ├─ 1. Do our versions integrate the vulnerable version?   no ──▶ VEX not_affected (component_not_present); nothing else
  │        (SBOM of each version)
  ├─ 2. Can it be exploited in our product?                 no ──▶ VEX not_affected (not in execute path / not controllable / mitigated);
  │        (call graph, configuration, analyst, tests)               evidence kept; report upstream if the maintainer does not know yet; no filing
  └─ 3. Has it been exploited in our product?
           (customers, hosted-environment logs, CSIRT)        no ──▶ VEX affected; fix or workaround without delay; look for traces;
                                                                     warn concerned users (offered); voluntary notice (Art. 15); no filing
                                                             yes ──▶ T0; early warning 24 h; notification 72 h; users informed; final report
```

The ladder is the guidance's §218 read in order: steps 1 and 2 are exit (i),
step 3's "no" is exit (ii). Every exit, including "do not report", is written
down with its reason. That sentence is the whole requirement on the tool.
The decision is one per incident, for the product; each shipped version
carries its own VEX statement, and the decision writes the statement of the
versions that have none (§4a).

## Context

### The process a manufacturer ends up with

Every manufacturer that reads Article 14 draws the same pipeline:

```
signal ──▶ analyse ──▶ decide (T0?) ──▶ file (24 h / 72 h) ──▶ inform users ──▶ fix ──▶ final report (14 d)
                                           │
                                           └── not exploited here ──▶ VEX "not affected" or "affected", upstream notice if the maintainer does not know, close
```

with a register that records every step, its time, the decision and its
reason, and four questions in the "analyse" step:

1. Is the vulnerability attacked anywhere? (known-exploited catalogues,
   exploit availability, exploitation likelihood)
2. Which versions and which clients are affected, in which countries? (an
   inventory per version, a register of who runs what)
3. Does our code reach the vulnerable part? (reachability)
4. What is the decision, with what proof? (a VEX per version, a register of
   decisions and delays)

Running this in a ticket tracker works for a week. Then tickets drift: the
list of affected versions is typed by hand, one VEX file per version is
managed in a folder, "did client X get the notice for version Y?" is a
question answered by searching a mailbox, and the security team carries the
mental load of checking that nothing was forgotten before saying "closed".
In a dispute, the proof that a notice was sent on time is an email header.

The requirements such a team writes down, question by question, are the
same everywhere: match every version and branch against the catalogues
daily and alert the same day; cover every version in use, including out of
support, and answer "who is affected" within an hour; analyse reachability
for every listed vulnerability; keep each decision with its reason and
evidence and produce the VEX of each version; build on what exists; cover
other products later; require little day-to-day effort; keep the toolchain
itself secure.

### Not only exploited vulnerabilities

The same shape — a signal, a decision, derived actions, evidence, a computed
"nothing remains" — fits other events a security team handles today by
hand:

| Event | Signal hibou already has | Actions a team runs |
|---|---|---|
| A credential is pushed to a repository | `secret.discovered` (ADR-010), with the provider's verification result | revoke, rotate, remove from the ref, assess exposure (public repository? shared forge?), tell the owner of the credential |
| A malicious package enters the inventory | `malware.detected` | remove, rebuild, rotate CI secrets the package could have read, check whether a release shipped it and tell the clients who received it, report to the registry |
| A build chain or signing key is compromised | none; a person declares it | the CRA severe-incident path; warn every client who received deliverables |
| A vulnerability crosses an organisation's own line (critical with a fix, EPSS above a threshold, a CWE on a deny list) on a shipped version | finding attributes, EPSS movements (ADR-040), KEV (ADR-032) | an internal priority fix with an internal deadline, not a regulatory filing |

Each team draws the line differently: one opens an incident on every secret,
another only on verified ones; one treats EPSS ≥ 0.5 on a release as an
incident, another treats nothing short of KEV that way. The model therefore
has to be **generic in its mechanics and configurable in its triggers**, per
repository with organisation defaults, and open to kinds that do not exist
yet.

### What hibou already holds

| Question | Hibou today |
|---|---|
| 1. Attacked anywhere? | CISA KEV and EUVD exploited set mirrored and joined to advisories (ADR-032); EPSS (ADR-038, ADR-040); advisory freshness on released snapshots (ADR-024 §6) |
| 2. Which versions, which clients? | Releases derived from tags and forge releases, pinned snapshots (ADR-024); `clients` with labels, `deployments` (active release per client), `ListClientImpactVulns` |
| 3. Do we reach it? | Call-graph reachability where the language supports it (`internal/callgraph`, finding `reachability`, ADR-049); otherwise the analyst's VEX justification |
| 4. Decision and proof? | VEX statements with status, justification, impact and action statements, expiry, author (ADR-009); OpenVEX, CycloneDX and CSAF export (`internal/vex`); audit log; ADR-041 item 6 hash chain (planned) |
| Inform users | Email, Slack, Teams, Discord, webhook senders with delivery records and audit entries (`internal/notify`); `clients.contact_email`, `clients.notification_prefs` |
| Fix | Remediation pull requests on release branches (ADR-050) |
| Triggers | the filter grammar over findings (ADR-013, ADR-021, ADR-038 §6): `exploited:true`, `epss:>=0.5`, `cvss:>=9`, `severity:critical`, `type:secret`, `type:malware` |

Every fact the process needs is in the database. What is missing is the
object that ties them together and says, at any moment, either **"these
actions remain"** or **"nothing remains, closed"**.

### What is missing

1. **No incident.** Nothing represents "this advisory, in this product, is
   being handled under Article 14", nor "this leaked key is being revoked".
   ADR-031 named the entity (`report`) and its clocks but not what makes it
   complete.
2. **No derived checklist.** Which VEX statements must exist, which clients
   must be told, which filings are due: all of it is computable from
   advisory × releases × active deployments × clients, and none of it is
   computed.
3. **No exploitation event.** ADR-032 mirrors the catalogues but does not
   raise an event when an advisory matched on a *released* snapshot enters
   one of them. The signal exists; nothing wakes anyone.
4. **No per-repository line** saying which findings deserve an incident.
5. **No client delivery.** Notifications go to the org's own integrations,
   not to a client's security contact, and carry no document.
6. **No proof of delivery.** Delivery records serve integration health. They
   do not say which document, with which digest, reached which recipient at
   which time, in a form a third party can check later.
7. **No automatic closure.** The security team closes by conviction.
8. **No tracker link.** Teams that live in a ticket tracker get no mirror of
   the incident there and have to type it twice.
9. **No home.** A signed-in user lands on the organisation onboarding page,
   whatever the state of their organisations.

## Decision

Hibou gets an **incident**: an org-scoped object of a declared **kind**,
opened by a **trigger** configured per repository, that derives the
**actions** its kind requires from the data hibou already holds, records
every step with its time and reason, delivers documents to the people who
must be told with a verifiable record, mirrors itself into the team's
tracker if they have one, and closes itself when no action remains.

The principle: **the tool never decides, and never forgets.** Humans decide
exploitation, T0, scope and content. Hibou derives what follows from those
decisions, keeps the clocks, delivers, records, and refuses to call the
incident closed while anything is pending.

### 1. Kinds, regimes, triggers

Three concepts, kept apart because they vary independently:

- A **kind** says what the incident is about and how its scope and actions
  are derived. Kinds are code: a registry in `internal/incident` where each
  kind implements `Scope`, `Actions` and `Closure` over the incident and the
  store. First set:

  | Kind | About | Scope | Derived actions |
  |---|---|---|---|
  | `exploited_vulnerability` | an advisory on a shipped product: a component advisory, or a first-party record (§4a) | releases matching the advisory × active deployments | `vex` per release, `client_notice` per client, filings per regime, `fix_release`, `upstream_notice` (component case only) |
  | `severe_incident` | a declared event (build chain, signing key, hosted environment) | entered by hand: releases, clients | filings per regime, `client_notice`, `remediation` (free-form, evidenced) |
  | `secret_leak` | a secret finding; the incident is a view over the finding's own lifecycle (§4) | the refs and forks where the secret is present; exposure (public, shared forge) | `revoke` (checklist or validator-confirmed dead), `rotate`, `assess_exposure`, `remove` (auto, hygiene only), `notify_owner` |
  | `malware` | a malicious package in the inventory | refs containing it × releases that shipped it × deployments | `remove_package` (auto), `rotate_ci_secrets`, `client_notice` when shipped, `report_registry` |
  | `policy_breach` | a finding crossing the organisation's own line | the finding's refs and releases | `fix` with an internal due date, `acceptance` (an approved exception closes it) |

  A new kind is a Go type and a migration for any extra table it needs; the
  incident core, timeline, deliveries, tracker mirror, dashboard and API do
  not change. This is the extension point for later use cases.

- A **regime** says which external obligations attach: clocks, filings,
  recipients. Regimes are data (a versioned catalogue, as ADR-041 item 1
  does for frameworks):

  | Regime | Clocks from T0 | Filings | Users to inform |
  |---|---|---|---|
  | `cra-article-14` | 24 h, 72 h, final 14 d after measure (vulnerability) or 1 month (incident) | `srp_early_warning`, `srp_notification`, `srp_final_report` | impacted users, machine-readable where appropriate |
  | `nis2-article-23` | 24 h, 72 h, 1 month | `csirt_early_warning`, `csirt_notification`, `csirt_final_report` | recipients of the service, where appropriate |
  | `national:<code>` | as configured | as configured (name, due, recipient) | — |
  | `internal` | the organisation's own targets | none | — |

  A kind may carry several regimes at once (CRA plus a national rule); each
  adds its filings and the earliest deadline drives the countdown. An
  organisation may set internal targets stricter than a regime (48 h instead
  of 72 h); the regulatory deadline is always shown next to the internal
  one.

- A **trigger** says when a signal opens an incident of a kind, per
  repository. Triggers are filter expressions over findings, the grammar
  users already know, evaluated on new or changed findings of the configured
  refs:

  ```yaml
  # .hibou.yaml
  incidents:
    owner: team:product-security          # who receives signals and countdowns
    rules:                                # first matching rule wins
      - match: "exploited:true"           # refs: released (default for vulnerabilities)
        regimes: [cra-article-14]
        priority: P1
      - match: "type:secret verified:true"  # refs: all (default for secrets and malware)
        priority: P1
      - match: "type:malware"
        priority: P1
      - match: "epss:>=0.5 OR (severity:critical AND fix:available)"
        refs: [released, default]         # released snapshots and the default branch
        due: 7d
        priority: P2
      - match: "type:secret"
        priority: P3
  ```

  A rule has one required field, `match`. The **kind is derived** from what
  matched: `type:secret` → `secret_leak`, `type:malware` → `malware`,
  `exploited:true` → `exploited_vulnerability`, anything else →
  `policy_breach`. `kind:` may be written to override, and is refused when
  the finding cannot carry it (a `secret_leak` on a dependency). `refs`
  says on which snapshots a finding must appear to count. A ref is what
  hibou scans a repository at — a branch, a tag or a pull-request head;
  every snapshot belongs to one — and the rule accepts three reserved
  keywords and globs: `default` (the latest snapshot of the default
  branch), `all` (the latest snapshot of every ref, pull requests
  included), `released` (the snapshots pinned by a release, ADR-024,
  whatever ref produced them — a selector over releases, not a ref name),
  or a glob over branch names such as `release/*`, the syntax
  `dependencies.branches` already uses; a list combines them. **The
  default follows the kind**:
  `all` for `secret_leak` and `malware`, because a credential or a
  malicious package is a problem the moment it exists anywhere; `released`
  for `exploited_vulnerability` and `policy_breach`, because the gate
  already stops those from entering and the incident is about what
  shipped. `regimes` defaults to `[internal]`; `priority` to `P2`; `due`
  applies to `policy_breach` only. The first three rules above are the
  built-in defaults, so a repository that writes nothing still opens
  incidents on exploited, verified-secret and malware findings; writing
  `rules` replaces the list, writing nothing keeps it.

  The grammar is the one of ADR-013 and ADR-038 §6, unchanged: comparisons
  are written `key:>=value` (`epss:>=0.5`, `epss:>=10%`, `cvss:>=9`,
  `epss-percentile:>=95%`), exploitation is `exploited:true`. Two keys are
  added for triggers and the search bar alike, since the columns exist:
  `fix:available|none` (a fixed version is known) and `verified:true|false`
  (a secret the validator confirmed live). The filter bar already completes
  comparison values (`epss:` offers `>=10%`, `>=1%`, `none`, and renders a
  typed comparison in words); the keys are only hidden from the chip row,
  so nobody finds them. They become visible under a *Risk* group, the new
  keys get the same value completion, and the trigger `match` field in the
  repository settings is the same filter bar component, so a trigger is
  written, completed and explained exactly as a search.

  Organisation settings hold the defaults; a repository's `.hibou.yaml`
  overrides them; an org admin may lock a rule so repositories cannot weaken
  it (the ADR-032 stance: KEV on a released snapshot always opens an
  `exploited_vulnerability` signal unless the org says otherwise). `priority`
  is the team's own P1–P3 triage order and sorts the dashboard; it is not a
  regulatory concept. A person can always open an incident of any kind by
  hand (`customer`, `csirt`, `researcher`, `internal` signal sources).

  Alert volume is the known risk of a wide trigger, EPSS especially. Three
  guards: the trigger applies to `released` refs by default, not to every
  branch; a VEX `not_affected` on the advisory closes the incident and
  suppresses re-triggering for that (advisory, release); the dashboard
  surfaces trigger rules that opened more than N incidents in a week.

### 2. Signals open draft incidents; people decide

An automatic trigger creates the incident in state `signal` and notifies the
owner through the existing dispatcher: a pre-filled summary by mail to the
security mailbox and a line in the team channel, nothing else. It does
**not** set T0. FAQ 5.1 and 5.4 are explicit: a catalogue entry is evidence
that the vulnerability is exploited *somewhere*, not that it is exploitable
in this product. The ADR-032 gate already blocks the *introduction* of such a
dependency; the incident covers what is already shipped. For
`exploited_vulnerability`, hibou diffs the catalogue entries against
advisories matched on snapshots pinned by a release (closing ADR-032's open
item) and raises `advisory.exploitation_observed`. The diff runs after
every catalogue sync **and** after every advisory refresh: the catalogues
are keyed by CVE, and an advisory hibou first knew under a GHSA only joins
a catalogue entry once the CVE alias arrives, so a KEV listing can predate
the alias by a refresh cycle. The catalogue entry is never invalidated by
later advisory changes; the incident simply carries the latest data.

The **decision** step moves the incident to `reportable` or
`not_reportable` (kinds without a regime use `confirmed` / `dismissed`).
"Reportable" means owed to the authorities under Art. 14; what is owed to
clients (Art. 14(8), Annex I Part II) and to the component maintainer
(Art. 13(6)) is derived per step, and the UI names the audience in every
step's wording so the three are never confused. The decision requires:

- the decision reason (free text, mandatory), with the ladder step reached
  for `exploited_vulnerability` (not present / not reachable / reachable, no
  attack / attacked);
- for `reportable`: `aware_at` (T0), defaulting to now, editable backwards
  only, never after a filing;
- the decider, taken from the session; four-eyes (ADR-041 item 7) applies to
  `not_reportable` and `dismissed` when configured, since those are the
  decisions that hide.

Analysis aids are proposals, never decisions: the call graph's reachability,
an assistant's reading of the code, a scanner's "vulnerable method called"
are shown with their source, and the VEX justification the analyst records
names which evidence was relied on. Where an automated aid concluded "not
reachable", the record says so, so that a wrong aid is traceable.

### 3. Scope is derived, then confirmed

For `exploited_vulnerability`, hibou computes the **scope** when the
incident opens: every release of the product repository whose pinned
snapshot matches the advisory, joined to the clients with an active
deployment of that release and the countries their labels give. The analyst
sees one row per release:

| Release | Matched component | Reachable | Clients (active) | Statement |
|---|---|---|---|---|
| 4.2.1 | pkg:maven/… | yes (call graph) | 3 | *affected* |
| 4.1.0 | pkg:maven/… | unknown | 1 | *affected* |
| 3.9.4 | pkg:maven/… (different code path) | no | 2 | *not affected*, `vulnerable_code_not_in_execute_path` |
| 3.2.0 | no inventory for this release | — | 1 | *unknown*: SBOM to produce from the tag, or a version range assumed |
| 2.x | not matched | — | 1 | *excluded*, out of product scope, reason recorded |

Each row ends with exactly one of: a VEX statement (`affected`,
`not_affected` with justification, `fixed`, `under_investigation`), or an
explicit exclusion with a reason. A release with an active deployment but no
pinned snapshot is shown as *unknown* and blocks closure until an inventory
is produced (re-extracted from the tag, ADR-045) or the analyst assumes a
status with a reason. The conservative default is every release with an
active deployment, support status or not; excluding a release line is a
recorded decision, never a filter.

**Advisory data moves under the incident.** Identifiers, descriptions and
scores change most in the first weeks of a vulnerability's life: a GHSA
precedes the CVE, a reserved CVE gets content, EUVD adds its identifier,
NVD scores days after the CNA and differently, two identifiers merge, one
is rejected. Hibou's canonical advisory already absorbs this (ADR-007
aliases, ADR-038 ratings, ADR-028 divergence); the incident model adds four
rules. Statements and incidents bind to the canonical advisory *row*, never
to an identifier string, so a new alias changes nothing but the next
document's identifier list — which is also how a first-party record moves
from a vendor identifier to a CVE. Documents embed the advisory as of send
time (identifiers, description, scores recorded in the delivery's inputs);
the on-the-fly export shows current data. A changed score changes no
decision: `not_affected` is about reachability and exploitability; the new
score re-evaluates the triggers of §1 and appears in the next document
version, and never reopens a closed incident. When two canonical advisories
merge, their open incidents on one product merge too: the survivor absorbs
scope, actions, deliveries and timeline with a `merged` event, nothing is
deleted; an advisory rejected upstream proposes `withdrawn` with the reason,
and a person confirms, since documents already sent stay valid as sent.

The scope is **recomputed** on every change to releases, deployments or the
advisory match. A new deployment of an affected release, or a client newly
assigned to one, adds a row with a pending action and, if the incident was
closed, reopens it with a timeline entry saying why. Other kinds derive their
scope the same way from their own facts (`secret_leak`: refs where the
fingerprint is present; `malware`: refs and releases containing the
package).

### 4. Actions are derived, never typed

From the decision and the scope, the kind derives the action list. For
`exploited_vulnerability` under `cra-article-14`:

| Action | One per | Done when |
|---|---|---|
| `vex` | release in scope | a VEX statement for (advisory, release snapshot) exists, is approved if the org requires approval, and is not `under_investigation` |
| `srp_early_warning`, `srp_notification`, `srp_final_report` | incident (`reportable` only) | a person records the filing with the platform's reference and time; hibou pre-fills the content and links to the portal (the regime step carries its URL; national regimes may set one) |
| `client_notice` | client with an active deployment of an *affected* release | a delivery of the client's document set (§5) is recorded as `sent` (or `acknowledged`, when the org requires it); due from T0, not from the fix, since Art. 14(8) is not conditioned on one — the first notice may carry a workaround and a later one the fix |
| `fix_release` | affected release line | a release exists whose snapshot no longer matches the advisory, or a VEX `fixed` statement names it; linked to the ADR-050 pull request when one exists; a person may attach verification evidence (the attack replayed against the fixed build) |
| `upstream_notice` | matched third-party component, when `not_reportable` because not exploitable here, and the advisory has no public identifier (a public one means the maintainer knows, guidance §223) | a person records the Art. 13(6) notice to the component maintainer (ADR-031 item 9) |

**Secrets: the finding is the incident.** A leaked credential already has
a lifecycle on the finding (ADR-023: never resolved by absence, only by a
human attestation), and a second object with a second set of buttons would
be the worst UX available. `secret_leak` is therefore a *view* over the
finding: opening it (by trigger or by hand) adds the owner, the countdown,
the timeline and the dashboard presence; its actions are the finding's own
and are completed from the finding. Four changes to the finding make that
work, and amend ADR-023:

- **Proof beats attestation.** Scanners with validation already tell hibou
  whether the credential is live (`valid`) or dead (`invalid`, `revoked`);
  today that only moves severity. A **Re-check now** action runs the
  validator; a confirmed-dead result resolves the finding with the
  validation record as evidence, no attestation needed. Transient results
  (`unknown`, errors, rate limits) never resolve. ADR-023's invariant
  becomes: a secret resolves by attestation *or* by validator-confirmed
  death, never by absence.
- **The attestation is a short checklist, not a text box**: *revoked at the
  provider* (required: where, by whom, a link or ticket), *rotated* (new
  credential deployed, or "not needed" with a reason), *exposure*
  (pre-filled from repository visibility, forks and how long the secret
  sat in history; confirmed by a person). A free-text note stays.
- **The primary action follows the state.** Live or unverified: **Revoke…**
  (the checklist). Validator-dead: a *Resolved* chip, with *Record
  rotation* as the only follow-up. **Accept risk** on a live credential is
  behind the menu, requires an expiry and the four-eyes rule. **False
  positive** stays for placeholders and fixtures. The row's split button
  today shows *Accept* first with *Mark revoked…* in the menu, the
  opposite of what ADR-023 specified; that is fixed with this.
- **Removal is tracked, not required.** `remove` is automatic when the
  fingerprint is absent from every scanned ref, shown as hygiene; it never
  resolves, because the value stays valid in history until revoked.

The incident's derived actions are then exactly: `revoke` (checklist or
validator), `rotate` (checklist), `assess_exposure` (checklist), `remove`
(automatic), and `notify_owner` — a delivery (§5) to the credential's owner
when it is not the team's own, or a `client_notice` when the secret shipped
in a release. A signing key or a build-chain credential escalates to
`severe_incident` by a person's decision, carrying the finding with it.
For `malware`:
`remove_package` is automatic; `rotate_ci_secrets` is manual; `client_notice`
derives exactly as above when a release shipped the package.

Every action carries `due_at` (from the regime's clocks or the trigger's
`due`), `state` (`pending`, `done`, `waived`), the evidence that made it
done, and, for `waived`, who and why. Waiving is the sanctioned exception,
audited and four-eyed when configured.

Hibou does **not** submit to the single reporting platform. ADR-031's reason
stands: the filing is a legal act of the manufacturer, and the platform has
no machine interface. Hibou produces the pre-filled content (product,
version, component, advisory, measures, affected Member States from client
country labels when present, "unknown" otherwise) and records the filing a
person makes.

### 4a. Triage is where the VEX is written (amends ADR-023)

The `vex` action of §4 is satisfied by the statements analysts write when
they triage, so the triage dialog must produce statements that stand on
their own. Today it does not, in three ways: "Not exploitable in this
context" is offered as a reason to *accept risk*, which exports a VEX
`affected` statement — the opposite of what was said; a `not_affected`
statement derived from a false-positive decision may carry no structured
justification, although hibou's own `vex_statements` table forbids exactly
that; and "false positive" names both a wrong detection and a correct
detection that is not exploitable in this product, which is the case where
evidence is required.

The rule is simple: **a justification is mandatory exactly when a
`not_affected` statement is produced, and never offered otherwise.** The
standard forbids a justification on `affected`, and a statement needs a
vulnerability identifier: a finding that has none (a SAST, DAST or secret
result, which names a rule and a CWE, not a CVE) gets no statement at all.
The dialog's current wording, "VEX describes third-party component
exploitability; this is a first-party code finding", is wrong on the reason:
VEX is a statement about a *product* and a *vulnerability*, and the
third-party package is only the optional subcomponent. A vulnerability in
the manufacturer's own code with a CVE or a vendor-assigned identifier is a
normal VEX subject (product = the release, no subcomponent), and the case
the ladder's "own product named in a catalogue" branch needs. The wording
becomes "no vulnerability identifier, so no VEX statement".

For findings that carry an identifier the dialog asks the VEX question
first:

| Decision | Required | Exported | Risk reporting |
|---|---|---|---|
| **Not affected** | one of the five justifications (`component_not_present`, `vulnerable_code_not_present`, `vulnerable_code_not_in_execute_path`, `vulnerable_code_cannot_be_controlled_by_adversary`, `inline_mitigations_already_exist`); free text is the evidence detail | `not_affected` + justification + impact statement | excluded |
| **Affected, risk accepted** | action statement (free text); expiry, mandatory when the advisory is known-exploited | `affected` + action statement | counts, flagged accepted |

"Not affected" covers both the wrong detection (first two justifications)
and the correct-but-not-exploitable case (last three), so the "false
positive" wording disappears from dependency findings. For findings without
an identifier the dialog keeps its two decisions and free reason.

**First-party vulnerability records.** Advisories exist in hibou only as
matches on components, so a vulnerability in the product's own code cannot
be the subject of a statement, an incident scope or a CSAF advisory. The
incident model adds a first-party record: an advisory row owned by the
organisation, with its vulnerability identifier (a CVE the manufacturer
requested, or a vendor identifier such as `VENDOR-2026-001` until one
exists), the repository, the affected release ranges, and optionally the
SAST, DAST or manual finding it was promoted from. The *product* is
identified separately, and by two keys with different roles: a **purl** as
the primary one (`pkg:generic/<vendor>/<product>@<version>`, or the
repository's real package coordinates; configured per repository as
`product.purl` in `.hibou.yaml` or taken from the build SBOM's
`metadata.component`; version from the release, ranges in `vers`), which
is what OpenVEX, CycloneDX and hibou itself use, and an optional **CPE**
alias, which is how NVD names the product once a CVE is assigned and how
clients' CPE-based scanners will match it. CSAF carries both in the
`product_tree` helpers. From there the record behaves as any advisory:
scope rows per release, `vex` statements with the release as product and no
subcomponent, CSAF `product_status`, client notices. Promoting a finding to
a record is an audited action; it does not change the finding's own triage.

**The decision writes the statement.** Today the export synthesizes
statements from `finding_acceptances` at request time, with a precedence
dance against stored rows and reachability results, and a `not_affected`
derived that way escapes the table's own justification constraint. That
path goes away. For a finding with an identifier, the triage decision
inserts a `vex_statements` row and the acceptance references it
(`finding_acceptances.vex_statement_id`, required for such findings);
`reason_kind` stays for gate and risk semantics (`false_positive` ⇔
`not_affected`, `risk_accepted` ⇔ `affected`) but the status, justification
and statements live in one place. Reachability results pre-fill the dialog
and are recorded as the statement's evidence; they no longer produce
statements of their own. The export reads `vex_statements` and nothing
else. Automated aids (call graph, assistant) pre-select a justification and
say so; the analyst confirms.

**Statements are scoped to versions and never edited in place.** A
statement today is (advisory, repo, purl): "9.0.2 not affected, 8.4.1
affected" cannot be two rows. It gains a product axis — a `vers` range over
the repository's releases, or a single `release_id` — so the scope table of
§3 is literally the set of statements for one advisory. A change inserts a
new row that `supersedes` the previous one; the current statement is the
one nothing supersedes, and the history is the chain. This is what lets a
document sent on a given day be explained from the rows later, and what
the four-eyes rule of ADR-041 item 7 attaches to.

### 5. Delivery with a verifiable record

Each `client_notice` (or `notify_owner`) action produces a **document set**
for its recipient. For a client under `cra-article-14`:

- the user-facing advisory in CSAF 2.0 (`csaf_security_advisory`), scoped to
  the releases the client runs, carrying the three items of the final report
  (description and severity, threat actor if known, affected versions and
  fix) and the per-version flags that mirror the VEX justifications;
- the VEX statements for those releases: CycloneDX VEX, which is the
  internal record, and OpenVEX;
- a human-readable notice rendered from the same data (HTML and plain text).

Documents are rendered from the rows at send time, then **stored as sent**:
the bytes go to the object store under their SHA-256, the digest and the
structured inputs (statement ids, advisory revision, releases, client) go
to `incident_deliveries.documents`. The on-the-fly export (`GET …/vex`)
keeps serving the current state from the same rows; the stored document is
a snapshot of that output at a point in time, not a second source. The
renderer is deterministic (canonical key order, the timestamp an input),
and `hibou verify-document` re-renders from the stored inputs and compares
with the stored bytes — recomputation verifies the evidence (ADR-041
item 4), it does not replace storing it, because the audit chain anchors a
digest and a document that regenerates one byte differently proves
nothing. A later decision renders and sends a new version; the previous
one stays, as CSAF's `revision_history` expects. The organisation may
require an approval step before the first send (a designated approver
signs off the message); the approval is an audited event.

Delivery channels, chosen per client in `clients.notification_prefs`:

| Channel | Mechanism | Record |
|---|---|---|
| `email` | the org's SMTP integration (`internal/notify/email.go`), recipient = the client's security contacts, documents attached, a signed acknowledgement link | message id, recipients, sent time, document digests |
| `webhook` | a client-registered endpoint, HMAC-signed body | status code, response digest, sent time |
| `portal` | a client-scoped token (ADR-020 scope `incidents:read`, bound to one client) lists and downloads the client's documents | first download time, token id |
| `manual` | the account owner sends by another channel and records it | who, when, what, free-text evidence |

Every delivery writes an `incident_deliveries` row and an audit entry with
the document digests, and that entry lands in the hash-chained log anchored
by an external timestamp (ADR-041 item 6). The claim hibou can make is
exactly: *this document, with this digest, was handed to this channel for
this recipient at this time, and the record has not been altered since the
anchor*. It cannot prove the recipient read it. An acknowledgement (link
click, portal download, webhook 2xx) is recorded when it happens; whether it
is required for `client_notice` to be done is an org setting, default off,
because the obligation is to inform, not to obtain a receipt.

The **incident dossier** export bundles the timeline, the scope with its
statements, the documents, the delivery records and the chain proof. It is
what the manufacturer hands to a market surveillance authority, or to a
client in a dispute. It follows ADR-041 item 4: recomputable, signed by the
instance key for integrity only, and saying so.

### 6. The timeline is the register

Every state change, decision, scope change, action completion, delivery,
approval and waiver appends an `incident_events` row: time, actor, kind,
detail. This is the "register of events: each step, its time, the decision
and its reason" that the process needs; it is rendered as the incident's
timeline and exported in the dossier. Nothing on the incident is edited in
place without an event.

### 7. Closure is computed

An incident is `closed` when, and only when, its kind's closure rule holds;
for `exploited_vulnerability`:

- it is `not_reportable` and every `vex` and `upstream_notice` action is
  done or waived, and no scope row is *unknown*; or
- it is `reportable` and every action, including the regime's final filing,
  is done or waived.

Hibou closes it, with a timeline entry listing what satisfied each action.
A person may not close it earlier; a person may `withdraw` it (wrong
advisory, duplicate) with a reason, which is a terminal state distinct from
closed. Reopening (§3) is automatic.

This is the property the security team buys: at any time the incident page
says either *these actions remain, due by these times* or *closed, here is
why*.

### 8. Tracker mirror

Teams that run their work in a ticket tracker keep doing so. Hibou stays the
source of truth for the incident, its clocks and its evidence, and mirrors
it into the tracker:

- **Jira** (Cloud and Data Center) first, through the existing integrations
  model (`integrations` row with the tracker URL, project key, credentials
  in the secret store, an issue type and a field mapping); then GitHub and
  GitLab issues (the forge App already has the access), then a generic
  webhook pair for anything else.
- **Outbound**: opening an incident creates one issue per incident with a
  back-link, the scope table and the action list in the description;
  timeline events post as comments; action and state changes update labels
  or a mapped status field; the issue key is stored on the incident and
  shown in the UI.
- **Inbound**, optional per integration: a transition of the mirrored issue
  to a mapped status marks a *manual* action done (with the tracker user as
  actor and the transition as evidence); comments with a configured prefix
  append to the timeline. Nothing inbound can set T0, change scope, waive an
  action or close the incident — those stay in hibou, where the
  four-eyes rule and the chain apply.
- Failures of the mirror are integration-health events, never blockers:
  an incident proceeds with the mirror lagging, and the dashboard shows the
  lag.

### 9. Home: a dashboard instead of onboarding

Today a signed-in user lands on `/orgs`, an onboarding page, however many
organisations they have. Once there is at least one, that page answers no
question the user has. The landing route becomes **Home**, a dashboard
across the user's organisations:

- **Needs you**: actions assigned to the user or their team, overdue first,
  then due within 24 h; approvals waiting for them (four-eyes, notice
  sign-off).
- **Incidents**: open incidents across organisations, sorted by nearest
  deadline, with state, priority, regime countdown and owner; a filter per
  kind; the trigger rules that fired most this week.
- **Exposure**: clients on affected releases, releases without an inventory
  that an incident needs, deployments flagged stale.
- **Recent**: gate failures on protected branches, new catalogue hits on
  released snapshots, secrets and malware found since the last visit.
- **Organisations and repositories**, in a side column as on a forge's
  home page: the user's organisations with their open incident counts and
  "Add organization" as a button, then **Your repositories**, the ones the
  user opens most and most recently, filled with recently analysed ones
  until they have opened enough. The full onboarding panel renders only when
  the user has no organisation at all, and the logo leads to Home.

Each tile is a query the API already answers or that this ADR adds; the
page holds no logic of its own. Organisation-level Overview tabs keep their
role for one organisation; Home is the cross-organisation, person-centred
view. The widget set will grow beyond incidents; what this ADR fixes is
the route, the empty-state rule and the first four tiles.

### 10. Data model

```sql
CREATE TYPE incident_state AS ENUM ('signal', 'assessing', 'reportable', 'not_reportable', 'confirmed', 'dismissed', 'closed', 'withdrawn');

CREATE TABLE incidents (
    id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id            uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    repo_id           uuid REFERENCES repositories(id) ON DELETE RESTRICT,   -- null for an org-wide severe incident
    kind              text NOT NULL,                  -- registry key: exploited_vulnerability | severe_incident | secret_leak | malware | policy_breach | ...
    regimes           text[] NOT NULL DEFAULT '{}',   -- cra-article-14 | nis2-article-23 | national:<code> | internal
    subject_type      text,                           -- advisory | finding | package | none
    subject_id        text,
    title             text NOT NULL,
    state             incident_state NOT NULL DEFAULT 'signal',
    priority          text NOT NULL DEFAULT 'P2',     -- P1 | P2 | P3, the team's order
    signal_source     text NOT NULL,                  -- kev | euvd | epss | trigger | customer | csirt | researcher | internal | other
    trigger_rule      text,                           -- the matched expression, for the volume view
    signal_at         timestamptz NOT NULL DEFAULT now(),
    aware_at          timestamptz,                    -- T0, set by the decision
    decision_reason   text,
    decision_step     text,                           -- not_present | not_reachable | reachable_no_attack | attacked (exploited_vulnerability)
    decided_by        uuid REFERENCES users(id),
    owner_id          uuid REFERENCES users(id),
    owner_team_id     uuid REFERENCES teams(id),
    tracker_ref       text,                           -- mirrored issue key
    closed_at         timestamptz,
    created_by        uuid REFERENCES users(id),
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT incident_decision_recorded CHECK (state IN ('signal', 'assessing', 'withdrawn') OR decision_reason IS NOT NULL)
);
CREATE UNIQUE INDEX incidents_open_subject ON incidents (org_id, repo_id, kind, subject_type, subject_id)
    WHERE state NOT IN ('closed', 'withdrawn');       -- one open incident per subject and product

CREATE TABLE incident_deadlines (                      -- one row per regime clock; the earliest drives the countdown
    incident_id uuid NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    regime      text NOT NULL,
    step        text NOT NULL,                        -- early_warning | notification | final_report | internal
    due_at      timestamptz NOT NULL,
    met_at      timestamptz,
    PRIMARY KEY (incident_id, regime, step)
);

CREATE TABLE incident_scope (
    incident_id   uuid NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    subject_type  text NOT NULL,                      -- release | ref
    subject_id    text NOT NULL,
    status        text NOT NULL DEFAULT 'pending',    -- pending | affected | not_affected | fixed | unknown | excluded
    reason        text NOT NULL DEFAULT '',
    vex_statement_id uuid REFERENCES vex_statements(id),
    reachability  smallint,                           -- copied from the finding when known
    decided_by    uuid REFERENCES users(id),
    decided_at    timestamptz,
    PRIMARY KEY (incident_id, subject_type, subject_id)
);

CREATE TABLE incident_actions (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id   uuid NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    kind          text NOT NULL,                      -- vex | srp_* | csirt_* | client_notice | fix_release | upstream_notice | revoke | rotate | remove | ...
    subject_type  text,                               -- release | client | component | ref
    subject_id    text,
    due_at        timestamptz,
    state         text NOT NULL DEFAULT 'pending',    -- pending | done | waived
    assignee_id   uuid REFERENCES users(id),
    done_at       timestamptz,
    done_by       uuid REFERENCES users(id),
    evidence      jsonb NOT NULL DEFAULT '{}',        -- what satisfied it: statement id, delivery id, filing reference, release id, tracker transition
    waived_by     uuid REFERENCES users(id),
    waived_reason text,
    UNIQUE (incident_id, kind, subject_type, subject_id)
);

CREATE TABLE incident_deliveries (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id     uuid NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    client_id       uuid REFERENCES clients(id) ON DELETE RESTRICT,   -- null for a non-client recipient (credential owner)
    channel         text NOT NULL,                    -- email | webhook | portal | manual
    recipient       text NOT NULL,
    documents       jsonb NOT NULL,                   -- [{kind, object_key, sha256}]
    approved_by     uuid REFERENCES users(id),
    status          text NOT NULL,                    -- sent | failed | acknowledged
    provider_ref    text NOT NULL DEFAULT '',         -- message id, response digest, token id
    sent_at         timestamptz NOT NULL,
    acknowledged_at timestamptz,
    ack_evidence    jsonb NOT NULL DEFAULT '{}',
    audit_log_id    uuid NOT NULL                     -- the chained audit entry
);

CREATE TABLE incident_events (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id uuid NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    at          timestamptz NOT NULL DEFAULT now(),
    actor_id    uuid,
    actor_type  text NOT NULL DEFAULT 'user',         -- user | system | tracker
    kind        text NOT NULL,
    detail      jsonb NOT NULL DEFAULT '{}'
);
```

`vex_statements` changes shape (no compatibility is owed; the project is
pre-alpha and ADR-009 edited its own migration for the same reason):

```sql
ALTER TABLE vex_statements
    ADD COLUMN release_id     uuid REFERENCES releases(id),   -- one version…
    ADD COLUMN version_range  text,                           -- …or a vers range over the repo's releases; both null = whole repo
    ADD COLUMN evidence       jsonb NOT NULL DEFAULT '{}',    -- reachability result, aid output, links
    ADD COLUMN supersedes     uuid REFERENCES vex_statements(id),
    ADD COLUMN approved_by    uuid REFERENCES users(id);
CREATE UNIQUE INDEX vex_statements_supersedes_once ON vex_statements (supersedes) WHERE supersedes IS NOT NULL;
-- rows are insert-only from here: no UPDATE path in the store layer

ALTER TABLE finding_acceptances
    ADD COLUMN vex_statement_id uuid REFERENCES vex_statements(id);  -- required when the finding has a vulnerability identifier
-- acceptanceVEXStatements and reachabilityVEXStatements are removed; export reads vex_statements only

CREATE TABLE first_party_advisories (                   -- §4a: a vulnerability in the product's own code
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    repo_id         uuid NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    advisory_id     uuid NOT NULL REFERENCES advisories(id),  -- the canonical row; identifier CVE-… or VENDOR-…
    product_purl    text NOT NULL,                            -- pkg:generic/<vendor>/<product>, version-less
    product_cpe     text,                                     -- optional alias for NVD and CPE-based consumers
    affected_range  text NOT NULL,                            -- vers range
    promoted_from   text,                                     -- finding fingerprint, when promoted from a SAST/DAST/manual finding
    created_by      uuid REFERENCES users(id),
    created_at      timestamptz NOT NULL DEFAULT now()
);
```

`clients` gains `security_contacts jsonb` (name, email, role) alongside the
existing single `contact_email`, and `notification_prefs` gains the delivery
channel and its parameters (webhook URL and secret reference, portal token
id). Client `labels` already carry free keys; `country` becomes a documented
key because the early warning asks for Member States. `releases` and
`deployments` stay as they are: an active deployment is the exposure signal,
whatever its provenance (ADR-024 §8 remains a separate phase; over-counting
exposure stays the safe failure mode). `.hibou.yaml` gains the `incidents`
section of §1, with its JSON schema; the org settings gain the defaults and
locks.

### 11. Surfaces

- **Home** (§9) at `/`; `/orgs` keeps the organisation list.
- **Org tab "Incidents"**: open incidents of the organisation sorted by the
  nearest due action, with the countdown; closed and withdrawn behind a
  filter; kind and priority filters.
- **Incident page**: header (kind, state, priority, T0, clocks per regime),
  scope table (§3), action list (§4) with evidence links and assignees,
  deliveries, timeline, tracker link, dossier export.
- **Finding, advisory and package detail**: "open incident" when one
  exists, "open an incident" otherwise, next to the ADR-032 exploitation
  facts.
- **Client detail**: the client's incidents and what it received, when.
- **Repo settings**: the `incidents` section rendered and editable, with the
  org defaults and locks shown.
- **API** under `/orgs/{provider}/{slug}/incidents`, gated on
  `admin | release_manager | security` (a new org role if `release_manager`
  is too narrow; §"Before building"); every mutation audited.
- **CLI**: `hibou incident open|decide|scope|action|deliver|status|export`,
  so the process can be driven from a runbook when the UI is not the habit.
- **Notifications**: `incident.opened`, `incident.due_soon` (configurable
  lead, default 6 h before each clock), `incident.overdue`,
  `incident.delivery_failed`, `incident.reopened`, `incident.closed`,
  `incident.mirror_lagging`, through the existing rules and senders.

### 12. Non-goals

- Submitting to the single reporting platform (ADR-031). Revisit when a
  stable machine interface exists; the action model already has the slot.
- Deciding exploitation or reachability. Hibou shows evidence, including
  automated aids, with its source; a person decides and signs the reason.
- Detecting exploitation in clients' systems. Out of scope by nature;
  a customer report is a `customer` signal entered by hand.
- Replacing the ticket tracker for the *correction* work. The fix is tracked
  as a release (and an ADR-050 pull request); the mirror (§8) keeps the
  team's tracker informed; how the team organises the work in between is
  not hibou's concern.
- Proving that a client *read* a notice. Hibou proves handing-over and
  records acknowledgement when it gets one.
- Any claim of legal compliance. The dossier is evidence; the manufacturer
  makes the claim (ADR-041 non-negotiables).
- A general-purpose dashboard framework. Home is a fixed set of tiles over
  existing queries; configurable widgets are a later decision.

## Before building

The design above is the proposal, not the requirement. Each point below
changes the build if answered differently, and must be answered by the people
who will run the process:

1. **Which channel is the legal notice to clients?** If contracts say
   "email to the designated security contact", `email` with the delivery
   record is enough. If they say nothing, decide what counts before hibou
   automates it. The `manual` channel exists so that nothing is blocked
   while this is settled.
2. **Is an acknowledgement required?** Default off (§5). Turning it on makes
   closure depend on clients.
3. **Is the ticket tracker still the register?** The mirror (§8) assumes
   hibou is the source and the tracker a view. If the tracker must stay the
   legal register, inbound sync grows and the dossier export must pull from
   it; say so before phase 1.
4. **Who is the owner?** The incident owner receives the signal and the
   countdowns; ADR-028's lesson is that a queue without a named owner is a
   queue nobody reads. A required org setting.
5. **Which releases are "the product"?** The conservative default (every
   active deployment) can be narrowed per release line with a recorded
   reason; decide whether out-of-support lines are excluded by policy or
   case by case. The answer "all of them, including out of support" is the
   one the regulation leans to.
6. **Which regimes apply?** CRA alone, or CRA plus a national rule with a
   broader trigger; Legal answers, and the `national:<code>` regime carries
   it.
7. **Internal targets stricter than the regulation?** The clocks accept an
   org-level override (e.g. 48 h instead of 72 h); the regulatory deadline is
   always shown next to it.
8. **Which triggers, at what volume?** Start with KEV and EUVD on released
   refs; measure EPSS thresholds on a two-week replay before enabling them.
9. **Role.** Whether `release_manager` covers deciding and delivering, or a
   `security` role is needed.

A pilot on one product with real client data and one past advisory,
replayed end to end, answers most of these faster than a meeting.

## Rollout

1. **Incident core and the CRA kind**: the catalogue-sync diff on released
   snapshots, the kind registry with `exploited_vulnerability` and
   `severe_incident`, the `cra-article-14` and `internal` regimes,
   `incidents`, `incident_deadlines`, `incident_scope`, `incident_actions`,
   `incident_events`, states and T0, the derived scope with *unknown* rows,
   the `vex`, `srp_*`, `fix_release` and `upstream_notice` actions, computed
   closure, the `.hibou.yaml` `incidents.rules` list with
   org defaults, the org tab and incident page, the CLI. The triage dialog
   change and the first-party vulnerability record of §4a, since the `vex`
   action depends on both. No delivery yet; the `manual` channel records
   what people send by hand.
2. **Delivery and dossier**: document sets (CSAF advisory, CycloneDX and
   OpenVEX, notice), approval step, `email` and `portal` channels,
   `incident_deliveries`, the chained audit entry, `client_notice` actions,
   the dossier export.
3. **More kinds and the tracker**: `secret_leak`, `malware`,
   `policy_breach` with their triggers; the Jira mirror, outbound then
   inbound; forge issues.
4. **Home**: the landing route, the empty-state rule, the four tiles of §9.
5. **Completeness**: scope recomputation on deployment and release changes,
   `webhook` channel, acknowledgements, `nis2-article-23` and
   `national:<code>` regimes, generic tracker webhooks.
6. **Compliance lens**: the incident register feeds ADR-031 item 8's CRA
   mapping (Art. 14 rows: covers), and ADR-041 item 3's SLA reporting
   (incident clocks as SLAs).

Phase 1 depends on nothing new. Phase 2 depends on ADR-041 item 6 for the
anchored proof; without it, deliveries are audited but the record is only as
trustworthy as the instance, and the dossier says so. Home (phase 4) can be
pulled forward; it has no dependency on phases 2–3 beyond the incident
queries.

## Consequences

- The security team's question "is anything left?" has a computed answer.
  The cost is that every action must be either satisfied with evidence or
  waived on the record; there is no quiet closure.
- Clients, deployments and releases become load-bearing for a legal
  process. Stale deployment data now produces wrong action lists: a client
  recorded on a version it no longer runs gets a notice it does not need
  (safe), a client missing from the data gets none (not safe). The list of
  clients per version, updated at each delivery, is the single highest risk
  of the whole process and a human one; ADR-024 §8's client self-reporting
  becomes worth building.
- Releases without an inventory become visible as *unknown* rows that
  block closure. Producing SBOMs for older versions (from the tag) stops
  being optional for any product with such versions in use.
- VEX statements written in an incident end up in documents handed to
  clients and, in the dossier, to authorities. ADR-031's note on
  CRA-quality wording applies with force; the incident page should show the
  statement as the client will read it.
- Hibou sends email to people outside the organisation for the first time.
  The sender path reuses the netguard and redaction of `internal/notify`,
  and the recipient list is the client's recorded contacts only, never free
  text at send time.
- A generic trigger grammar can open many incidents. The defaults are
  narrow (KEV on released refs, verified secrets, all malware); widening
  them is a per-repository choice with a visible volume.
- The kind registry is an extension point inside hibou, not a plugin API.
  New kinds are code reviewed like any other feature; this keeps the
  evidence semantics of each kind under the same scrutiny as the first.
- The tracker mirror gives hibou write access to a team's tracker. The
  credentials live in the secret store, the integration is per
  organisation, and inbound changes are limited to marking manual actions
  done; nothing inbound can hide or close an incident.
- One open incident per (subject, product) means an advisory that affects
  several products (repositories) has several incidents, one per product,
  because scope, clients and filings differ per product. Home and the org
  tab show them together; a cross-product view is a filter, not a parent
  object.
- The landing page changes for every signed-in user. Users with no
  organisation see what they see today; everyone else sees Home.
- ADR-031 Decision items 2 and 3 are superseded by this ADR; ADR-032's open
  item closes; ADR-024 §8 moves from "nothing blocks it" to "wanted".

## Alternatives considered

- **Stay in the ticket tracker, add a checklist template.** Cheapest; keeps
  every fact typed by hand, and the proof of delivery stays in mailboxes.
  Fails the "either actions remain or it is closed" requirement as soon as a
  client or a version is forgotten, which is the failure the process is
  meant to prevent. The mirror (§8) keeps the tracker without making it the
  register.
- **A CRA-only `report` entity** (ADR-031's sketch). Smaller, and the second
  use case (a leaked key, a malicious package) would have rebuilt the same
  timeline, actions and closure under another name. The kind registry costs
  one interface and buys every later case.
- **Hand-maintained action list on the incident.** Simpler schema; the same
  failure in a nicer UI. Deriving actions from scope is the whole point.
- **Auto-decide T0 from the catalogue entry.** Would start the clocks on
  every KEV hit on a shipped version, including the majority that are not
  exploitable in the product (FAQ 5.4), and would make hibou the entity that
  decided a legal fact. Rejected; signals stay signals.
- **Triggers as a fixed set of toggles** (`kev: true`, `epss_min`). Enough
  for the first year, and the third request would have been an expression
  anyway. The filter grammar already exists and users already type it.
- **Incident per advisory across all products.** One object, several
  filings, scopes and client sets inside it; every query becomes a join on
  product. Rejected for one incident per (subject, product).
- **Require acknowledgement for closure.** Legally stronger evidence, but
  the obligation is to inform; a silent client would hold the incident open
  indefinitely. Available as a setting.
- **Two-way tracker sync as the default.** Lets the tracker close
  incidents, which puts the closure rule outside the chain. Inbound is
  limited to manual actions.
- **Submit to the single reporting platform.** Rejected again for ADR-031's
  reasons; the action model keeps the slot.
- **A configurable widget dashboard.** More than Home needs today; the
  fixed tiles are a query each and can be replaced later without a data
  model.

## Open questions

- CSAF profile for the user notice: `csaf_security_advisory` with a VEX
  section, or two documents. One document is easier to hand over; two map
  more cleanly onto the existing exporters.
- Whether `secret_leak` should consider forge history (a force-pushed secret
  is still in the reflog for a while) in `assess_exposure`, and how to
  record that without storing the secret (ADR-010 keeps hashes only).
- Retention of incident documents versus the tiered snapshot retention
  (ADR-014): incident dossiers and the snapshots they reference must outlive
  the product's support period; pinning by incident is the likely answer.
- Whether the `portal` channel is worth building before a client asks for
  it; `email` plus `manual` may carry the first year.
- The paragraph references to the Commission guidelines below were taken
  from a secondary source and must be checked against the published text
  before this ADR is accepted.

## References

- Regulation (EU) 2024/2847, Art. 3(2), 3(13), 3(22), 3(42), 13(6), 14,
  15, 16, 24(3), 69(3); Recitals 12, 18, 19, 66, 68 —
  https://eur-lex.europa.eu/eli/reg/2024/2847/oj
- Commission services, *FAQs on the Cyber Resilience Act*, v1.4
  (2026-09-04), entries 1.2, 5.1–5.5 —
  https://ec.europa.eu/newsroom/dae/redirection/document/123307
- Commission, *Guidance on the application of Regulation (EU) 2024/2847*,
  Communication C(2026) 5252 of 2026-07-27, annex (draft approved; applies
  once formally adopted): §209–221 reporting (T0 as reasonable certainty
  after a prompt assessment, §213–214; component vulnerabilities reportable
  only when exploitable in and exploited in the product, §218; users
  informed proportionately, §219–221), §222–228 reporting upstream (not
  required when the maintainer already knows, §223) —
  https://ec.europa.eu/newsroom/dae/redirection/document/131456
- Directive (EU) 2022/2555 (NIS2), Art. 23
- CISA KEV catalogue; ENISA EUVD; FIRST EPSS; CycloneDX VEX; OASIS CSAF 2.0
- ADR-009 (VEX), ADR-010 (secret scanning), ADR-013 and ADR-021 (filter
  grammar), ADR-020 (fine-grained tokens), ADR-024 (releases, clients,
  deployments), ADR-028 (named owner), ADR-031 (CRA), ADR-032 (KEV/EUVD),
  ADR-040 (EPSS movements), ADR-041 (evidence, hash chain, SLAs),
  ADR-045 (inventory extraction), ADR-049 (reachability), ADR-050
  (remediation pull requests)
