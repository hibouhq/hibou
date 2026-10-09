# SAST scanner reference

What each popular SAST scanner gives hibou when its SARIF is uploaded: what it
analyses, how developers suppress findings in code, and whether those
suppressions reach hibou.

Hibou has no SAST engine of its own; it ingests SARIF 2.1.0 from any producer
(see [COMPARISON.md](COMPARISON.md)). The columns below are the properties
that decide how useful a scanner's SARIF is once ingested.

**Scope.** The first rows are the scanners GitLab wraps in its SAST feature,
current and retired. More rows are expected; keep one row per scanner and add
columns rather than prose. Secret scanners are out of scope: hibou runs its
own secret scanning, and secret results arriving in SARIF (Trivy) are dropped
on ingestion. IaC is included where GitLab ships it (KICS, Kubesec).

**Evidence.** Every cell was checked against the scanner's official docs or
source at the version listed, on 2026-10-08. Sources are under each scanner.
"Unknown" means the evidence was not found, not that the feature is absent.

## Legend

| Mark | Meaning |
|---|---|
| ✅ | yes / supported |
| ⚠️ | partly, or with a caveat (see notes) |
| ❌ | no |
| — | not applicable |

## Overview

| Scanner | GitLab | Targets | Analysis | No build | License | Maintenance | Version checked |
|---|---|---|---|---|---|---|---|
| [Semgrep CE](#semgrep-ce) | current | 30+ languages, config files | AST patterns; taint within one function (cross-file in paid Pro) | ✅ | LGPL-2.1 engine; rules under non-OSI licence | very active | 1.180.0 (2026-10-07) |
| [Opengrep](#opengrep) | — (Semgrep CE fork) | 30+ languages incl. Apex, Elixir, Visual Basic; Semgrep-compatible rules | AST patterns; cross-function taint within a file (`--taint-intrafile`) | ✅ | LGPL-2.1 | very active | 1.30.2 (2026-10-07) |
| [SpotBugs + Find Security Bugs](#spotbugs--find-security-bugs) | current | JVM bytecode (Java, Kotlin, Scala, Groovy) | bytecode dataflow; taint with method summaries | ❌ needs compiled classes | LGPL-2.1 / LGPL-3.0 | SpotBugs active, FSB slow | 4.10.4 / FSB 1.14.0 |
| [PMD](#pmd-apex) (Apex rules) | current | Apex, Visualforce (+ many other languages) | AST, XPath and Java rules; heuristic variable tracking | ✅ | BSD-style (no SPDX id) | active | 7.28.0 (2026-09-25) |
| [Sobelow](#sobelow) | current | Elixir / Phoenix | AST; intra-function resolution | ✅ | Apache-2.0 | active (moved to `sobelow/sobelow`) | 0.16.0 (2026-09-30) |
| [Kubesec](#kubesec) | current, off by default | Kubernetes manifests | fixed rules over manifest objects | ✅ | Apache-2.0 | slow | 2.15.0 (2026-10-08) |
| [GitLab Advanced SAST](#gitlab-advanced-sast) | current, Ultimate | C#, C/C++, Go, Java, JS/TS, PHP, Python, Ruby (+ beta) | cross-file, cross-function taint | ⚠️ except C/C++ (compilation database) | proprietary | active | unknown (image `:2`) |
| [Bandit](#bandit) | retired → Semgrep | Python | AST, no dataflow | ✅ | Apache-2.0 | active, slow releases | 1.9.4 (2026-02-25) |
| [Brakeman](#brakeman) | retired → Semgrep | Ruby on Rails | AST; limited controller→view flow | ✅ | Brakeman Public Use License (commercial use needs a paid licence) | active | 8.1.0 (2026-09-30) |
| [ESLint + plugin-security](#eslint--eslint-plugin-security) | retired → Semgrep | JavaScript (TS via typescript-eslint) | AST patterns | ✅ | MIT / Apache-2.0 | plugin active; SARIF formatter slow | ESLint 10.12.0, plugin 4.2.0 |
| [Flawfinder](#flawfinder) | retired → Semgrep | C / C++ | lexical, risky-function list | ✅ | GPL-2.0-or-later | slow | 2.0.20 (2026-05-16) |
| [gosec](#gosec) | retired → Semgrep | Go | AST + types; SSA; inter-procedural taint (G7xx) | ⚠️ packages must type-check | Apache-2.0 | active | 2.29.0 (2026-08-26) |
| [MobSF / mobsfscan](#mobsf--mobsfscan) | retired → Semgrep | Android & iOS source | Semgrep patterns + regex | ✅ | LGPL-3.0-or-later | active | mobsfscan 1.0.1 (2026-09-21) |
| [NodeJsScan / njsscan](#nodejsscan--njsscan) | retired → Semgrep | JavaScript (no `.ts`), templates | Semgrep patterns (2 taint rules) + regex | ✅ | LGPL-3.0-or-later | active | njsscan 1.0.1 (2026-09-21) |
| [phpcs-security-audit](#phpcs-security-audit) | retired → Semgrep | PHP, Drupal 7 | token-stream sniffs | ✅ | GPL-3.0-or-later | unmaintained (2019); blocks PHPCS 4 | 2.0.1 (2019-08-05) |
| [Security Code Scan](#security-code-scan) | retired → Semgrep | C#, VB.NET | Roslyn semantic, inter-procedural taint | ❌ needs a compilation | LGPL-3.0 | dormant since 2022 | 5.6.7 (2022-09-05) |
| [KICS](#kics) | separate IaC feature | Terraform, CloudFormation, K8s, Docker, Ansible, Helm, … | Rego queries over parsed IaC | ✅ | Apache-2.0 | active | 2.2.0 (2026-09-17) |

## Ingestion into hibou

The column that matters most is **Emits suppressed**: hibou shows a scanner's
in-source suppressions (with their justification as the triage comment,
[ADR-026](adr/026-in-source-suppression-directives.md)) only when the scanner
keeps suppressed results in its SARIF with a `suppressions` entry. A scanner
that drops them makes suppressed findings look *resolved* in hibou.

Columns:

- **In-code suppression**: the comment or annotation a developer writes next
  to the code to silence a finding.
- **Rule-specific**: the comment can name the rule it silences
  (`# nosec B602`) instead of silencing everything on the line.
- **Justification**: the comment can carry the *reason* for silencing it,
  e.g. `// #nosec G304 -- path comes from our own config`. Hibou shows that
  reason as the triage comment, so reviewers see why the finding was
  accepted without asking the author.
- **Emits suppressed**: the silenced finding is still written to the SARIF,
  marked `suppressions` (with the reason when there is one), instead of being
  dropped.
- **Fingerprint**: a stable ID per finding supplied by the scanner; without
  it hibou derives one from rule, file and line.

| Scanner | SARIF | In-code suppression | Rule-specific | Justification | Emits suppressed | Fingerprint | CWE in SARIF | Hibou |
|---|---|---|---|---|---|---|---|---|
| Semgrep CE | ✅ `--sarif` | `# nosemgrep: rule-id` | ✅ | ❌ | ✅ `inSource`, no justification — only when SARIF is the primary output | ⚠️ placeholder when logged out | ⚠️ tag text | ⚠️ ingested; fingerprint issue |
| Opengrep | ✅ `--sarif` / `--sarif-output=file` | `// noopengrep: rule-id` (also `nosemgrep`) | ✅ | ❌ | ✅ `inSource`, no justification — also with `--sarif-output` | ✅ match-based hash | ⚠️ tag text | untested |
| SpotBugs + FSB | ✅ `-sarif=file` | `@SuppressFBWarnings(value=, justification=)` | ✅ | ✅ (not exported) | ❌ | ❌ | ✅ taxonomy | untested |
| PMD (Apex) | ✅ `-f sarif` | `@SuppressWarnings('PMD.Rule')`, `// NOPMD` | ⚠️ annotation only | ⚠️ NOPMD text | ❌ (`--show-suppressed` ignored by SARIF) | ❌ | ❌ | untested |
| Sobelow | ✅ `--format sarif` | `# sobelow_skip ["XSS.Raw"]` + `--skip` | ⚠️ by finding type | ❌ | ❌ | ✅ partial, includes line | ❌ | untested |
| Kubesec | ⚠️ bundled template | none | — | — | ❌ | ❌ | ❌ | untested |
| GitLab Advanced SAST | ❌ GitLab JSON only | `gitlab-advanced-sast-exclude: id` | ✅ | ❌ | unknown | GitLab `tracking` | ✅ (GitLab JSON) | ❌ no SARIF |
| Bandit | ✅ `-f sarif` (`bandit[sarif]`) | `# nosec B602` | ✅ | ⚠️ after a second `#` | ❌ | ❌ | ✅ tag | untested |
| Brakeman | ✅ `-f sarif` | none (ignore file) | — | ✅ ignore-file `note` | ✅ `external`, by default | ❌ | ❌ | untested |
| ESLint + plugin | ⚠️ `@microsoft/eslint-formatter-sarif` | `// eslint-disable-next-line rule -- reason` | ✅ | ✅ | ✅ `inSource` with justification, by default | ❌ | ❌ | untested |
| Flawfinder | ✅ `--sarif` | `// flawfinder: ignore` | ❌ | ❌ | ❌ | ⚠️ line-content hash | ✅ taxonomy | untested |
| gosec | ✅ `-fmt sarif` | `// #nosec G304 -- reason` | ✅ | ✅ | ✅ `inSource` + `external`, with `-track-suppressions` | ❌ | ✅ taxonomy | ✅ hibou CI |
| mobsfscan | ✅ `--sarif` | `// mobsf-ignore: rule_id` | ✅ | ❌ | ❌ | ❌ | ✅ tag | untested |
| njsscan | ✅ `--sarif` | `// njsscan-ignore: rule_id` | ⚠️ substring match | ❌ | ❌ | ❌ | ✅ tag | untested |
| phpcs-security-audit | ⚠️ third-party report class | `// phpcs:ignore Sniff -- reason` | ✅ | ⚠️ discarded | ❌ | depends on converter | ❌ | untested |
| Security Code Scan | ⚠️ compiler `/errorlog:f,version=2.1` | `#pragma warning disable SCS0005`, `[SuppressMessage(…, Justification=)]` | ✅ | ✅ SuppressMessage | ⚠️ ✅ via compiler errorlog, ❌ via standalone tool | ❌ | ❌ | untested |
| KICS | ✅ `--report-formats sarif` | `# kics-scan ignore-line`, `disable=<uuid>` | ⚠️ file-level only | ❌ | ❌ | ❌ (JSON only) | ✅ taxonomy | untested |

**Hibou column**: *hibou CI* — runs in this repository's pipeline;
*ingested* — exercised through the sample project or parser tests;
*untested* — native SARIF that should ingest but has not been tried.

### Takeaways

- Only **gosec, ESLint, Brakeman, Semgrep, Opengrep** and the **.NET compiler
  errorlog** keep suppressed results; of those, only gosec, ESLint and the .NET errorlog
  carry the developer's justification inline. For every other scanner, a
  suppressed finding simply disappears from the next upload.
- **Fingerprints are rare.** Hibou falls back to a hash of
  `repo/tool/rule/file/line`, so most findings get a new identity when the
  code above them moves.
- **Semgrep logged out** writes the same placeholder fingerprint
  (`"requires login"`) on every result. Hibou uses the first non-empty
  fingerprint as the finding identity, so all results of such a run collapse
  into one. Needs a fix in ingestion before Semgrep CE output is trusted.
  Opengrep, the community fork, writes a real match-based fingerprint and is
  the better fit for hibou today.
- **CWE** is expressed three ways: rule tags (`external/cwe/cwe-89`,
  `CWE-89: …`), rule `relationships` to a CWE taxonomy, or not at all.

## Per-scanner notes

Commands assume SARIF to a file. "Quirks" lists what an ingester must handle.

### Semgrep CE

- `semgrep scan --config auto --sarif -o semgrep.sarif`
- Suppress: `// nosemgrep: rule-id` on the line or the line before; trailing
  words are parsed as rule IDs, so there is nowhere to write a reason.
- Suppressed results are kept with `suppressions:[{"kind":"inSource"}]` only
  when SARIF is the primary format; `--sarif-output=` beside another primary
  format receives them already filtered (from source, not tested).
- Quirks: logged-out `fingerprints["matchBasedId/v1"] = "requires login"`;
  `%SRCROOT%` without `originalUriBaseIds`; driver name `Semgrep OSS` or
  `Semgrep PRO`; rule help carries a Pro upsell when logged out.
- Sources: [release](https://github.com/semgrep/semgrep/releases/tag/v1.180.0),
  [CE vs Pro](https://docs.semgrep.dev/semgrep-pro-vs-oss),
  [Sarif_output.ml](https://github.com/semgrep/semgrep/blob/v1.180.0/src/osemgrep/reporting/Sarif_output.ml),
  [Output_format.ml](https://github.com/semgrep/semgrep/blob/v1.180.0/src/osemgrep/reporting/Output_format.ml),
  [ignoring code](https://docs.semgrep.dev/ignoring-files-folders-code).

### Opengrep

- Community fork of Semgrep CE, created when Semgrep moved features behind a
  commercial licence; backed by a consortium of AppSec vendors. Runs the same
  rule format, with rules you provide.
- `opengrep scan -f rules/ --sarif-output=opengrep.sarif .`
- Suppress: `// noopengrep: rule-id`; `nosemgrep` and `nosem` still work, and
  `--opengrep-ignore-pattern` adds a custom marker. No justification field.
- Suppressed results are kept with `kind: "inSource"` whenever any requested
  output is SARIF, including `--sarif-output` beside another format (fixes
  the Semgrep CE caveat).
- Fingerprint: `fingerprints["matchBasedId/v1"]` is a real hash of rule,
  metavariables and path, with no login gating, so hibou gets a stable
  identity per match.
- Beyond Semgrep CE: intra-file cross-function taint (`--taint-intrafile`),
  Apex, Elixir and Visual Basic, self-contained binaries including Windows.
- Sources: [repository](https://github.com/opengrep/opengrep),
  [1.30.2](https://github.com/opengrep/opengrep/releases/tag/v1.30.2),
  [differences from Semgrep](https://github.com/opengrep/opengrep/blob/v1.30.2/OPENGREP.md),
  [Nosemgrep.ml](https://github.com/opengrep/opengrep/blob/v1.30.2/src/reporting/Nosemgrep.ml),
  [Sarif_output.ml](https://github.com/opengrep/opengrep/blob/v1.30.2/src/osemgrep/reporting/Sarif_output.ml),
  [Scan_subcommand.ml](https://github.com/opengrep/opengrep/blob/v1.30.2/src/osemgrep/cli_scan/Scan_subcommand.ml).

### SpotBugs + Find Security Bugs

- `spotbugs -textui -pluginList findsecbugs-plugin.jar -sarif=spotbugs.sarif -sourcepath src target/classes`
- Suppress: `@SuppressFBWarnings(value = "SQL_INJECTION_JDBC", justification = "…")`;
  unused suppressions are reported since 4.9. Baseline: `-excludeBugs baseline.xml`.
- Suppressed bugs never reach any reporter; the justification is not exported.
- Quirks: without `-sourcepath` results have only logical locations (no
  file); URIs are relative to numeric `uriBaseId`s; no columns; FSB findings
  appear as category `SECURITY`, not as a separate tool.
- Sources: [SpotBugs 4.10.4](https://github.com/spotbugs/spotbugs/releases/tag/4.10.4),
  [SARIF writer](https://github.com/spotbugs/spotbugs/tree/4.10.4/spotbugs/src/main/java/edu/umd/cs/findbugs/sarif),
  [SuppressFBWarnings](https://github.com/spotbugs/spotbugs/blob/4.10.4/spotbugs-annotations/src/main/java/edu/umd/cs/findbugs/annotations/SuppressFBWarnings.java),
  [FSB 1.14.0](https://github.com/find-sec-bugs/find-sec-bugs/releases/tag/version-1.14.0).

### PMD (Apex)

- `pmd check -d src -R category/apex/security.xml -f sarif -r pmd.sarif`
- Suppress: `@SuppressWarnings('PMD.ApexCRUDViolation')` (single quotes in
  Apex), or `// NOPMD reason` (same line, all rules).
- Suppressed violations are reported only by the html, summaryhtml, xml and
  JSON renderers; SARIF drops them even with `--show-suppressed`.
- Quirks: absolute `file:///` URIs; the same rule id can appear several times
  in `rules[]`; `ruleId` is the rule name.
- Sources: [7.28.0](https://github.com/pmd/pmd/releases/tag/pmd_releases%2F7.28.0),
  [Apex security rules](https://github.com/pmd/pmd/blob/pmd_releases/7.28.0/pmd-apex/src/main/resources/category/apex/security.xml),
  [suppressing](https://github.com/pmd/pmd/blob/pmd_releases/7.28.0/docs/pages/pmd/userdocs/suppressing_warnings.md),
  [SarifRenderer](https://github.com/pmd/pmd/blob/pmd_releases/7.28.0/pmd-core/src/main/java/net/sourceforge/pmd/renderers/SarifRenderer.java).

### Sobelow

- `mix sobelow --format sarif --out sobelow.sarif`
- Suppress: `# sobelow_skip ["XSS.Raw"]` before a function or router
  pipeline, applied only with `--skip`; fingerprint baseline in
  `.sobelow-skips` (`--mark-skip-all`).
- Quirks: `partialFingerprints.primaryLocationLineHash` includes the line, so
  it is not stable across edits; fingerprints changed in 0.14, invalidating
  old skip files; `message.text` is only the finding type; URI encoding
  changed in 0.16.
- Sources: [repository](https://github.com/sobelow/sobelow),
  [0.16.0](https://github.com/sobelow/sobelow/releases/tag/v0.16.0),
  [finding_log.ex](https://github.com/sobelow/sobelow/blob/main/lib/sobelow/finding_log.ex).

### Kubesec

- `kubesec scan deploy.yaml --format template --template templates/sarif.tpl`
- No suppression at all; `--rules` is an allow-list of rules to run.
- Quirks: one SARIF run per manifest object; no region (file only); every
  result `level: warning` whatever its points; old `$schema` URL; rule text
  inserted without JSON escaping.
- Sources: [2.15.0](https://github.com/controlplaneio/kubesec/releases/tag/v2.15.0),
  [sarif.tpl](https://github.com/controlplaneio/kubesec/blob/v2.15.0/templates/sarif.tpl).

### GitLab Advanced SAST

- Runs only in GitLab CI (Ultimate); writes `gl-sast-report.json` in the
  GitLab security report schema, not SARIF. Ingesting it would need a
  GitLab-schema importer.
- Suppress: `gitlab-advanced-sast-exclude: rule-id` in a comment on the line
  or the line before. Whether excluded findings are reported is undocumented.
- Sources: [docs](https://docs.gitlab.com/user/application_security/sast/gitlab_advanced_sast/),
  [ruleset customisation](https://docs.gitlab.com/user/application_security/sast/customize_rulesets/),
  [report schemas](https://gitlab.com/gitlab-org/security-products/security-report-schemas).

### Bandit

- `pip install 'bandit[sarif]'`; `bandit -r . -f sarif -o bandit.sarif`
- Suppress: `# nosec B602, B607`; a reason is only safe after a second `#`
  (`# nosec B602  # reason`), otherwise the words are read as test IDs.
- `-b baseline.json` cannot be combined with SARIF output (exit 2).
- Quirks: parse failures are `toolConfigurationNotifications`, not results;
  suppressions only appear as counts in `run.properties.metrics`.
- Sources: [1.9.4](https://github.com/PyCQA/bandit/releases/tag/1.9.4),
  [config](https://bandit.readthedocs.io/en/latest/config.html),
  [SARIF formatter](https://github.com/PyCQA/bandit/blob/1.9.4/bandit/formatters/sarif.py).

### Brakeman

- `brakeman -f sarif -o brakeman.sarif`
- No inline comments; suppressions live in `config/brakeman.ignore`
  (fingerprint + `note`), loaded automatically. `--ensure-ignore-notes` makes
  a note mandatory.
- Ignored warnings are kept in SARIF as `kind: "external"` with the note as
  justification, by default.
- Quirks: `justification: null` when a note is missing (invalid per schema);
  `level` reflects confidence, not severity; `startLine` only; licence
  restricts commercial use.
- Sources: [8.1.0](https://github.com/presidentbeef/brakeman/releases/tag/v8.1.0),
  [ignoring false positives](https://brakemanscanner.org/docs/ignoring_false_positives/),
  [licence](https://github.com/presidentbeef/brakeman/blob/v8.1.0/LICENSE.md).

### ESLint + eslint-plugin-security

- `npm i -D eslint-plugin-security @microsoft/eslint-formatter-sarif`;
  `eslint -f @microsoft/eslint-formatter-sarif -o eslint.sarif .`
- Suppress: `// eslint-disable-next-line security/detect-eval-with-expression -- reason`.
  Bulk suppressions (`eslint-suppressions.json`, ESLint ≥ 9.24) export as
  `external` with an empty justification.
- Suppressed results are kept by default; `SARIF_ESLINT_IGNORE_SUPPRESSED=true`
  drops them.
- Quirks: files with no suppression get no `suppressions` property, others
  get `[]` on active results; absolute `file://` URIs; one driver `ESLint`
  for all plugins; `--quiet` drops suppressed warnings.
- Sources: [plugin](https://github.com/eslint-community/eslint-plugin-security),
  [formatter](https://github.com/microsoft/sarif-js-sdk),
  [inline config](https://eslint.org/docs/latest/use/configure/rules),
  [bulk suppressions](https://eslint.org/docs/latest/use/suppressions).

### Flawfinder

- `flawfinder --sarif src > flawfinder.sarif`
- Suppress: `// flawfinder: ignore` (also ITS4/RATS forms), all rules at
  once, text after it ignored.
- Quirks: `fingerprints.contextHash/v1` hashes the line content, so identical
  lines collide and any edit changes it; result level can differ from the
  rule default.
- Sources: [2.0.20](https://github.com/david-a-wheeler/flawfinder/blob/2.0.20/ChangeLog),
  [README](https://github.com/david-a-wheeler/flawfinder).

### gosec

- `gosec -track-suppressions -fmt sarif -out gosec.sarif ./...` (as in this
  repository's CI).
- Suppress: `// #nosec G304 -- reason` or `//gosec:disable G304 -- reason`;
  `//nolint:gosec` is a golangci-lint directive that standalone gosec never
  sees ([ADR-026](adr/026-in-source-suppression-directives.md)).
  `-nosec-require-rules` and `-nosec-require-justification` enforce both.
- Quirks: `-show-ignored` without `-track-suppressions` emits ignored issues
  with no `suppressions`, so they ingest as active; global excludes appear as
  `external` with justification "Globally suppressed."
- Sources: [2.29.0](https://github.com/securego/gosec/releases/tag/v2.29.0),
  [README](https://github.com/securego/gosec/blob/v2.29.0/README.md).

### MobSF / mobsfscan

- `mobsfscan --sarif -o mobsfscan.sarif .`
- Suppress: `// mobsf-ignore: rule_id`; config `.mobsf` (`ignore-rules`,
  `ignore-paths`).
- Quirks: "missing best practice" findings get a synthetic location at line 1
  of the first scan path.
- Sources: [mobsfscan](https://github.com/MobSF/mobsfscan),
  [1.0.1](https://github.com/MobSF/mobsfscan/releases/tag/1.0.1).

### NodeJsScan / njsscan

- `njsscan --sarif -o njsscan.sarif .` (NodeJsScan is now a web UI over njsscan).
- Suppress: `// njsscan-ignore: rule_id`; config `.njsscan`.
- Quirks: the ignore check is a substring match, so one ID can silence
  another containing it; `.ts` files are not scanned.
- Sources: [njsscan](https://github.com/ajinabraham/njsscan),
  [1.0.1](https://github.com/ajinabraham/njsscan/releases/tag/1.0.1).

### phpcs-security-audit

- No native SARIF: `phpcs --standard=Security --report='\Bartlett\Sarif\Converter\Reporter\PhpCsReport'`
  with [sarif-php-converters](https://github.com/llaville/sarif-php-converters).
- Suppress: `// phpcs:ignore Security.BadFunctions.EasyXSS -- reason`; the
  reason is discarded by PHPCS.
- Not a good candidate: unmaintained since 2019 and its Composer constraint
  rejects PHPCS 4.
- Sources: [repository](https://github.com/FloeDesignTechnologies/phpcs-security-audit),
  [PHPCS advanced usage](https://github.com/PHPCSStandards/PHP_CodeSniffer/wiki/Advanced-Usage).

### Security Code Scan

- Preferred: the NuGet analyzer with the compiler error log,
  `<ErrorLog>scs.sarif,version=2.1</ErrorLog>` (without `version=2.1` Roslyn
  writes SARIF 1.0). The standalone `security-scan my.sln --export=scs.sarif`
  drops suppressed results.
- Suppress: `#pragma warning disable SCS0005` or
  `[SuppressMessage("Security", "SCS0005", Justification = "…")]`; the errorlog
  writes `inSource` suppressions with the justification (Roslyn ≥ 3.9).
- Quirks: one errorlog per project and target framework; it also contains
  compiler and other analyzers' diagnostics (filter on `SCS*`); project
  dormant since 2022.
- Sources: [repository](https://github.com/security-code-scan/security-code-scan),
  [Roslyn SarifV2ErrorLogger](https://github.com/dotnet/roslyn/blob/main/src/Compilers/Core/Portable/CommandLine/SarifV2ErrorLogger.cs),
  [in-source suppression](https://learn.microsoft.com/visualstudio/code-quality/in-source-suppression-overview).

### KICS

- `kics scan -p . --report-formats sarif -o out/`
- Suppress: `# kics-scan ignore-line` / `ignore-block` (all rules), or file
  header `# kics-scan disable=<query-uuid>`; `--exclude-results` takes
  similarity IDs as a baseline.
- Quirks: rule IDs are UUIDs; `startLine` only; the `similarityID` is in the
  JSON report but not in SARIF.
- Sources: [2.2.0](https://github.com/Checkmarx/kics/releases/tag/v2.2.0),
  [running KICS](https://github.com/Checkmarx/kics/blob/master/docs/running-kics.md),
  [SARIF model](https://github.com/Checkmarx/kics/blob/master/pkg/report/model/sarif.go).

## Adding a scanner

1. Add a row to both tables; keep columns, add one if a new property matters.
2. Check each cell against the scanner's docs or source at a named version;
   write "unknown" rather than guessing.
3. For **Emits suppressed**, read the SARIF writer: docs rarely say.
4. Run it once against a fixture with one suppressed finding and upload the
   SARIF to a local hibou before marking the Hibou column *ingested*.
5. Add a per-scanner note with the command, suppression syntax, quirks and
   sources.
