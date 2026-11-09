# ADR-050: Remediation pull requests for a branch or a release

## Status

Proposed (2026-10-17); **to be implemented if adopted, not scheduled**
(status verified 2026-11-09).

- **Not implemented:** the guided-remediation planner, `hibou fix`,
  maintained-line policy, release-branch targeting and remediation PR
  API/UI. Having OSV-SCALIBR and forge write helpers is not this feature.
- **Deferred extension:** execution in managed isolated runners and a
  continuously scheduled update-bot mode.
- **Deliberately excluded, not unfinished work:** server execution of package
  managers/repository scripts, automatic merging/tagging/publishing, and
  remediation for ecosystems the selected engine does not support.
- This proposal has **not been dropped**.

Builds on [ADR-024](024-release-tracking.md)
(releases derived from tags, clients and deployments),
[ADR-045](045-built-in-dependency-inventory.md) (OSV-SCALIBR as a library,
§7 security of server-side work), [ADR-046](046-dependency-cli.md) (CLI,
offline advisory database) and [ADR-035](035-bundled-scanners-and-coverage-policy.md)
(approved network locations, isolated runners).

Answer to the question that opened it: **yes, OSV-SCALIBR's
`guidedremediation` package can compute the fixes**, for npm, Maven and
Python only, and with one constraint that shapes the design: its
lockfile-regenerating paths run the package manager, which the server
must not do (ADR-045 §7). Hibou supplies what the library does not:
choosing the target branch, the PR itself, and knowing which release
lines are still maintained.

## Context

A user looking at the vulnerabilities of a branch or a release (ADR-024)
wants a pull request that fixes them on the code line that shipped that
release, not only on the default branch.

What exists:

- `github.com/google/osv-scalibr` v0.5.3 is already a dependency. Its
  `guidedremediation` package exposes `FixVulns(options.FixVulnsOptions)`:
  it resolves the full dependency graph, computes minimal patches,
  rewrites the manifest or lockfile on disk and returns a `result.Result`
  (vulnerabilities, patches with fixed/introduced IDs, unactionable ones).
  Options cover what a PR needs: `ExplicitVulns`, `IgnoreVulns`,
  `MaxUpgrades`, `NoIntroduce`, `MaxDepth`, `DevDeps`, per-package
  `upgrade.Config` (major/minor/patch), `ProjectRoot`.
- Forges already implement `CreateBranch`, `CreateOrUpdateFile` and
  `CreatePullRequest` (`internal/forge/forge.go`), used by the onboarding
  PR (`internal/repoconfig/onboarding.go`).
- Releases are derived from tags matching `releases.tag_pattern`; each
  points at a tag ref and a snapshot (commit). Clients and deployments say
  who runs which release.

What the library does, measured on v0.5.3:

| Ecosystem | File | Strategy | Executes a tool |
| --- | --- | --- | --- |
| npm | `package.json` | relax | `npm install --package-lock-only --ignore-scripts` when a lockfile is passed |
| npm | `package-lock.json` | in-place | No |
| Maven | `pom.xml` | override (`dependencyManagement`) | No |
| pip | `requirements.in` / standalone `requirements.txt` | relax | `pip-compile` when a lockfile is passed |
| Poetry | `pyproject.toml` | relax | `poetry lock` when a lockfile is passed |
| Pipenv | `Pipfile` | relax | `pipenv lock` when a lockfile is passed |

Gaps: no Go modules, Gradle, NuGet, Cargo, Composer, Bundler. Maven parent
POMs outside `ProjectRoot` are not updated. Resolution needs registry
metadata (a `resolve.Client`, plus a Maven registry client), so it needs
the network. The vulnerability source must be an enricher whose name
starts with `vulnmatch/` (upstream ships `osvdev`, online, and
`osvlocal`, downloaded OSV exports). The package README warns that on
untrusted projects the package manager may run scripts or follow
registries declared in the project.

What does not exist: knowing which branch carries a release's code line,
and which lines a team still maintains. That second fact is a company
policy, and companies differ: "last two minors", "LTS majors until a
date", "whatever a client still runs", or a hand-kept list.

### Goals

1. From a branch or from a release, open one PR that fixes the selected
   (or all fixable) vulnerabilities with the smallest upgrades.
2. From a release, find the target branch automatically; when none
   exists, offer to create a release branch from the tag.
3. Show which release lines are maintained without hard-coding one
   maintenance model, and fix "all maintained lines" in one action.
4. Keep ADR-045 §7: the server executes no repository tooling and only
   reaches approved network locations.

### Non-goals

- Ecosystems the library does not cover (see Gaps). Findings there show
  "no automated fix" with the fixed version Hibou already knows.
- Cherry-picking code fixes (first-party vulnerabilities, SAST findings).
- Merging, tagging or publishing a release. Hibou opens the PR; the team
  merges and tags, and ADR-024 derives the new release from the tag.
- Running continuously as an update bot. PRs are opened on request (UI,
  API, CLI); a scheduled mode can come later on the same planner.

## Decision

### 1. Engine: OSV-SCALIBR `guidedremediation`, Hibou's advisory data

- **Vulnerability source**: a Hibou enricher, `vulnmatch/hibou`, backed
  by the same advisory store that produced the findings, so a PR fixes
  what the user sees. Triage feeds the options: findings marked not
  affected or risk-accepted go to `IgnoreVulns`; a selection goes to
  `ExplicitVulns`. Offline installations use the ADR-046 export. The
  `vulnmatch/` prefix check is an upstream convention, not an API:
  pin the version and cover it with a test.
- **Registry metadata**: resolution clients built by Hibou, pointed only
  at operator-approved registries or mirrors (ADR-035). Project files
  (`.npmrc`, `<repositories>`, `pip.conf`) never redirect a request, as in
  ADR-045 §7. Without an approved registry for an ecosystem, remediation
  for that ecosystem is unavailable and says why. The spike verifies
  that the upstream clients do not read project registry config; if they
  do, Hibou wraps or replaces them.
- **Defaults**: `NoIntroduce = true`, dev dependencies included,
  `MaxDepth` unlimited. Upgrade level per target: patch and minor on
  release branches, major allowed on the default branch; overridable per
  request and in `.hibou.yaml`.

### 2. Where it runs

| Mode | Strategies | Who runs it |
| --- | --- | --- |
| **Server** (worker job) | Maven override, npm in-place on `package-lock.json`, relax on manifests that have no lockfile | Hibou, on a clone at the target ref (ADR-045 clone path, same owner-binding and limits) |
| **CLI** `hibou fix` | All, including relax + relock | A developer or a CI job, with their own toolchain and trust |
| **Isolated runner** (later, ADR-035) | All | Operator-enabled runners |

The server never calls `FixVulns` with a lockfile that would trigger a
relock; for those projects the UI shows the exact `hibou fix` command
instead of a button. The CLI and the server share the planner (target
resolution, options, PR body), so a PR opened from either reads the same.
`hibou fix --pr` pushes the branch with the user's git credentials and
asks the server to open the PR.

### 3. Target branch from a release

A release R has a tag T, a commit C and a version V. Its **line** is the
version prefix that a maintenance branch tracks: `major.minor` by default,
`major` when configured (§4).

Resolution, first match wins:

1. **Declared**: `.hibou.yaml` (default branch) or the release manager's
   setting maps R's line to a branch (§4).
2. **Pattern**: branches matching `releases.branch_pattern` with R's line
   substituted. The default tries common shapes: `release/{line}`,
   `release-{line}`, `{line}.x`, `v{line}`, `support/{line}`,
   `maintenance/{line}`. A candidate qualifies only if C is an ancestor of
   its head.
3. **Default branch**: if C is an ancestor of its head and R's line is
   the newest line (no later line has been released from it).
4. **None**: offer to create one (§5).

Several qualifying candidates are shown to the user; the choice is saved
as a declaration so the next request is deterministic. When R is not the
newest release of its line, the UI says so: the fix lands on the line's
branch, not on R's exact commit.

Ancestry needs a forge call: a new `IsAncestor(ctx, owner, repo, base,
head)` on the forge interface, implemented with each forge's compare
endpoint. Providers without it return "unknown" and step 2 falls back to
name matching, shown as unverified.

### 4. Release lines and maintenance: facts plus a declared policy

Hibou does not guess a maintenance policy. It shows facts for every line
and evaluates a declared policy over them; a line no rule covers is
**unknown**, never "unmaintained".

Facts per line, all already known or derived: its releases, latest
release and date, branch (if resolved), open vulnerabilities on the
latest release, and active deployments (ADR-024 clients).

Policy, in `.hibou.yaml` on the default branch, editable by a release
manager in the UI (stored per repository; the file wins when present):

```yaml
releases:
  tag_pattern: "^v\\d+\\.\\d+\\.\\d+$"
  line: minor                      # major | minor
  branch_pattern: "release/{line}" # optional; default tries common shapes
  maintained:
    latest: 2                      # the newest N lines
    deployed: true                 # any line a client still runs
    lines:                         # explicit entries win over the rules
      - line: "3.4"
        branch: support/3.4-lts
        until: 2027-06-30
      - line: "2.*"
        maintained: false
```

The rule kinds map to the practices seen in the field: newest N lines,
dated support windows, "supported while deployed", and an explicit list.
An organization can set defaults that repositories inherit and override.
The UI states the source of each verdict ("maintained: latest 2",
"maintained: deployed at 3 clients", "unknown: no rule").

The useful warning falls out of the facts, policy or not: **deployed but
unmaintained**, a line clients run that no rule keeps alive.

"Fix all maintained lines" opens one PR per maintained line, each with
its own upgrade levels; lines whose branch cannot be resolved are listed
with the create-branch offer.

### 5. Creating a release branch

When step 4 of §3 is reached, the user can create the line's branch from
the newest tag of that line (not necessarily R), named by
`branch_pattern` (default `release/{line}`), with the existing
`CreateBranch`. Only admins and release managers may do it (same Casbin
role as ADR-024's lifecycle endpoints). The branch is created before the
PR and recorded as the line's declared branch. Branch protection is the
team's business; Hibou only opens a PR into it.

### 6. The pull request

- **Commit**: one commit with every changed file. A new forge method
  `CommitFiles(ctx, owner, repo, branch, message, files)` uses each
  forge's multi-file API (GitHub git trees, GitLab commit actions,
  Gitea/Forgejo change-files). `CreateOrUpdateFile` per file remains the
  fallback.
- **Branch name**: `hibou/fix/{target}/{short hash of the patch set}`. A
  request whose patch set matches an open Hibou PR on the same target
  updates it instead of opening another (needs a `FindPullRequest(head,
  base)` forge method).
- **Body**: per patch, the packages and versions changed, direct or
  transitive, the vulnerability IDs fixed with severity, KEV and EPSS
  (ADR-032, ADR-038), introduced IDs if the user allowed any, and the
  unactionable ones with why. Generated from `result.Result`, so the
  server and the CLI produce the same text.
- **Link back**: the findings fixed by the PR show it; the next scan of
  the merged branch resolves them through the normal presence rules
  (ADR-034). Nothing is marked fixed when the PR is opened.
- **Permissions**: maintainers of the repository open PRs; creating a
  branch needs release manager (§5). Every request is audited.

### 7. API, UI, CLI

- `POST /orgs/{org}/repos/{repo}/remediations` with `{target: {branch}
  | {release}, create_branch?, vulns?, upgrade_level?, max_upgrades?}`;
  returns the plan (resolved target, patches, unactionable, mode). A
  `dry_run` returns the plan without writing.
- `GET .../release-lines`: lines, facts, maintenance verdict and source.
- UI: "Fix" on a branch or release vulnerability list, opening a plan
  preview before the PR; a Lines view on the Releases tab.
- CLI: `hibou fix [--branch B | --release V] [--vuln ID…] [--pr]`,
  usable offline with `--advisory-db` (ADR-046).

## Rollout

1. Spike: `FixVulns` on the test corpus (npm, Maven, Python) with a
   `vulnmatch/hibou` enricher and approved-registry clients; confirm no
   project registry config is read and no tool is executed in server mode.
2. Server mode on a branch, Maven and npm lockfile only; dry run, then PR.
3. Release lines: line derivation, facts, policy evaluation, Lines view.
4. Target from release: autodetection, `IsAncestor`, create-branch.
5. `hibou fix` with relock; "fix all maintained lines".

## Consequences

- Hibou moves from reporting to changing repositories; the forge app
  needs contents and pull request write access, which the onboarding PR
  already requires.
- Coverage is limited to npm, Maven and Python. Go and Gradle, likely
  frequent in onboarded repositories, get "no automated fix" until a
  later ADR.
- Server mode needs an approved registry per ecosystem; air-gapped
  installations need a mirror or use the CLI.
- npm and Python projects with lockfiles that need a relock are CLI-only
  until isolated runners exist.
- The maintenance policy is a new piece of configuration; with none set,
  every line shows as unknown and the feature still works per branch.
- An upstream pre-1.0 API: version bumps of OSV-SCALIBR need the spike's
  tests to pass.

## Alternatives considered

- **Running the package manager on the server.** Covers every lockfile,
  breaks ADR-045 §7 (execution, project-controlled registries). Rejected;
  isolated runners are the place for it.
- **Naive version bumps from Hibou's fixed versions.** Works for any
  ecosystem and direct dependencies, ignores the graph: transitive fixes,
  conflicts and newly introduced vulnerabilities are missed. Kept only as
  the "no automated fix" hint.
- **Hard-coding one maintenance model** (for example "newest two
  minors"). Simple, wrong for most companies. Rejected for facts plus a
  declared policy.
- **Inferring maintenance from branch activity.** Recent commits on a
  branch say little about a support promise and would label lines
  unmaintained by accident. Shown as a fact, never used as a verdict.
- **Delegating to an external dependency-update bot.** Its policy is per
  repository and it does not know Hibou's releases, triage or
  deployments. Rejected; the library gives the same resolution engine
  without the bot.
