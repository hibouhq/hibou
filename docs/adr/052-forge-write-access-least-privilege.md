# ADR-052: Forge access with least privilege: what Hibou may read and write

## Status

Accepted (2026-10-18).

Implemented:

- per-operation tokens (M3), with tests that fail on a call whose
  permissions are not declared;
- the `hibou/**` write namespace on every forge (M4);
- the tier setting (`HIBOU_FORGE_N_TIER`, Helm `tier`), capping every token;
- the confinement check (§1), with its log lines, metric and
  instance-admin endpoint;
- the installation guide (`docs/DEPLOYMENT.md`: tiers, selected
  repositories, rulesets, Forgejo protection rules);
- the audit entry for the onboarding pull request, the one write a user
  triggers today.

Not yet (Rollout): capability detection and consent per feature, the Forge
access page, the App manifest flow, release branch patterns, patch mode,
audit of future write features, and the external key signer.

Related: [ADR-018](018-forge-native-quality-gate-checks.md) (check runs),
[ADR-050](050-guided-remediation-pull-requests.md) (remediation pull
requests), the onboarding pull request (`internal/repoconfig/onboarding.go`),
[ADR-010](010-secret-scanning.md) (clones for secret scanning),
[ADR-045](045-built-in-dependency-inventory.md) (clones for extraction), and
`docs/THREAT-MODEL.md` (I-5, E-1).

## Context

Hibou talks to forges with a GitHub App (or the GitLab/Forgejo equivalent).
What it does with that access falls into three groups:

| Group | Operations | GitHub permission |
|---|---|---|
| **Read** | Clone for secret scanning and dependency extraction, read files and trees, list repositories, check membership | `contents: read`, `metadata: read`, `members: read` |
| **Report** | Check runs and commit statuses (quality gate), pull request comments | `checks: write`, `statuses: write`, `pull_requests: write` |
| **Propose** | Create a branch, write a file, open a pull request: the onboarding PR on `hibou/configure`, and the remediation PRs of ADR-050 | `contents: write`, `pull_requests: write` |

Only **Propose** needs `contents: write`, through exactly two calls
(`CreateBranch`, `CreateOrUpdateFile`). Yet today:

- The dogfood App is installed on **all** repositories of the organization
  with `contents: write`, `pull_requests: write`, `checks: write` and
  `statuses: write`.
- Every installation token Hibou mints (`createInstallationToken`) asks for
  **everything the installation has**, on **every repository** of the
  account. A read-only clone gets a token that could push to `main`.
- Nothing in Hibou limits *which branches* it writes to. The onboarding PR
  happens to use `hibou/configure`; nothing enforces a namespace.
- `docs/DEPLOYMENT.md` tells operators to grant `Contents: read-only` and does
  not list `Checks: write`, while the code needs check runs and, for
  onboarding and remediation, contents write. The documentation and the
  dogfood installation disagree, and neither is the least privilege for its
  feature set.

The threat model covers the leak of the App's private key (I-5) but not what
the key, or Hibou itself, can do with the App's reach.

### Threats

| ID | Threat | Today's blast radius |
|---|---|---|
| F-1 | **App private key stolen** (pod compromise, secret misconfiguration, backup leak) | Mint tokens with every permission on every installed repository: push to default branches, move tags, rewrite releases. A supply-chain compromise of every repository |
| F-2 | **Hibou server compromised** (RCE, malicious dependency) | Same as F-1, plus the database |
| F-3 | **Confused deputy in Hibou** (a bug where a request for org A acts on org B's repository, as in review findings B1–B3) | A token with full rights on the wrong repository |
| F-4 | **A Hibou user abuses a write feature** (an org admin in Hibou who is not a maintainer of the repository) | Branches and pull requests created in their name by the App |
| F-5 | **App installed on repositories Hibou never enrolled** | Every repository of the account is in reach, including ones created later |
| F-6 | **Write to a branch that matters** (default branch, release branches, tags) | Unreviewed code in a release |

The goal is that even F-1, the worst case, is reduced to "can open pull
requests on `hibou/*` branches of the repositories Hibou analyses, which a
human must approve".

## Options

| # | Mitigation | Stops | Cost | Who decides |
|---|---|---|---|---|
| M1 | **Install on selected repositories only** | F-5; narrows F-1/F-2/F-3 | The App must be added to each new repository Hibou should analyse | Forge administrator |
| M2 | **Capability tiers**: grant only the permissions of the features used (Read, Report, Propose) | F-1/F-2 cannot write contents unless Propose is granted | Features above the granted tier are off | Instance administrator |
| M3 | **Narrow tokens per operation**: mint each installation token for one repository and the permissions the operation needs (`repositories` and `permissions` in the token request) | F-3: a bug cannot reach another repository or write where it meant to read | Code change; a token cache per (account, repository, permission set) | Always on, in code |
| M4 | **Branch namespace enforced by Hibou**: the forge layer refuses any write outside `hibou/**` | F-3, F-4 on protected branches; makes the namespace a contract | A few lines in the forge layer | Always on, in code |
| M5 | **Forge rulesets confining the App**: every branch except `hibou/**` restricted (creation, update, deletion) with only human roles in the bypass list; default branch requires a pull request and an approval | F-1, F-2, F-6 at the forge, independent of Hibou's code | Rulesets per repository or organization (paid plan for private repositories) | Forge administrator |
| M6 | **Two Apps**: a read-and-report App everywhere, a Propose App installed only where write features are wanted | F-1 on the reader's key cannot write anywhere | Two installations and two keys to manage | Instance and forge administrators |
| M7 | **Patch mode**: Hibou produces the change (a patch or a branch description); the CLI or IDE applies and pushes it with the developer's own credentials | Removes contents write from the server entirely | The developer runs one command; no fully automatic PR | Instance administrator, per organization |
| M8 | **Key custody**: rotation cadence; the private key in the cluster secret only, or held by an external signer (Vault Transit, cloud KMS) so it never enters Hibou's memory | Reduces F-1's likelihood; with an external signer, a pod compromise cannot copy the key | Operational setup; an external signer needs a `crypto.Signer` adapter for the App JWT | Instance administrator |
| M9 | **Audit and alerting**: every forge write recorded in Hibou's audit log with the requesting user; the forge's own audit log streamed | F-4 visibility; detection of F-1/F-2 | Already partly there | Both |

Notes on the options:

- **M3 is the cheapest large gain.** GitHub's token request accepts
  `repositories` (or `repository_ids`) and a `permissions` subset. A read
  token for one repository can do nothing else, even if the code holding it
  is wrong. It does not help against F-1: whoever holds the key mints what
  they want. That is what M1, M2, M5 and M8 are for.
- **M5 is the only control that binds a stolen key.** GitHub evaluates
  rulesets for every actor; an App not in the bypass list cannot push to a
  restricted branch, whatever its permissions. On the Free plan, rulesets
  exist only on public repositories.
- **M7 trades convenience for zero server-side write access.** It suits
  regulated environments (ADR-041) and organizations that do not want any
  third party writing to their repositories.
- **GitLab and Forgejo** have the same shape: a project or group access token
  with scopes (`read_repository` vs `write_repository`, `api`), a bot user with
  the Developer role, and protected branches with "allowed to push" limited to
  maintainers and a `hibou/*` wildcard for the bot.

## Decision

### 1. Always on, in code

- **Narrow tokens (M3).** Each forge call declares the permissions it needs
  and the repository it acts on. Installation tokens are minted for exactly
  that, and cached per (account, repository, permission set) until shortly
  before expiry. Listing installations and repositories keeps an
  account-wide read token. A call without a declared need fails in tests.
- **Branch namespace (M4).** `CreateBranch`, `CreateOrUpdateFile` and any
  future write refuse branches outside `hibou/**`, before calling the forge.
  The prefix is a constant shared by onboarding and remediation (ADR-050
  uses `hibou/fix/...`).
- **Release branches are the one exception** (ADR-050 §5 creates a
  maintenance branch from a release tag). By default Hibou does not create
  them itself: it shows the release manager the exact `git` or `hibou`
  command, run with their own credentials. An instance administrator may
  instead allow the App to create branches matching declared patterns
  (`forge.N.release_branch_patterns`, e.g. `release/*`); the forge rulesets
  must then let the App create, but not update or delete, those branches.
  Only creation from a release tag's commit is allowed, never a push of new
  commits.
- **Write features need both capability and consent.** A Propose feature
  runs only when the App's installation actually holds `contents: write`
  (read from the installation at startup and on the installation webhook)
  **and** the organization enabled it in Hibou. Missing either, the feature
  explains what is missing instead of failing at the forge.
- **Audit (M9).** Every forge write is audit-logged with the Hibou user who
  caused it, the repository, the branch and the forge response.
- **Confinement check.** Hibou checks that the forge itself confines its
  identity, since that is what binds a stolen key. One minute after startup
  and every 6 hours, on one replica, it asks for each repository its
  identity can write to:
  - GitHub: which active rules (repository and organization rulesets) apply
    to a branch outside `hibou/*`, to the default branch and to a `hibou/*`
    branch, through "get rules for a branch"; then, per ruleset, whether the
    App may bypass it (`current_user_can_bypass`, answered for the caller).
    Both need only Metadata: read. A default branch with only classic branch
    protection is reported as not verifiable.
  - Forgejo: whether the token can push each existing branch (the branch
    list's `user_can_push`), and which protection rule applies to a new
    branch. Reading the rules needs repository admin, which the bot user
    must not have, so with the recommended setup branches that do not exist
    yet are reported as not verifiable. That is expected, not a gap to fix
    by granting admin.
  - GitLab: nothing to check; Hibou holds no GitLab server token.
  - On both, an identity that administers the repository is an error by
    itself: it can change or delete the rules that confine it (GitHub:
    the App holds Administration: write; Forgejo: the token's user is a
    repository or site admin).

  An error means the identity could write outside `hibou/*` (no rule, a
  bypass, an unprotected default branch); a warning means a weaker bypass,
  or a rule that also blocks `hibou/*`. Results go to the log (one line per
  repository, with the fix), to the gauge
  `hibou_forge_unconfined_repositories{forge}`, and to
  `GET /api/v1/instance/forges/confinement` (instance admins,
  `?refresh=true` to check again).

### 2. Tiers

The instance administrator picks one **tier** per forge. The tier is the
whole permission model: it decides the App's permissions, which features
exist, and the most a token may ask for.

| Tier | GitHub App permissions | What Hibou does on the forge | Pick it when |
|---|---|---|---|
| **Read** | Contents: read · Metadata: read · Members: read | Nothing visible: scans, inventory and membership checks; results stay in Hibou | You evaluate Hibou, or no tool may write to your forge |
| **Report** (default) | Read, plus Checks: write · Commit statuses: write · Pull requests: write | Quality-gate checks and statuses on commits, one Hibou comment per pull request | Almost everyone |
| **Propose** | Report, plus Contents: write | Opens pull requests on `hibou/*` branches: onboarding, dependency fixes (ADR-050), notices updates (ADR-051) | You want Hibou to open pull requests for you |

Below Propose, the features that would open a pull request still work in
**patch mode**: Hibou shows the change and one command that applies and
pushes it with the developer's own credentials (§3.4).

### 3. Setting it up: the steps

Every common case is three steps or fewer, and no credential is copied by
hand for GitHub.

#### 3.1 First installation (GitHub): 3 steps

1. **Instance settings → Forges → Add GitHub.** Choose the tier (Report is
   preselected) and click **Create the GitHub App**. Hibou uses GitHub's
   [App manifest flow](https://docs.github.com/en/apps/sharing-github-apps/registering-a-github-app-from-a-manifest):
   it sends GitHub the App definition (name `hibou-<instance>`, webhook URL,
   callback URL, the tier's permissions, the `push`, `pull_request`,
   `installation` and `installation_repositories` events). GitHub shows the
   App for confirmation; you click **Create**. GitHub sends Hibou the App ID,
   client ID and secret, webhook secret and private key, which Hibou stores
   encrypted (`HIBOU_ENCRYPTION_KEY`). Nothing to copy, no permission to tick.
2. **Click Install on GitHub.** GitHub's installation page opens. Choose
   **Only select repositories** and pick the repositories Hibou should
   analyse. Hibou's page says why, in one line: an App installed everywhere
   reaches repositories created later.
3. **Back in Hibou**, the Forge access page (§6) shows "Report · 4
   repositories · no warnings". Done.

Operators who manage secrets outside Hibou (Helm, Kubernetes secrets, a vault)
keep doing so: the `HIBOU_FORGE_N_*` variables override what the manifest
flow stored, and the page offers the created credentials once as a
Kubernetes secret manifest to download.

#### 3.2 Let Hibou open pull requests (Report → Propose): 3 steps

1. **Forge access → Allow pull requests.** GitHub has no API to change an
   App's permissions, so Hibou opens the App's permission page on GitHub and
   says the one change to make: **Contents → Read and write → Save**.
2. **Accept the new permission.** GitHub asks the organization owner to
   approve it (banner and email). When they do, GitHub sends Hibou a
   `new_permissions_accepted` event and the tier becomes Propose; no restart.
3. **Confine the App to `hibou/*` branches**, as a GitHub admin, following
   the installation guide (`docs/DEPLOYMENT.md`, "confine the App"). This is a
   documented manual step, on purpose: Hibou could only automate it with the
   Administration permission, which would also let a stolen key delete the
   rules. Where the rules can live depends on the GitHub plan:

   | Plan | Rulesets | New repositories |
   |---|---|---|
   | Team or Enterprise | One organization ruleset | Covered automatically |
   | Free | One per repository, public repositories only | Repeat for each |
   | Free, private repositories | Not available | Stay on Report (patch mode) |

   The bypass list holds the human repository roles (Write, Maintain,
   Admin): people keep pushing as usual, and the rule binds the App, which
   holds no repository role.

Then each organization that wants pull requests turns them on in its Hibou
settings (**Pull requests: Patch only → Open pull requests**).

#### 3.3 Go back to fewer permissions: 1 step

Remove the permission on the App's GitHub page. Hibou notices on the next
installation event or hourly check, and the features that needed it switch to
patch mode.

#### 3.4 Patch mode: 0 steps

It is what every pull-request feature does below Propose, or when an
organization keeps **Pull requests: Patch only**. The button reads **Get the
fix** instead of **Open pull request** and shows:

```bash
hibou fix apply 7f3c… --push     # creates hibou/fix/…, commits, pushes with your git credentials
```

and the same change as a plain `git apply` patch for those who prefer it.

#### 3.5 Rotate the private key: 2 steps

1. **Forge access → Rotate key** opens the App's GitHub page at **Generate a
   private key** (GitHub offers no API for this). Download the new key.
2. **Drop the `.pem` file on the page.** Hibou mints a token with it to prove
   it works, switches to it, and tells you to delete the old key on GitHub.

#### 3.6 GitLab and Forgejo: 2 steps

Hibou supports the latest release of each (Forgejo 17 at the time of
writing), so it can rely on their newest token and protection features.
Neither has an installable App: Forgejo offers OAuth2 applications and user
tokens, which since Forgejo 15 can be limited to specific repositories, but
nothing installed per organization. Hibou's GitLab provider holds no server
token today (sign-in only); the GitLab steps below apply once it does.

They have no App manifest, so Hibou shows the token form to fill in:

1. Create a **group access token** (GitLab) or a **bot user token** (Forgejo:
   a dedicated user with Write access to the chosen repositories, never
   admin, and a token limited to those repositories) with exactly the scopes Hibou lists
   for the tier:

   | Tier | GitLab scopes, role | Forgejo scopes |
   |---|---|---|
   | Read | `read_api`, `read_repository`; Reporter | `read:repository`, `read:organization` |
   | Report | `api`; Developer | `read:organization`, `write:issue` (comments), `write:repository` (commit statuses) |
   | Propose | as Report | as Report |

   Unlike GitHub, these forges have no scope that posts statuses without also
   allowing pushes: GitLab's `api` and Forgejo's `write:repository` both let
   the token write to the repository. On GitLab and Forgejo, **Report and
   Propose differ only in Hibou's own settings**, and protected branches are
   what keeps the token out of anything but `hibou/*`, from Report upwards.

2. Paste it into Hibou. Hibou reads back the token's scopes and role, refuses
   one broader than the tier (an owner token, `sudo`, an admin role), naming
   what is extra, and shows the protected-branch settings to apply:
   - GitLab: default and release branches protected with "allowed to push:
     Maintainers", which the token's Developer role is not;
   - Forgejo: a `hibou/**` rule allowing the bot user, then a `**` rule
     allowing only maintainers. Forgejo applies the first matching rule, and
     its `*` stops at `/`, so `**` is needed to cover nested branches.

### 4. Configuration reference

Everything above is stored by the UI; the same keys can be set in the config
file or environment, which then wins:

```yaml
forges:
  - type: github
    tier: report                    # read | report | propose  (default: report)
    app:                            # filled by the manifest flow (§3.1)
      id: "123456"
      private_key_file: /secrets/hibou-app.pem
    release_branch_patterns: []     # §1: empty = Hibou never creates release branches
    app_key_signer: ""              # optional, M8: vault-transit://… or a cloud KMS key URI
```

Per organization, in Hibou:

| Setting | Values | Default |
|---|---|---|
| Pull requests | **Patch only** · Open pull requests | Patch only |

`Open pull requests` is offered only when the forge's tier is Propose.

### 5. When the App and the tier disagree

| Situation | What Hibou does |
|---|---|
| The App holds **more** than the tier (e.g. Contents: write with tier Report) | Tokens never ask for more than the tier (M3), so the extra permission is never used. Forge access warns: "Contents: write granted but unused; remove it on GitHub" |
| The App holds **less** than the tier | Features that need the missing permission switch off or to patch mode, each saying which permission is missing, with a button to the GitHub page that adds it |
| Installed on **all repositories** | Works, with a warning and a button to the installation's repository settings |
| Tier is Propose, or Contents: write granted | The confinement check (§1) runs and reports each repository where the App could write outside `hibou/*`, with the ruleset to add or the bypass to remove |

### 6. Forge access page

One page per forge, for instance administrators, showing in plain words:

- **Tier**: "Report: Hibou posts checks and comments; it cannot change code."
- **Reach**: "Installed on 4 selected repositories" or "Installed on all 37
  repositories, including future ones".
- **Features**: on, off or patch mode, each with the reason.
- **Key**: age, last rotation, signer (file or external).
- **Confinement**: the latest check (§1), per repository, with the fix.
- **Warnings**, each with one button that does or opens the fix (§5).

### 7. Documentation

`docs/DEPLOYMENT.md` lists permissions per tier instead of one table, adds
`Checks: write` to Report, recommends selected repositories, and ships the
ruleset JSON for M5 (GitHub) and the protected-branch settings for GitLab
and Forgejo.

### 8. Threat model

`docs/THREAT-MODEL.md` gains, under Elevation of Privilege:

| ID | Threat | Mitigations | Residual risk |
|---|---|---|---|
| E-7 | Forge write access abused through a stolen App key, a compromised Hibou, or a confused-deputy bug | Capability tiers; per-operation tokens; `hibou/**` namespace enforced in code; selected-repository installation; forge rulesets with a human-only bypass; audit | A stolen key with Propose can still open PRs on `hibou/*` branches; humans must review them |
| E-8 | A Hibou user triggers forge writes on repositories they do not maintain | Write features need org consent and the repository role of ADR-050 §6; every write audited with the user | An org admin in Hibou can enable features an owner of the repository would not |

and I-5 (key leakage) references M8 for key custody.

### 9. Dogfood (hibouhq)

1. Install the App on selected repositories only (M1).
2. Keep `contents: write` only while onboarding or remediation PRs are used;
   otherwise downgrade to Report.
3. Apply rulesets confining it to `hibou/**` on the public repositories now,
   and on `hibou` at the flip (M5).
4. Rotate the private key (M8).

## Rollout

1. Documentation: tiers in `DEPLOYMENT.md`, ruleset JSON, threat model rows.
2. Branch namespace enforcement (M4) and audit of forge writes (M9).
3. Per-operation tokens (M3), with a test that fails on undeclared needs.
4. The confinement check (§1): log, metric, instance-admin endpoint.
5. Capability detection, the manifest flow and the Forge access page (§1, §3.1, §5, §6).
6. Patch mode (M7) and `hibou fix apply` for onboarding first, then ADR-050.
7. Optional: external signer (M8).

## Consequences

- A Hibou bug can no longer act on a repository other than the one it meant,
  or write where it meant to read.
- The default installation (Report) cannot change repository contents; the
  PR-opening features need a deliberate upgrade, visible on the Forge access
  page.
- Token minting increases slightly (one token per repository and permission
  set instead of one per account); tokens are cached and the forge's
  installation-token rate limits are far above this.
- Operators of existing installations with `contents: write` see a warning
  until they confine it or downgrade.
- The worst case (stolen key) depends on forge-side controls Hibou can only
  recommend and check: selected repositories and rulesets. The check reports
  a gap within 6 hours; it does not prevent one.

## Alternatives considered

- **Keep one broad App, rely on code correctness**: today's state; a single
  bug or stolen key reaches every repository with full write.
- **Read-only App, no write features at all**: safest, but drops onboarding
  and remediation PRs entirely; patch mode (M7) gives most of the value
  without server-side write.
- **OAuth user tokens for writes** (acting as the signed-in user): ties writes
  to a person, but needs the broad `repo` OAuth scope Hibou deliberately
  never requests, and fails for background jobs.
- **Reading the rulesets themselves**: needs `administration: read` on every
  repository, a broader permission than the risk it would report on. Not
  needed: "get rules for a branch" and `current_user_can_bypass` answer the
  same question with Metadata: read (§1).
- **Two Apps** (M6: a reader everywhere, a writer only where PRs are wanted):
  not common practice. Mainstream tools use one App, either read-and-report
  (no code changes) or with write for fix pull requests. It adds a second
  installation and key for a gain already covered by per-operation tokens,
  rulesets and key custody.
- **Hibou applying the rulesets itself**: needs the Administration
  permission, which also lets a stolen key remove them. A one-time manual
  step by a GitHub admin is safer.
