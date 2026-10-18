# ADR-042: IDE extensions — one Go language server, two thin clients (VS Code family, IntelliJ family)

## Status

Accepted (2026-10-13). Phases 1 and 2 implemented. Phase 3: the staged
secret check is implemented; running `hibou scan` from the IDE is dropped.
§7 is blocked. Builds on fine-grained tokens and read-only agent tokens
([ADR-020](020-fine-grained-api-tokens.md)), native in-source suppressions
([ADR-026](026-in-source-suppression-directives.md)), the boolean filter
language ([ADR-013](013-boolean-filter-expressions.md)) and the forge quality
gate ([ADR-018](018-forge-native-quality-gate-checks.md)). Login is specified
by [ADR-043](043-cli-browser-login-device-flow.md).

Implementation notes (2026-10-13):

- **Language server**: `hibou lsp` (`cmd/lsp.go`, `internal/lsp`). LSP 3.18,
  with every post-3.16 feature gated on the client's capabilities, so 3.17
  clients work. The protocol subset is hand-written (open question 4): no new
  Go dependency. Device login reuses `internal/devicelogin` (ADR-043).
- **Clients** live in their own repository,
  [hibouhq/hibou-ide](https://github.com/hibouhq/hibou-ide) (§1, revised
  2026-10-13). **VS Code** (`vscode/`): built, unit-tested and packaged as a
  VSIX. **IntelliJ** (`jetbrains/`, LSP4IJ, open question 1): written, not yet
  compiled; its first build is that repository's CI.
- **Verified** with Go tests against a fake API and a real git repository,
  then end to end against a seeded local server: snapshot of HEAD picked, a
  finding moved by an inserted line, hover, code actions, false-positive and
  reopen round trip.
- **Deviations from the decision below:**
  - §4 repository detection probes
    `/orgs/{provider}/{owner}/repos/{repo}` guessed from the git remote:
    `GET /orgs` only answers browser sessions.
  - §5 "live refresh over `/ws`" is polling instead: `/ws` rejects API tokens
    by design. The server checks local `HEAD` every 5 s and hibou every
    `pollSeconds` (default 120 s, minimum 30 s).
  - §5 phase-2 triage needs `triage:write` and the org admin role. The IDEs
    request the `triage` preset (read-only plus `triage:write`); the approval
    page preselects `read-only`, so triage is an explicit opt-in (ADR-043).
    The repository response carries `viewer_can_triage` (admin role after any
    login-token cap, and `triage:write` for a token); when it is false the
    triage quick fixes are replaced by "triage in the browser". A 403 still
    points to the browser and hides the actions for the session.
  - The suppression quick fix inserts the directive as an LSP 3.18 snippet
    edit with the cursor on the justification when the client supports it;
    otherwise the client asks for the justification first (`hibou.suppress`).
    Semgrep reads every word after `nosemgrep:` as a rule ID, so its
    justification goes on its own comment line. Checkov and Trivy get no
    quick fix: their directive belongs inside the resource block.
  - Phase 3 keeps only the staged-changes secret check
    (`hibou/secretCheck` → `POST /secret-scan/check`). The server scans the
    diff and stores nothing. It is off until the user agrees, from user-level
    settings only, and git runs it with fsmonitor, external diff and textconv
    disabled. "Run `hibou scan`" is dropped: it uploads a snapshot, and
    uncommitted local work must not be stored on the server.
  - §7 is blocked: the MCP listener is plain HTTP, off by default and limited
    to in-cluster peers by the chart's NetworkPolicy, so a developer's editor
    cannot reach it. Writing an editor MCP config needs a decision on exposing
    MCP (TLS, ingress, token auth at the edge) first.
- **Security**: `hibou.server` and `hibou.path` are machine-scoped in VS Code
  and application-level in IntelliJ, because the client runs the binary that
  server serves. VS Code does not activate in untrusted workspaces, because
  the server runs git there and a repository's git config can run commands.
  Users of other LSP clients (Neovim, Zed, Helix) are responsible for the
  same trust check.

## Context

Developers see hibou findings in three places today: the web UI, the PR check
or comment posted by the gate, and the CLI (`hibou gate`, `hibou secret-scan`).
All three come after the code is written. Nothing shows a finding in the file
where it would be fixed.

The two IDE families to cover:

| Family | Editors | Extension format | Distribution |
|---|---|---|---|
| **VS Code and its derivatives** | VS Code, Cursor, Windsurf, VSCodium, Positron, code-server, Coder/Gitpod, Eclipse Theia | VSIX (TypeScript, VS Code extension API) | Visual Studio Marketplace (Microsoft products only, per its terms) **and** Open VSX (all forks) |
| **IntelliJ Platform** | IntelliJ IDEA, GoLand, PyCharm, WebStorm, Rider, CLion, PhpStorm, RubyMine, Android Studio | Plugin ZIP (Kotlin, IntelliJ Platform SDK) | JetBrains Marketplace, or a custom plugin repository (`updatePlugins.xml`) |

The two APIs share nothing. Building two independent full-featured plugins
would write the same logic twice, in TypeScript and in Kotlin: auth, repo
detection, snapshot selection, mapping finding lines onto an edited working
copy, and suppression directives. That logic would drift.

### What hibou already has

- **REST API** for everything the IDE needs to read:
  `GET /orgs/{provider}/{slug}/repos/{repo}/findings?ref=…&q=…` (with the
  `file:` filter field), `…/findings/{fingerprint}`, `…/snapshots`,
  `…/pulls/{pr}/gate`, `/users/me`.
- **A Go CLI** that already resolves `provider/org/repo/ref/sha/PR` from the
  git checkout and CI env (`resolveUploadBase`, `resolveUploadContext` in
  `cmd/upload.go`), and stores server and token (`internal/cliconfig`).
- **Binary distribution from the server**: `GET /api/v1/bin/{os}/{arch}`
  (linux/darwin/windows × amd64/arm64), with sha256 checksums from
  `GET /api/v1/bin/version`. The CLI the server serves always matches the
  server's API.
- **An MCP server** (`internal/mcp`) with read tools (`list_vulnerabilities`,
  `compare_refs`, `impact_analysis`, …) scoped by ADR-020 tokens.
- **The config schema** at `GET /api/v1/schemas/hibou-config.schema.json`.

### What is missing

- **IDE-friendly login.** `hibou login --sso` opens the settings page and asks
  the user to create a key by hand and paste it. That is acceptable once in a
  terminal. In an IDE it is a drop-off point, and in remote environments
  (devcontainers, Codespaces, SSH remotes) a loopback-redirect flow does not
  work at all.
- **Snapshot selection by commit.** Snapshots resolve by `snapshot=<id>` or by
  `ref`. No endpoint answers "the newest snapshot whose commit is an ancestor
  of my HEAD".

## State of the art (October 2026)

| Product | Shape | Lesson |
|---|---|---|
| SonarQube for IDE (VS Code, IntelliJ, Eclipse, Visual Studio) | Native client per IDE over a shared Java analysis core; "connected mode" syncs server rules and issue status | Shared core plus thin clients is what makes four IDEs maintainable |
| Snyk IDE plugins | Shared Go language server (`snyk-ls`) consumed by each IDE client | The same split, with the core in Go, like hibou's CLI |
| GitHub Copilot, Red Hat YAML/Java, Terraform | LSP server in a standalone binary; VS Code client is ~a few hundred lines | LSP is the cross-IDE contract for diagnostics, hover and code actions |
| IntelliJ Platform LSP API; Red Hat **LSP4IJ** | Platform API (since 2023.2) was long limited to commercial IDEs; LSP4IJ is an open-source LSP client for every IntelliJ IDE | A JetBrains client can consume a language server without reimplementing it |

Everyone who ships to several IDEs converges on the same split: **put the
logic in a language server and keep the per-IDE code to UI glue.**

## Decision

### 1. Two client packages, one shared core

Yes, there are two "apps": a VS Code extension and an IntelliJ Platform plugin.
Neither contains business logic. Both start the same core:

```
 VS Code / Cursor / …            IntelliJ / GoLand / …
 ┌──────────────────┐            ┌──────────────────┐
 │ hibou-vscode     │            │ hibou-intellij   │
 │ (TypeScript)     │            │ (Kotlin)         │
 │ auth UI, panels, │            │ auth UI, tool    │
 │ status bar       │            │ window, widget   │
 └────────┬─────────┘            └────────┬─────────┘
          │ LSP (stdio) + hibou/* requests│
          └──────────────┬────────────────┘
                 ┌───────▼────────┐
                 │  hibou lsp     │  same Go binary as the CLI
                 │  repo detect,  │  (cmd/lsp.go, internal/lsp)
                 │  snapshot pick,│
                 │  line mapping, │
                 │  diagnostics   │
                 └───────┬────────┘
                         │ REST (Bearer token)
                 ┌───────▼────────┐
                 │  hibou server  │
                 └────────────────┘
```

- **`hibou lsp`** is a new subcommand of the existing CLI, speaking LSP over
  stdio. It reuses `cliconfig`, `cliclient` and the repo/ref detection in
  `cmd/upload.go` (moved into a shared internal package).
- Standard LSP covers diagnostics, hover, code actions and
  `workspace/didChangeWatchedFiles`. A few **custom requests** (`hibou/findings`,
  `hibou/gate`, `hibou/status`) feed the per-IDE panels.
- ~~Both clients live in this repository, version-locked to the server
  release.~~ **Revised (2026-10-13):** the clients live in
  [hibouhq/hibou-ide](https://github.com/hibouhq/hibou-ide) and are released
  on their own (`vX.Y.Z` tags there). Version-locking never held in practice:
  hibou is self-hosted, so users run many server versions while the stores
  update the extensions independently. One extension version must therefore
  work with every server version in use, whatever the repository layout.
  What protects that is a **versioned protocol**: `initialize` returns
  `capabilities.experimental.hibou = {protocol, requests}`
  (`internal/lsp/server.go`, `protocolVersion`, `hibouRequests`). Additive
  changes only extend `requests`; incompatible ones increment `protocol`.
  Clients hide what the server lacks and warn when the server is newer than
  they support. The contract is `PROTOCOL.md` in hibou-ide, whose CI checks the
  handshake against the latest hibou release. `hibou lsp` itself stays here:
  it ships in the same binary as the server and always matches it.

### 2. The client gets the binary from the configured server

At startup the client calls `GET /api/v1/bin/version`, downloads
`/api/v1/bin/{os}/{arch}` if the cached binary's sha256 differs, verifies the
sha256, and runs it. A user-supplied path (`hibou.path` setting) overrides this
for air-gapped or managed workstations.

Consequences: the language server always matches the server's API version, and
the extensions themselves almost never need a release for a server change. The
checksum protects against a corrupted or truncated download. It does not
protect against a compromised server, which already holds the findings and
tokens. Binary signing is ADR-041's work and applies here unchanged.

### 3. Login: OAuth 2.0 Device Authorization Grant (RFC 8628)

New server endpoints implement the device flow and mint an **ADR-020
user-owned scoped token**:

1. The client asks for a device code. The IDE shows a short code and opens
   `https://<hibou>/device`.
2. The user signs in with the instance's normal SSO and approves the request.
   The approval page shows the requested scope.
3. The client polls and receives the token.

- **Default scope: the "read-only agent" preset** (every capability at most
  `read`), 90-day expiry, named `IDE — <editor> on <hostname>`. It appears and
  is revocable under Settings › API Keys like any other token, and every use is
  audited as today.
- The device flow is chosen over a loopback redirect because it works in
  devcontainers, Codespaces and SSH remotes, where the browser and the IDE
  backend are on different machines.
- The token is stored in the IDE's secret store (VS Code `SecretStorage`,
  IntelliJ `PasswordSafe`) and passed to `hibou lsp` through an environment
  variable, never a command-line argument. If `hibou login` already configured
  the CLI, the client offers to reuse that configuration.
- `hibou login --sso` switches to the same flow, replacing today's manual
  copy-paste.

### 4. Which findings a file shows

The language server picks the snapshot and maps lines **locally**. No source
code leaves the machine in phases 1 and 2.

1. **Repo**: from the git remote, as the CLI does today. An unenrolled repo
   shows a single "not tracked by hibou" status, not an error.
2. **Snapshot**: list snapshots for the current branch (falling back to the
   default branch) and pick the newest one whose commit is an ancestor of
   `HEAD` (`git merge-base --is-ancestor`). A later optimisation can add
   `GET …/snapshots?ancestor_of=<sha>`. The client works without it.
3. **Findings**: fetched once per snapshot (paginated, cached by snapshot ID)
   and indexed by file path. They are refetched when `HEAD` moves, or, in
   phase 2, on a `/ws` "snapshot processed" event.
4. **Line mapping**: diff the snapshot's commit against the working copy. That
   is `git diff -U0 <sha> -- <file>` for saved files, and a diff of
   `git show <sha>:<file>` against the in-memory buffer for unsaved edits.
   Findings in untouched lines move with the diff. A finding whose lines were
   edited stays visible, marked "code changed since the scan; may be fixed".
   It is never silently dropped, because absence is not resolution
   ([ADR-034](034-absence-is-not-resolution.md)).
5. **Dependency findings** without a source location attach to the manifest
   line that declares the component (`go.mod`, `package.json`, `pom.xml`, …)
   when the language server can locate it. Otherwise they appear only in the
   panel.

### 5. Scope by phase

| Phase | Features | Token needs |
|---|---|---|
| **1: read** | Device login; diagnostics with severity mapping; hover (rule, CWE, CVSS/EPSS, KEV flag, first seen); "Open in hibou" deep link; findings panel for the repo and file; status-bar gate verdict for the branch's PR; `.hibou.yaml` validation via the server's JSON schema; **"Suppress with native directive" code action** that inserts the scanner's own directive with a required `-- reason` (ADR-026). This is a local edit, so no write scope is needed. | read-only preset |
| **2: triage** | Accept or dispute a finding with justification from the IDE; live refresh over `/ws`; patch-coverage gutter for changed lines (per-line hits, [ADR-018 line-level patch coverage](018-line-level-patch-coverage.md)) | the user opts in to `findings:write` in the device-approval screen |
| **3: local checks** | Opt-in pre-commit secret check of the staged diff via `POST /secret-scan/check` (sends diff content to the server; off by default, admin-disableable); run `hibou scan` for the current commit | `secrets:read` |

### 6. Distribution

- **VS Code family**: publish the same VSIX to the Visual Studio Marketplace
  and to **Open VSX**. Forks cannot use Microsoft's marketplace, so Open VSX is
  required, not optional. Also attach the VSIX to each GitHub release for
  offline install.
- **IntelliJ family**: JetBrains Marketplace (signed plugin). Also attach the
  plugin ZIP to the release, and document a custom plugin repository for
  air-gapped fleets. Set `sinceBuild` low enough for the Android Studio
  baseline, because it trails the IntelliJ platform by several releases.
- **No telemetry** in either client. Server-side request logs and token audit
  are the only usage signal.

### 7. Agents in the IDE use MCP, not the extension

Copilot, Cursor, Claude Code and JetBrains AI already talk to hibou through the
existing MCP server with a read-only token. The extensions do not proxy MCP.
At most they offer a "Configure hibou MCP for this workspace" command that
writes the editor's MCP config using the same device-flow token. The two
integrations stay independent: the human sees diagnostics and the agent
queries MCP, under the same scopes.

### Non-goals

- **Local scanning engine in the IDE.** Hibou aggregates scanner output. It
  does not re-run SAST on every keystroke. Phase 3 can trigger `hibou scan`,
  but scanners stay external tools.
- **Embedding the web UI in a webview.** Deep links open the browser. A
  webview would duplicate auth and CSP handling for little gain.
- **Other IDEs** (Visual Studio, Eclipse, Neovim, Zed, Helix). They are not
  built, but `hibou lsp` is a standard language server, so Neovim, Zed and
  Helix users can wire it in themselves with a few lines of config. That is
  documented and best-effort.

## Consequences

- **Positive**
  - Logic is written once, in Go, next to the code that already detects repos
    and calls the API. The two clients are UI glue, a few hundred to ~1–2k
    lines each.
  - Server and language server are always version-matched (§2), so most
    features ship with a server release, not an extension release.
  - The device flow fixes the CLI's manual SSO login too.
  - Read-only by default: an IDE token leaked from a laptop cannot triage,
    accept or change gates.
- **Negative**
  - Two more toolchains in CI (Node/vsce for the VSIX, Gradle/IntelliJ Platform
    Gradle Plugin for the plugin), and two marketplace accounts and release
    processes to own.
  - The IntelliJ client depends on either the platform LSP API, whose
    availability has varied by edition and version, or on LSP4IJ, a
    third-party plugin dependency. See open questions.
  - Line mapping is heuristic for heavily edited files. The "may be fixed"
    marker makes that visible rather than hiding it.
  - New auth surface (device endpoints) to threat-model: code phishing and
    polling rate limits. `docs/THREAT-MODEL.md` must be updated alongside.

## Alternatives considered

| Alternative | Why not |
|---|---|
| **Two fully native plugins calling REST directly** | Repo detection, snapshot selection, line mapping and directive syntax are written twice, in TypeScript and Kotlin, and drift. This is what the industry moved away from. |
| **One TypeScript language server bundled in the VSIX, reused by JetBrains** | Needs a Node runtime on IntelliJ users' machines and duplicates the Go CLI's git and config logic. Go is already the shipped binary. |
| **MCP only (no extension), let IDE agents surface findings** | Gives no diagnostics, gutter or code actions, and depends on the developer asking an agent. MCP complements the extension and does not replace it (§7). |
| **Webview embedding the SPA** | Duplicates auth, fights CSP, and gives no editor integration (diagnostics, quick fixes). |
| **Loopback-redirect OAuth (RFC 8252) for login** | Fails in remote dev environments, where the browser cannot reach the IDE backend's localhost. The device flow works everywhere. |
| **Personal token pasted into settings** | Today's CLI UX. It invites long-lived, over-scoped tokens stored in plain-text settings files. |

## Success criteria

- A developer goes from install to seeing findings in an open file in under
  two minutes, with no manual token creation.
- The same findings, on the same lines, appear in VS Code, Cursor and
  IntelliJ IDEA for a given checkout.
- No source code is sent to the server in phases 1–2. This is verifiable from
  the request log.
- Inserting a native suppression directive from the IDE results, after the
  next scan, in the finding showing as suppressed with the justification as
  its triage comment (ADR-026 end to end).

## Open questions

1. ~~**IntelliJ LSP plumbing.**~~ Resolved: LSP4IJ everywhere, one code path
   from 2024.2 (build 242), which covers the Android Studio baseline.
2. **Snapshot-by-ancestor endpoint.** The client searches the 300 most recent
   snapshots of the branch, then of the default branch. Revisit
   `?ancestor_of=<sha>` if long-lived branches outrun that window.
3. **Device-flow approval scope UI.** Resolved by ADR-043: `read-only` for
   phase 1, plus the opt-in `triage` preset for phase 2.
4. ~~**Go LSP protocol types.**~~ Resolved: hand-written subset
   (`internal/lsp/protocol.go`, `jsonrpc.go`).
5. ~~**Repository layout.**~~ Resolved: separate repository
   hibouhq/hibou-ide for the clients; `hibou lsp` stays in this repository
   (§1, revised).
