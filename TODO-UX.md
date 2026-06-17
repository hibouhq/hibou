# TODO-UX — Frontend gaps

The backend has shipped far ahead of the SPA. This file enumerates every backend
capability that has **no** (or only **partial**) UI in `site/`, so the frontend can
catch up. Grouped by priority.

Legend: ❌ none · 🟡 partial · ✅ done (listed only where it anchors a gap).

Design rules for all items below:
- Reuse the existing dark design system (`surface*`, `accent*` Tailwind tokens,
  `lucide-vue-next` icons, `ForgeIcon`, Pinia stores, `api` client in
  [site/src/api/client.ts](site/src/api/client.ts)). Do **not** introduce a clashing theme.
- Every new view needs: loading skeleton, empty state, error state, and success toast.
- Add `api` client methods + types alongside each feature (most endpoints below have
  **no** client method yet).
- Respect the skill .claude/skills/frontend-design/SKILL.md

---

## P0 — Org onboarding (the missing first-run flow)

Backend ready: `installation.created` auto-provision (opt-in via `HIBOU_AUTO_PROVISION_ORGS`),
forge-admin gate on `POST /api/v1/orgs` (`AuthorizeForgeOrgCreation`), pending-admin claim on
login (`ClaimPendingAdmin`). See [internal/orgprovision/service.go](internal/orgprovision/service.go).

- [x] **Empty-state onboarding on Orgs page** ✅ — [site/src/views/OrgsView.vue](site/src/views/OrgsView.vue)
  currently shows a bare "No organizations found." Replace with a guided panel:
  "Install the Hibou App" CTA (deep-link to the forge App install URL per provider) +
  the importable-orgs picker below.
- [x] **Importable forge orgs picker** ✅ — backed by `GET /api/v1/orgs/onboardable`
  (e.g. `GET /api/v1/orgs/onboardable`) returning, for the current user, the forge
  accounts they may onboard, each tagged `imported` / `importable` / `pending`
  (scoped to the user's own recorded installer rows to avoid info leak). Picker cards
  with one-click **Import** → calls gated `createOrg` → success toast → refetch.
- [x] **"Add organization" affordance when orgs already exist** ✅ — a header button on
  OrgsView opening the same install + picker flow (today there is no create-org UI at all,
  only the backend endpoint).
- [x] **Claim feedback** ✅ — when `ClaimPendingAdmin` grants an org at login, surface a
  toast/notification ("You're now admin of github/acme") and refresh the org list.
- [x] **Manual create fallback dialog** ✅ — form (name, slug auto-derived + live-validated
  against 2–63 `[a-z0-9-]`, provider select) for the gated `POST /orgs`, with the 403
  "requires a verified forge admin" message rendered clearly.

## P0 — Forge permission mirroring (NO manual membership)

**Design principle (SonarCloud-style): membership and visibility are a *projection* of the
user's forge permissions, synced automatically — never assigned by hand.** A user logs in
and immediately sees exactly the orgs/repos they can access on the forge, at the right role.
Manual member admin is explicitly out of scope (only optional overrides later).

How the reference tools (SonarCloud, Snyk, Codecov) do it:
- The App installation is the tenant boundary (Hibou already creates the org from `installation.created`).
- At login, the user's OAuth token is used **transiently** to ask the forge "what can this user see?"
  GitHub computes effective permissions for you:
  - `GET /user/installations` → installations the user can reach.
  - `GET /user/installations/{id}/repositories` → repos the user can access, each with a `permissions`
    object (`admin`/`maintain`/`push`/`triage`/`pull`).
  - `GET /user/memberships/orgs/{org}` → org role (`admin`/`member`).
  - GitLab/Forgejo equivalents: `projects?membership=true` + `access_level`; `/user/orgs`, `/user/repos`.
- Map forge permission → Hibou role: admin/owner(50)/maintainer(40) → **admin**; push/developer(30) →
  **write**; pull/reporter/guest → **read**.
- Efficient sync, not polling: refresh on login (1 paginated call/installation) + short-TTL cache with
  **ETag/conditional requests** + **webhook-driven invalidation** (`installation_repositories`, `member`,
  `membership`, `team`, `organization`, `repository`) + a background reconcile job for drift.
- Derived rows are tagged `source=forge` so revoking access on the forge revokes it in Hibou.

Frontend tasks:
- [ ] **Auto-visible orgs/repos** ❌ — the orgs list and repo lists show the forge-synced projection;
  no "add member" UI. Show each user's derived role as a read-only badge.
- [ ] **"Refresh access" affordance** ❌ — a manual re-sync button (calls the sync endpoint) plus a
  "last synced" indicator, for when a user just got granted access on the forge.
- [ ] **Invited (non-forge) members** 🟡 → see the dedicated **"Non-forge users & read-only access"**
  section below. Forge mirroring covers developers; auditors / GRC / external assessors who have **no
  forge account** get access via direct invite, shown as a clearly separated group from the
  forge-derived projection (never mixed).

Backend work required (mirror forge permissions — see the dedicated section at the bottom):
- [ ] Use the user token **transiently at login** to enumerate accessible installations/orgs/repos + levels.
- [ ] Permission-sync service projecting forge perms into derived `org_members` (+ per-user repo-access),
  tagged `source=forge`, with `synced_at`; forge→role mapping.
- [ ] Webhook-driven cache invalidation (extend the dispatcher) + TTL/ETag cache + background reconcile.
- [ ] Org/repo list endpoints filter by the synced projection (membership becomes auto-derived).

> Note: the existing manual member endpoints (`GET/POST /members`, `PUT /members/{userID}/role`,
> `DELETE /members/{userID}`) are **not** dead weight — they become the backbone of the *invited
> members* path below (non-forge users), kept strictly separate from the forge-derived projection.

## P1 — Non-forge users & read-only access (auditors, GRC, external assessors)

**Why this exists:** forge permission mirroring is perfect for developers, but several first-class
Hibou personas have **no forge account at all** — internal auditors, compliance/GRC officers, security
reviewers, executives, and *external* third-party assessors. They need read-only access to findings,
advisories, VEX, coverage evidence, compliance exports, and the audit log, yet they will never appear in
a GitHub/GitLab permission projection. Hibou ships ISO 27001 / SoA evidence exports, so **auditors are a
primary persona, not an edge case** — and for compliance-focused deployments this section is effectively P0.

**Model — two access *sources*, one *effective* access:**
- `source=forge` — auto-synced projection (developers). Never hand-managed; reconcile prunes it.
- `source=invite` — directly granted to non-forge users (and to forge users needing extra scope).
  Hand-managed by org admins; **survives forge syncs**.
- **Effective role = max(forge role, invited role).** An invite can only *add* access; a forge sync can
  never remove an invited grant.
- **Hard invariant (security):** the forge reconcile/prune job MUST scope its `DELETE` to `source=forge`
  rows only. It must never touch `source=invite` rows. Enforce in code + a regression test.

**Identity for people without a forge login:** decouple *user* from *forge identity* so a user row can
exist with no `provider_user_id`. Invited users authenticate via a non-forge path:
- Email magic-link (simplest for the single binary) and/or OIDC/SAML SSO (enterprise). Local password is
  the least-preferred fallback.
- Invite-by-email → user accepts via magic-link/SSO → matched to the pending grant by *verified* email.

**Read-only role:** the baseline `auditor` / `viewer` role (already named in RBAC) becomes org-scoped
read — findings/advisories/VEX/coverage/compliance exports/audit log across all repos; **no** repo
config, uploads, settings, or member management. Distinct from repo-scoped dev `read`.

**Time-boxed access:** optional `expires_at` on invited grants (auto-expire), ideal for external
assessors with a fixed engagement window.

Frontend tasks:
- [ ] **Members page = two groups** ❌ — "Synced from <forge>" (read-only list, role badge, not editable)
  and "Invited" (editable: role, optional expiry, identity/source badge). Never mix the two.
- [ ] **Invite flow** ❌ — email + role (`auditor`/`viewer`/`write`/`admin`) + optional expiry; sends a
  magic-link/SSO invite. Pending-invites list with resend / revoke.
- [ ] **Auditor-first landing** ❌ — read-only users must NOT hit the "import a repo" empty state. Land
  them on a compliance/overview/evidence view; hide write affordances app-wide for read-only roles.
- [ ] **Identity-source badges** ❌ — show whether a member came from the forge or an email invite.

Backend work required (consolidated in the backend section at the bottom):
- [ ] Decouple user identity from forge identity; allow `provider_user_id`-less users.
- [ ] Non-forge auth path (email magic-link and/or OIDC/SAML SSO) + email-invite accept flow.
- [ ] Wire the `auditor`/`viewer` role into real org-scoped read access (incl. compliance/audit; no writes).
- [ ] `source` column on membership (`forge`|`invite`) + optional `expires_at`; effective-role = max().
- [ ] **Reconcile scopes deletes to `source=forge` only** (tested invariant).

## P1 — Org settings & lifecycle

- [ ] **Org settings page** ❌ — `GET/PUT /orgs/{p}/{s}/settings` (no client method/UI).
- [ ] **Edit / delete organization** ❌ — `PUT`/`DELETE /orgs/{p}/{s}` (no client method/UI).
- [ ] **Multi-forge clarity** 🟡 — badge/group orgs by provider on OrgsView; link badge to `forge_url`.

## P1 — Repository inventory & lifecycle (new backend, thin UI)

Backend ready: webhook-driven inventory, lifecycle status (`discovered`/`active`/`archived`/`deleted`),
coverage summary, `POST /repos/sync`. See [internal/server/repo_inventory.go](internal/server/repo_inventory.go).

- [ ] **Lifecycle badges + filters** 🟡 — surface `status` and `last_scanned` on
  [site/src/views/ReposView.vue](site/src/views/ReposView.vue); filter by lifecycle.
- [ ] **"Sync now" button + inventory coverage summary** 🟡 — call `syncRepos`, show
  discovered/active/archived counts.
- [ ] **Repo config view** ❌ — `GET /repos/{repo}/config` (no client/UI).
- [ ] **Repo onboard action** ❌ — `POST /repos/{repo}/onboard` (no client/UI).
- [ ] **Repo update / remove** ❌ — `PUT`/`DELETE /repos/{repo}` (no client/UI).

## P1 — VEX (Vulnerability Exploitability eXchange)

Backend ready: per-repo VEX CRUD + export. No client/UI.

- [ ] **VEX statements view** ❌ — list/create/edit/delete VEX statements on a repo,
  plus **Export** (`GET /repos/{repo}/vex/export`). Add as a repo tab.

## P1 — Notifications, rules, integrations, quality gates

- [ ] **Notifications center** 🟡 — store exists ([site/src/stores/notifications.ts](site/src/stores/notifications.ts));
  needs a full page: list, mark read, mark-all-read, unread badge in nav.
- [ ] **Notification rules** ❌ — CRUD + **dry-run** (`/notification-rules`, `/dry-run`). No client/UI.
- [ ] **Integrations** ❌ — CRUD + **health** + **replay** (`/integrations/...`). No client/UI.
- [ ] **Quality gates** ❌ — CRUD (`/quality-gates`). No client/UI.

## P2 — Teams (mirror forge teams, not manual)

Consistent with the permission-mirroring principle, teams should reflect **forge teams/groups**
(GitHub teams, GitLab subgroups, Gitea org teams) rather than being hand-managed.

- [ ] **Forge-synced teams (read-only projection)** ❌ — display forge teams and their members,
  synced via the same permission-sync service + webhooks (`team`, `membership`). No manual team
  CRUD as the primary flow.
- [ ] **(Optional, later) Manual team overrides** 🟡 — only if needed; the existing team CRUD
  endpoints back this, clearly separated from forge-derived teams.

## P2 — Compliance & catalog

- [ ] **Compliance exports** ❌ — download buttons for `/compliance/export`,
  `/compliance/iso27001`, `/compliance/soa`. No client/UI.
- [ ] **Tool catalog view** ❌ — `GET /tool-catalog`. No client/UI.

## P2 — Releases, snapshots, trends, delta

- [ ] **Releases UI** 🟡 — `listReleases`/`createRelease` client methods exist; no view.
- [ ] **Snapshots browser** 🟡 — `listSnapshots` exists; no dedicated view.
- [ ] **Trends charts** 🟡 — `getTrends` exists; wire into repo overview.
- [ ] **Delta view** ❌ — `GET /repos/{repo}/delta` (no client/UI).

## P2 — Secret scanning

Backend ready: secret scanning (`internal/secretscan`, on-push). No UI.

- [ ] **Secret findings view** ❌ — surface secret-scan results (repo tab or org dashboard).

## P2 — Account / developer settings

- [ ] **API keys** ❌ — `users/me/api-keys` CRUD (create/list/delete). No client/UI.
  [SettingsView.vue](site/src/views/SettingsView.vue) is still a "coming soon" stub and the
  avatar-menu "API Keys" link ([AppLayout.vue](site/src/layouts/AppLayout.vue)) points at it.
  **Blocks CI:** the `HIBOU_API_TOKEN` secret used by
  [.github/workflows/ci.yml](.github/workflows/ci.yml) can only be obtained today via a manual
  browser-console `POST /api/v1/users/me/api-keys` call — there is no supported way to mint a key
  from the product. Build a real **Settings → API Keys** panel (replace the SettingsView stub):
  - Create form: name + scope multi-select (`upload`, `all`, …); `POST` returns the raw key once.
  - Copy-once reveal with a clear "shown only once — store it now" warning.
  - List active keys (name, scopes, created, expiry, last-used) via `GET`.
  - Revoke via `DELETE /users/me/api-keys/{id}` with a confirm dialog.
  - Add `api` client methods + types for all three operations.
- [ ] **CLI token generation** ❌ — `POST /auth/cli-token` (session-only; rejects bearer auth).
  No client/UI; pairs with the API keys panel to support the `hibou login --sso` flow.
- [ ] **Upload status** ❌ — `GET /uploads/{id}/status` (CLI-only today; optional web view).

## Cross-cutting polish

- [ ] Consistent loading skeletons + empty/error states across all views.
- [ ] Toast/notification system (if not already present) for action feedback.
- [ ] Slug live-validation helper shared between org/client/repo create forms.
- [ ] Surface provider/forge identity consistently (icons + forge links).

---

## Backend work required — forge permission mirroring (SonarCloud-style)

This is the backend foundation for the P0 "Forge permission mirroring" section. It supersedes
manual membership as the primary model.

- [x] **Transient token use at login** ✅ — the OAuth callback now fires an async, best-effort login
  hook with the user's transient token ([internal/auth/auth.go](internal/auth/auth.go), `context.WithoutCancel`
  + panic recovery so sync never blocks or fails login). GitHub enumerates real access via
  `GET /user/installations`, `GET /user/installations/{id}/repositories` (per-repo `permissions`), and
  best-effort `GET /user/memberships/orgs/{login}` (org-admin fallback capped at `write`, never granted
  from repo permission). GitLab/Forgejo `ListUserAccess` are graceful multi-forge no-ops for now. No token
  is ever persisted. ([internal/forge/forge.go](internal/forge/forge.go), [internal/forge/github.go](internal/forge/github.go))
- [x] **Forge→role mapping** ✅ — admin/owner(50)/maintainer(40) → `admin`; push/developer(30) → `write`;
  pull/reporter(20)/guest(10) → `read`. Centralized in one multi-forge mapper:
  [internal/forge/rolemap.go](internal/forge/rolemap.go) `MapForgeRole(providerID, level)` (GitHub/GitLab
  numeric+textual/Gitea+Forgejo), unit-tested. Consumed by the permission-sync service (below).
- [x] **Permission-sync service** ✅ (core) — [internal/permissionsync/service.go](internal/permissionsync/service.go)
  `SyncUser` projects forge permissions into derived membership at login:
  - Schema (migration `00007_two_source_membership`): `org_members` gains `source` (CHECK `forge|invite`,
    default `invite`), `synced_at`, `expires_at`; new `user_repo_access (user_id, repo_id, role, source, synced_at)`.
  - Projects org access **only into orgs that already exist** (never auto-creates orgs) and repo access
    only for enrolled repos; tier→`member_role` translated (`admin→admin`, `write→developer`, `read→viewer`).
  - RBAC updated add-before-remove (a failed add never strips existing access; same-role is a no-op).
  - Revocation prune is **scoped to `source=forge` only** (`PruneForgeOrgMembersForUser` /
    `PruneForgeUserRepoAccess`); explicit/manual/claimed grants re-assert `source=invite` so they survive
    every forge prune — tested DB invariant. Trigger: login. _Background reconcile of offline users deferred._
- [x] **Token strategy decision** ✅ — **chosen: login-transient sync, no token persistence** (option a).
  Active users are reconciled on their next login; we explicitly avoid storing refresh tokens to keep the
  security surface minimal. Background reconcile of offline users is deferred to a future job if needed.
- [x] **List endpoints** ✅ — `GET /orgs` (`handleListOrgs`) and repo lists already filter by `org_members`
  membership, so forge-projected members become auto-visible with no endpoint change required.
- [ ] **Webhook-driven invalidation** _(deferred — Phase 4)_ — extend the dispatcher
  ([internal/server/webhooks.go](internal/server/webhooks.go)) to handle `installation_repositories`,
  `member`, `membership`, `team`, `organization`, `repository` → re-sync the affected scope instead of
  relying on next-login refresh.
- [ ] **Efficiency** _(deferred)_ — short-TTL cache + **ETag/conditional requests** to stay under rate
  limits; per-installation pagination; avoid N+1 by batching.

## Follow-ups beyond current backend (UX-driven backend work)

- [x] **Broaden onboarding beyond the installer** ✅ (backend) — previously only the person who clicked
  "Install App" got a `forge_org_admins` row, so co-admins couldn't self-onboard. The permission-mirroring
  service above now subsumes this: any user with forge access to an **already-provisioned** org is
  auto-projected into membership at login via their transient token (org admins → Hibou `admin`, capped),
  so co-admins gain access without a manual invite. _Org **creation** still flows through installation
  auto-provision / the installer-gated create; that gate is intentionally left in place._
- [x] **Slugify non-`[a-z0-9-]` forge accounts** ✅ (backend) — `slugifyAccount`
  ([internal/orgprovision/service.go](internal/orgprovision/service.go)) now normalizes any non-`[a-z0-9]`
  run to a single `-`, trims/collapses hyphens, and caps at 63 chars, so accounts like `Foo_Bar`/`acme.io`
  auto-provision instead of silently failing `api.IsValidSlug`. `AuthorizeForgeOrgCreation` scans all
  installations whose account collides to the same slug (no false-negative deny). UI slug-edit affordance
  already exists in the manual-create dialog (P0 above) for explicit disambiguation of rare collisions.
