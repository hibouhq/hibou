# ADR-028 Implementation TODO — CVE subscriptions with human purl triage

Tracking checklist derived from [ADR-028](028-cve-subscriptions-with-manual-purl-triage.md).
Tick items as they land. Phases are ordered to keep the build green: the RBAC
foundation first (it is a hard prerequisite and independently testable), then pure
ingestion/projection code, then schema, then the write path, then UI, then the
optional identity work.

> Conventions: nothing authored by a human reaches a quality gate until §5's queue
> exists; `auto_apply` defaults **off**; the feed is **never** cloned (§3);
> `advisory:triage` is an explicit grant, never inherited (§17). Every phase after
> 1 assumes the local-role namespace exists.

## Phase 0 — Decisions required before code

- [ ] **Deployment model declared**: single-organisation instance vs multi-tenant.
      Decides whether instance-wide triage is the default or is disabled (§17).
      Nothing in config distinguishes them today.
- [ ] **Named owner for the triage queue** identified (§14). Without one the queue
      is not worked and the ADR fails regardless of implementation quality.
- [x] **`HSA` go/no-go** — **decided: reserve, do not build.** No editorial
      commitment needed yet; see Phase 8. Original question retained below:
      is there a resourced editorial commitment to curate
      common infrastructure (§16)? An unstaffed `HSA` is worse than none. If
      no-go, Phase 8 is dropped and `HSAT`/instance scope is the whole story.
      -> may document in code for futur complete implem but we won't implement this now...

## Phase 1 — RBAC foundation (prerequisite, no ADR-028 features yet)

> Landed in `internal/rbac` (`keys.go`, rewritten `policies.go`, enforcer
> methods, 8 tests). **A pre-existing cross-tenant authorization bug was found
> and fixed here** — see the matcher item below; it predates ADR-028 and
> affected every org-scoped permission check in the product.
>
> Still open in this phase: the downgrade/suspension conflict rules and the
> stale-sync surface, both of which need the Phase 3 schema to record a
> suspended grant.

Independently valuable and independently testable; ships before anything else.

- [x] Namespace role ownership (§17):
      `role:forge:<name>:org:<id>` (sync-owned) vs
      `role:local:<name>:org:<id>` (operator-owned)
- [x] Add the **`instance:` object namespace** and `role:local:<name>:instance`.
      Casbin has no instance scope today — every key is `org:<uuid>`-scoped
      ([rbac.go:43](../../internal/rbac/rbac.go#L43),
      [policies.go:11](../../internal/rbac/policies.go#L11))
- [x] Keep it **distinct from the existing instance-admin config list**
      (`HIBOU_INSTANCE_ADMINS` / `InstanceAdminsFile`,
      [instance_settings.go:46](../../internal/server/instance_settings.go#L46)).
      That list is email-keyed, static, and deliberately scoped to banners +
      instance audit; it must not become the triage authority
- [x] `permissionsync` writes **only** the `role:forge:*` namespace; assert it can
      never add, remove or overwrite a `role:local:*` grant
- [x] Conflict rules (§17), each with a test:
      - [x] forge upgrade → base role follows immediately, local grants unchanged
      - [x] forge downgrade → base role follows, **privileged local grants
            suspended + operator notified**
      - [x] membership removed → base role *and* local grants revoked
      - [x] sync failure → fail **stale** (keep last known), never fail closed —
            `SyncUser` returns early on a missing token or provider, so a failed
            sync changes nothing rather than revoking
      - [ ] surface a sync that has not succeeded for N hours — the feed has this
            (§11b health strip); permission sync does not yet
- [x] Express roles as a Casbin **hierarchy** — `g("role:admin:org:X",
      "role:developer:org:X")` — replacing the duplicated action lists in
      [policies.go](../../internal/rbac/policies.go). No model change needed;
      `g = _, _` already chains
- [x] ~~Fix the live bug: a members-dropdown role can be overwritten by the next
      sync~~ — **not a bug.** `org_members.source` (`invite` | `forge`) already
      separates them and the sync upsert is guarded `WHERE source = 'forge'`
      ([queries/org_members.sql:47](../../internal/store/queries/org_members.sql#L47)),
      pinned by `TestTwoSourceMembershipInvariants`. `release_manager` and
      `auditor` are unreachable from `RoleForTier` and so are local-only by
      nature, which is what the namespace now makes explicit
- [x] **Fixed a cross-tenant authorization bug found here**: the Casbin matcher
      was `keyMatch2`, which reads `:name` as a named parameter, so the object
      `org:<uuid>/*` compiled to `^org[^/]+/.*$` and matched **every** org — a
      role in one org authorized the same actions in all others. Now `keyMatch`;
      `TestOrgPoliciesDoNotCrossOrgs` and `TestOrgRoleDoesNotReachInstanceObjects`
      pin it
- [x] New local-only roles seeded: `subscription:write`, `advisory:triage`
      (`cve-triager`), `advisory:promote` (instance only)
- [x] `internal/audit` entry on every `advisory:triage` use

## Phase 2 — Feed ingestion (pure, no schema)

> Landed in `internal/cvefeed` (decoder, normalisation, severity selection;
> 10 tests, fixtures are real records). Validated against the full published
> corpus: **zero decode failures** over a 6,261-record sample, 4.9% `REJECTED`
> retained, 50% carrying a scored severity, 6,902 products / 17,725 ranges.
>
> Two things the corpus corrected that the ADR had not anticipated:
> **(a)** a bare `version` with no `lessThan`/`lessThanOrEqual` is one exact
> affected release and is **65% of all affected entries** — an early draft
> dropped them as unbounded and lost most of the feed's usable data (usable
> products 29% → 56% once fixed). Only a wildcard (`*`, `0`, `-`) is genuinely
> open, and only that is dropped.
> **(b)** severity must be chosen by the quality of the statement, not the
> standing of its author: on CVE-2026-59084 the CNA supplies the textual "low"
> while CISA-ADP supplies CVSS 9.1 CRITICAL.

- [x] **Blobless shallow git ingester** (§3): `git clone --depth 1
      --filter=blob:none --no-checkout` — measured **9.3 MB in 6 s**, not 2.6 GB;
      then `git fetch --depth 1` + `git diff --name-only` to name changed CVE
      files, fetching only those blobs (~7 KB each)
- [x] Short poll interval — the repo commits ~2.8×/hour, so ~21 min granularity
      beats the hourly release bundles
- [x] ~~On-demand refresh via `cveawg`~~ — **dropped, one transport instead.**
      Measured: git content is byte-identical to the API for records git has
      (6/6, ±0 s); the only difference is arrival, ~13 min observed. A refresh
      re-reads from the pinned revision (~600 ms) rather than fetching, which
      also keeps git's repository lock out of request handlers
- [x] Release-bundle transport kept as a **fallback** for deployments without
      outbound git
- [x] Working state stays under 10 MB — assert blobs are never checked out
- [x] Projection decoder: CVE Record Format 5.x → index tier and index+prose tier
      (0.33 KB / 0.88 KB per record measured, §13)
- [x] Per-record size cap — the corpus contains a 23.4 MB record (§13)
- [x] Track `state` as a first-class field — **do not skip `REJECTED`** (§11b):
      a `PUBLISHED` → `REJECTED` transition must retire derived findings
      automatically. ~5% of the corpus is rejected, and one appeared in a single
      500-record delta
- [x] Treat revisions as the common case, not the exception — **73%** of a
      delta's records are revisions of already-published CVEs
- [x] Normalisation helper: casefold + strip non-alphanumerics for product/vendor
      keys (§4)
- [x] ~~`cveawg.mitre.org` point-lookup client~~ — **dropped.** Git content is
      byte-identical for records git has (6/6, ±0 s); a refresh re-reads from the
      pinned revision instead, which also keeps git's repo lock out of handlers
- [x] Unit tests over recorded fixtures, including: missing `vendor`, missing
      `product`, `n/a` placeholders, multi-`affected[]` records, `lessThan` vs
      `lessThanOrEqual`
- [x] Range conversion shared with `scripts/ghsa-contrib/`: `lessThanOrEqual` →
      `last_affected`, `lessThan` → `fixed`, **never an inferred fix version**
- [x] Bare `version` → an exact point interval, not an open range (65% of
      affected entries); wildcard versions dropped
- [x] Severity chosen by statement quality across CNA **and** ADP containers —
      a structured vector always beats free text

## Phase 3 — Schema, sized for the access patterns (§18)

> Landed as migration `00031_cve_subscriptions` + `internal/store/cve_feed.go`,
> `advisory_events.go`, 24 sqlc queries and 2 integration tests. Applied and
> rolled back against Postgres 18.
>
> **Explain-analysed at corpus scale** — 380,000 records, 760,000 affected rows:
>
> | Query | Plan | Time |
> |---|---|---|
> | Subscription preview | Index Scan on `product_key` + PK lookups | **2.4 ms** |
> | Revision detection | Index Scan on `record_updated_at` | **0.03 ms** |
> | Subscription match | Seq Scan (400 rows — planner is right; the GIN index is there for when it is not) | **0.09 ms** |
>
> Raw records deliberately do NOT go in Postgres: the corpus is 3.14 GB with a
> 23.4 MB outlier, against ~0.9 KB per row for the projection.

- [x] Migration: `cve_subscriptions`, `cve_triage_items`,
      `product_package_mappings` (§12)
- [x] Migration: corpus projection table, with **`dateUpdated` indexed** —
      revision detection runs on every delta and must not scan (§18)
- [x] Migration: **`cve_affected_products`** — `affected[]` denormalised out of
      JSON (~3.8 rows per record, ~1.4M for the corpus). Turns the subscription
      preview and matcher from a JSON scan into an index lookup (§18)
- [x] Store `product_key` / `vendor_key` **pre-normalised** (casefold, strip
      non-alphanumerics) with raw strings kept alongside for display; index the
      normalised column, never the raw one
- [x] GIN index on `cve_subscriptions.product_keys`
- [x] Migration: `advisory_events` (append-only, §11), **partitioned by month**
      following [audit_partitions.go](../../internal/store/audit_partitions.go)
- [x] Raw records go to `internal/objstore`, **not Postgres** — subscribed records
      only, and the corpus holds a 23.4 MB record (§13, §18)
- [x] Explain-analyse the preview query and the delta-match query against a
      full-corpus fixture before declaring the phase done
- [x] Confirm `advisories`, `advisory_aliases`, `advisory_sources`,
      `affected_ranges` and `components` are **untouched** — the central claim of §7

## Phase 4 — Matching and the authoring write path

> Landed in `internal/cvetriage` (`cvetriage.go`, `review.go`; 9 tests) plus two
> convergence tests in `internal/advisory`.
>
> **The dedup guarantee is now proven rather than asserted**, in both directions:
> authored coordinates arriving after upstream join the existing advisory, and
> upstream arriving after a triager authored join theirs. Either way one
> `advisories` row, the CVE canonical, both sources recorded — so an org never
> carries two advisories for one vulnerability.
>
> Still open here: `auto_apply` evaluation and divergence *detection against a
> live upstream feed* — the diff and the staleness check exist and are tested,
> but nothing yet runs them on a schedule. That is the worker, and it wants the
> Phase 6 notification wiring to be useful.

- [x] Subscription matcher: normalised product key, optional vendor narrowing,
      **never** keyed on `assignerShortName` (§4)
- [x] Watch-candidate derivation: components no provider covers (§1)
- [x] Subscription **preview**: which historical CVEs would have matched (§4) —
      exact once the corpus is mirrored (§13)
- [x] Triage decision writes `affected_ranges` via the existing ingest path with
      `source = 'hsa' | 'hsat:<org>' | 'instance'` (§7)
- [x] Verify alias convergence: authored data for a CVE lands on the *same*
      `advisories` row as OSV/NVD, via `preferredCanonicalID` /
      `shouldPromoteCanonicalID` — with a test, since this is the dedup guarantee
- [x] Revision detection wired into the sweep: a record moving past the value a
      decision was stamped with re-opens it with a `cna_revised` event
      (`internal/cvetriage/reviewpass.go`, 4 tests)
- [x] Divergence *against upstream coordinates* —
      `internal/cvetriage/divergence.go` + `divergencepass.go` +
      `internal/provider/osv/vulns.go`, 11 tests, run in the same sweep pass.
      Adopts nothing automatically: `superseded` when upstream is broader or
      equal, `diverged` when it is narrower, both as events a person reads.
      **Any** contraction diverges, even alongside an expansion — the packages it
      drops are findings that would disappear.
      Two things the implementation had to get right: a failed lookup is counted
      as failed, never as "upstream names nothing" (which would diverge every
      mapping on a network blip); and aliases are followed, because OSV serves a
      CVE ID from its CVE ecosystem where `affected[].package` is null —
      `/v1/vulns/CVE-2021-44228` has no package at all while its alias
      `GHSA-jfh8-c2jp-5v3q` carries ten Maven coordinates, so a lookup stopping
      at the CVE record would report "no upstream coordinates" for every advisory
      ever checked
- [x] CNA revision detection: `dateUpdated` past the triaged value re-opens the
      item (§8)
- [x] `auto_apply` per mapping, default **off** (§8, §14)
- [x] **Diff on `cna_revised`**: compute changed field paths + before/after
      against the stored projection, write to `advisory_events.detail`. Do not
      retain full prior copies (§18)
- [x] **Audit vs timeline separation** (§18): a triage action writes to both
      `advisory_events` *and* `internal/audit`; a CNA revision writes only to the
      timeline. Assert the audit entry records actor, mapping, before/after

## Phase 5 — UI / UX

> **Watches** landed as a complete vertical slice (originally `watched-software`
> under an org; renamed and moved under `/instance/advisories/watches` once the scope question
> resolved — see the ADR's §17): four handlers
> (`internal/server/watched_software.go`) with API-token scopes declared,
> `WatchedSoftwareTab.vue`, `WatchProductDialog.vue`, client types, route and
> org tab. Built against the app's own tokens rather than a new aesthetic — a
> new page that does not look native is a defect, not a design choice.
>
> The two decisions worth keeping: the list is a **coverage** view, not an
> inventory (the last-matched column exists to separate quiet-because-safe from
> quiet-because-misnamed, and a never-matched product is flagged after 14 days);
> and the create dialog runs the §4 preview live, so a wrong name is caught in
> seconds instead of as months of silence.
>
> Two bugs found and fixed in the first cut, both from the discarded per-row
> scope model: an IDOR on delete (any org admin could remove any watch by id,
> instance-wide ones included), and a scope escalation on create (an org admin
> could create a watch governing every org from a URL scoped to their own).
> Collapsing to instance-wide made both unrepresentable rather than guarded.
>
> Remaining Phase 5 screens — triage queue, activity, timeline, members rework,
> instance-wide members view — are not built.

The triage queue is where this ADR lives or dies: if one CVE takes longer than a
minute, the queue will not be worked (§15).

- [x] **Instance admin: global members/teams view** — new
      (`site/src/views/settings/`, alongside `InstanceAdminsSettings.vue`):
      - [x] One table of every user across **all orgs and all forges**, showing
            per-org base role and per-org/instance local grants
      - [x] Answers "what can this person do everywhere?" before a cross-org role
            is granted — currently unanswerable, since the members panel is
            per-org (§17)
      - [x] Identity is one person across forges; group rows by user, not by
            forge account
      - [x] **Define and grant local-only roles here**, `cve-triager` included —
            they exist outside any forge's vocabulary so they have no other home
      - [x] Filter by role, by org, by forge; find "everyone who can triage"
      - [x] Visible to instance admins only; every grant audited
- [x] **Members settings rework** (per-org, `SettingsView` / members panel):
      - [x] Base role shown as **synced and read-only**, with its forge origin named
      - [x] Separate **"Additional grants"** control (multi-select, not a dropdown)
            listing local-only roles incl. `cve-triager`
      - [x] Suspended-grant state rendered distinctly, with the reason
            ("forge role downgraded — re-confirm")
      - [x] Remove the current single-role dropdown's ability to set roles the
            sync will overwrite
- [x] **Triage queue view** — new:
      - [x] One screen: CVE, CNA ranges, severity, description
      - [x] **Form modelled on GitHub's advisory form, minus half of it** (§18):
            ecosystem + package rows only. Ranges are derived and shown read-only.
            If a third input appears, question it against the one-minute budget
      - [x] Ranked inventory candidates, multi-select, no version typing (§6)
      - [x] Keyboard-first; match the existing `j/k` finding navigation
      - [x] Reads as a work queue with an end — a count that reaches zero, no
            pagination trap
      - [x] ~~Scope selector (org vs instance)~~ — obsolete; one scope
- [x] **Watch candidates view**: uncovered components listed beneath the watch
      list, promote opens the dialog **pre-filled and previewed** rather than
      watching outright — a component's package name is rarely the name its
      vendor files advisories under, and the preview is what proves which (§1, §4)
- [x] **CVE activity view** (§11b) — "what moved since I last looked":
      - [x] Reverse-chronological stream: queued / revised / rejected /
            superseded / diverged
      - [x] ~~Subscribed by default, expandable to the whole feed~~ — obsolete;
            events are instance-wide, so there is one stream and no split
      - [x] Unmatched records **counted, not listed** (~1,297/day) so it stays
            readable
      - [x] Feed health in the same place — last sync, records seen, matches —
            so "quiet week" and "broken poller" cannot look alike
- [x] **Advisory timeline**: reuse `FindingTimeline.vue`'s vocabulary for the §11
      event kinds (`published`, `cna_revised`, `enriched`,
      `coordinates_authored`, `coordinates_upstreamed`, `superseded`, `diverged`,
      `withdrawn`)
      - [x] **External and human events interleaved in one list** — a CVE triaged
            in July and revised by the CNA in August shows both, in order (§18)
      - [x] `cna_revised` renders *what* changed, from the stored diff — a triager
            must be able to tell a typo fix from a widened range
- [x] **Date disambiguation** (§18) — the collision risk:
      - [x] Group dates as **Upstream** (reserved / published / revised) vs
            **Here** (known here / first detected / last seen)
      - [x] **Never render a bare date**; every one is labelled with its origin
      - [x] "First detected" keeps its existing `first_seen_at` meaning; nothing
            else may reuse the phrase
      - [x] Surface **detection lag = first detected − published**; on the
            motivating case it is over a month, and it is the number that makes
            the gap legible
      - [x] Audit every existing surface that prints a date for ambiguity before
            adding new ones
- [x] **Provenance on findings**: *locally curated* label naming the decider (§9),
      following ADR-027 §8's rule — badge the exception, never the norm
- [x] **Filters**: satisfied by the attribution change — authored findings carry
      `scanner_name = "triage"`, so the existing `tool:` filter and its
      data-derived facet reach them with no new axis
- [x] Empty states that say what to do next, for every new view

## Phase 6 — Notifications

> Event types `triage.queued` and `advisory.diverged` landed in
> `internal/events`, with dispatcher copy in `internal/notify` and a **digest**
> emitted once per sweep rather than once per record.
>
> The sweeper that these notify *about* has landed:
> `internal/cvetriage/sweeper.go` + `internal/server/cve_feed_loop.go`, always
> on, leader-locked so replicas do not race the cursor, on a 15-minute tick.
> No switch and no path to configure: the clone directory is derived, because
> the resume point lives in the database and the clone is a disposable ~10 MB
> cache. Nothing to set in a Helm chart, and no volume needed.
>
> One bug the tests caught and fixed: the first version advanced the feed cursor
> even when records had failed to store, which silently skips those advisories
> for ever — precisely the failure this feature exists to prevent. The cursor
> now holds until a clean pass, and re-reading is free because storing and
> queueing are idempotent.

- [x] `subscription.match` and `advisory.diverged` event types through
      `internal/notify`'s existing dispatchers (Slack/Teams/Discord/email/webhook)
- [x] **Digest by default**, not per-CVE — ~1,300 records/day across the feed
      means a well-targeted subscription can still burst (§17)
- [x] ~~Instance vs org notification routing~~ — obsolete; one scope, one queue
- [x] Notify on privileged-grant suspension (Phase 1 conflict rules)

## Phase 7 — Corpus mirror (optional, enables exact preview)

> `internal/cvetriage/seed.go`, run automatically by the sweep. Verified against
> the real published corpus: 382,343 records seen, 382,341 stored, 2 malformed,
> 56 s, streamed with nothing written to disk.
>
> Not optional in practice, which the implementation made obvious: the §4
> preview is the only thing that makes a wrong product name visible, and on an
> empty database it answers zero for *every* name — a preview that cannot tell a
> good name from a typo is worse than none, because it looks like an answer.
>
> `SeedStore` deliberately cannot queue: an import must not put twenty years of
> advisories in front of a person. Enforced by the interface, with a test.
>
> Throughput measured at ~215,000 records in ten minutes (batched; ~1.5x the
> per-record path). The remaining cost is round trips, not transactions.

- [x] Index+prose projection for the full corpus (~340 MB measured, §13)
- [x] Raw retained **only** for subscribed records
- [x] Backfill: full corpus once, then hourly deltas
- [x] **Seeding is automatic** — the first sweep resolves the current commit,
      streams the corpus at it, and anchors there. No command, no switch, no
      path to configure
- [x] Deleted before shipping: the `cve-backfill` command and the release-bundle
      transport. Neither had a user, and the bundle's premise does not hold —
      `git clone https://github.com/...` *is* HTTPS, so "git blocked but HTTPS
      allowed" is not a real deployment. Keeping them meant two seeding paths and
      a bundle instance that could not seed at all
- [x] Streamed via `git archive`, never checked out: 300 MB pack, 382,354 records
      in 17 s, and the ~3.2 GB working tree never exists. Whole seed into
      Postgres measured end to end at 15 min / 382,346 rows
- [x] Resume point recorded as a commit, chosen up front rather than
      reconstructed afterwards: the same commit is snapshotted and anchored, so
      the two cannot disagree
- [x] **Seeding follows `cve_feed.remote`** — both halves, choosing the commit
      and streaming the corpus. An air-gapped instance mirroring the CVE list
      onto an internal git server seeds from that mirror; a hardcoded vendor host
      would have failed for exactly the deployment that needs the setting.
      Verified against a local git remote with no network
- [x] Deliberately **no** CVE browser UI — mirror as infrastructure, not a feature
      (§13's product-surface warning)

## Phase 8 — Identity: reserve now, build later

> **Decided:** prepare for `HSA-*` without implementing it. The namespace is
> reserved defensively; curation, the distribution channel and publication stay
> unbuilt, and none of it appears in user-facing documentation until it exists.

- [x] Default path confirmed: attach to the existing CVE, **mint nothing** (§10)
- [x] **Namespace closed to providers** — `rejectReservedAliases` drops `HSA-*`
      from anything a provider supplies, matched on shape rather than prefix so
      an unrelated vendor id is not wrongly claimed. Silent rather than fatal: a
      stray alias must not block a feed. 2 tests
- [x] ~~`authored_advisories` table~~ — not needed while nothing mints
- [ ] `HSA` minting for the no-upstream-identity case only — **deferred**
- [ ] Withdrawal semantics; IDs never reused — **deferred with minting**
- [ ] If ever exported: register the prefix with OSV rather than squat it
- [ ] Decide on a public git repo for `HSA` (review, history, auditable, one step
      from a GHSA PR) — **deferred**
- [x] **Not documented user-facing** until it exists: a documented identifier
      nobody can obtain is a support question, not a feature

## Validation

- [x] Fixture images in `hibou-sample-project` triage end-to-end: an uncovered
      Tomcat component becomes a watch candidate, a subscription, a queued CVE, a
      mapping, and a finding
- [x] The second Tomcat CVE requires no triage — the reuse claim, demonstrated
- [x] ~~Tenancy: `HSAT` in org A invisible to org B~~ — obsolete; there is one
      instance-wide scope, so there is no cross-org visibility question
- [x] Permissions: a `developer` without `advisory:triage` cannot author; with it,
      can; after a forge downgrade, cannot until re-confirmed
- [x] Storage measured against the §13 figures rather than assumed
