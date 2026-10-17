# ADR-047: Inventory evidence governance (deferred)

## Status

Proposed, **deferred** (2026-10-15). Third of three related ADRs. It extends
[ADR-045](045-built-in-dependency-inventory.md) §5.3 and
[ADR-046](046-dependency-cli.md) §4.3 with approval workflows for the actions
that can hide a vulnerability from a release. Nothing here is required for
ADR-045 or ADR-046 to ship; it is adopted when an org, a customer audit or an
incident asks for it. The schema of ADR-045 leaves room for it, so adoption
is additive.

## Context

ADR-045 already guarantees:

- CI and Hibou-scan evidence (`ci`, `repository_scan`, `legacy` origins) can
  never be deleted, revoked or edited by anyone; the database enforces it.
- Manual evidence (deliverables scanned with the CLI, retroactive uploads) is
  additive only: it adds components and discrepancies, never removes or
  changes existing ones.
- A manual source can be revoked by an admin, with a reason, from a user
  session, audit-logged and notified to org admins; revocation leaves
  affected findings "not re-checked", never resolved (ADR-034).
- The auditor role sees the full history and changes nothing.

Three actions remain where a single person's decision removes evidence from
the views that clients, gates and exports depend on:

1. Revoking a manual source (its components leave the inventory).
2. Settling a discrepancy by revoking the source that carried the vulnerable
   version.
3. Accepting an extractor-upgrade result that removes components from a
   pinned release (ADR-045 §4.3.1 applies these automatically, with history
   and labels).

For most orgs, admin-only plus audit log is enough. Orgs under ISO 27001,
SOC 2 or customer contracts that require segregation of duties for changes
to shipped-product records need a second pair of eyes. This ADR specifies
that layer so that it is designed once and switched on per org.

## Decision

### 1. Two-person approval for actions that can hide a vulnerability

An org setting `inventory.two_person_approval` (default **off**) turns the
actions below into a request-and-approve flow.

| Action | Can hide a CVE | Without the setting (ADR-045) | With the setting |
|---|---|---|---|
| Add a manual source, restore a revoked one | No | admin or release_manager | unchanged |
| Revoke a manual source | Yes | admin, with reason | **requested** by an admin or release_manager, **approved** by a second admin |
| Resolve a discrepancy by choosing a source (§2) | Yes, when the removed version carried a CVE | admin revokes the wrong source | same two-person flow when a CVE is removed; single admin otherwise |
| Apply an extractor-upgrade candidate that removes components (§3) | Yes | automatic, labelled | **review queue**: a release manager applies; a second admin approves when a CVE is removed |
| Revoke a build-time source | — | nobody | nobody |

Rules:

- **Humans only.** Requests, approvals and resolutions are refused for
  automation tokens and org service principals (ADR-020, ADR-022). They
  require a user session, in the web UI or through the CLI's browser login
  (ADR-043).
- **No self-approval.** The approver must be a different user from the
  requester. A pending request shows on the release and expires after 14
  days; expiry is recorded, not silent.
- **Visible.** Every request, approval, rejection, expiry and restore is
  audit-logged, notified to the org admins, and shown permanently in the
  release history.
- **Auditors read, never approve.** The auditor role is read-only for
  external compliance reviewers; it sees requests, decisions, who, when and
  why, as audit evidence.
- **Single-admin orgs** cannot produce a second approver. The setting cannot
  be turned on while the org has fewer than two admins; if it later drops to
  one, pending requests stay pending and the org settings page says why.

### 2. Discrepancy resolution

ADR-045 §5.3 keeps both versions of a component when a manual source
disagrees with a build-time source, matches both, and flags the component.
Settling it means deciding which source is right.

- The release page lists each discrepancy with both versions, their sources
  and their vulnerabilities, and a **choose source** action.
- Choosing the build-time source is always allowed for an admin: it is the
  default evidence, and the manual source is revoked as a consequence.
- Choosing the manual source over the build-time one never deletes the
  build-time source (immutable); it marks the component's build-time version
  as **superseded for this release**, with the reason. When the superseded
  version carried a CVE that the chosen one does not, the two-person flow of
  §1 applies.
- Resolutions are stored as their own rows (§4), so the flag can be
  recomputed and the decision reviewed later.

### 3. Extractor-upgrade review queue

ADR-045 §4.3.1 re-extracts pinned releases after an extractor upgrade and
adds the result as a new source, with disappearances labelled "changed by
extractor update". Orgs with the setting on get a review step in front of
removals:

1. The re-extraction result is stored as a **candidate** source: present,
   diffed against the current inventory, not counted.
2. Candidates that **only add** components or fill `unknown` relationships
   are applied automatically, as in ADR-045: they can only add CVEs.
3. Candidates that **remove** components or change versions wait in a review
   queue on the Releases tab. A release manager applies them; when applying
   removes a CVE, a second admin approves.
4. Applying sets `applied_at`; the old source stays. Rejecting leaves the
   candidate in history as rejected, with the reason, and the release keeps
   showing "extractor vX available, not applied".

### 4. Database additions

All additive to the ADR-045 schema; nothing existing changes.

```sql
ALTER TABLE inventory_sources
    ADD COLUMN candidate_at timestamptz,     -- extractor-upgrade candidate (§3)
    ADD COLUMN applied_at   timestamptz,     -- NULL while a candidate
    ADD COLUMN revoke_approved_by uuid;      -- second approver (§1)

CREATE TYPE inventory_request_kind AS ENUM ('revoke', 'resolve', 'apply_candidate');
CREATE TYPE inventory_request_state AS ENUM ('pending', 'approved', 'rejected', 'expired');

CREATE TABLE inventory_approval_requests (
    id            bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    org_id        uuid NOT NULL,
    repo_id       uuid NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    release_id    uuid REFERENCES releases(id) ON DELETE CASCADE,
    kind          inventory_request_kind NOT NULL,
    source_id     bigint REFERENCES inventory_sources(id),
    component_id  uuid REFERENCES components(id),     -- resolve: the component
    chosen_source_id bigint REFERENCES inventory_sources(id),
    removes_cve   boolean NOT NULL,                   -- computed at request time
    reason        text NOT NULL,
    requested_by  uuid NOT NULL,
    requested_at  timestamptz NOT NULL DEFAULT now(),
    state         inventory_request_state NOT NULL DEFAULT 'pending',
    decided_by    uuid,
    decided_at    timestamptz,
    decision_note text,
    expires_at    timestamptz NOT NULL,
    CHECK (decided_by IS NULL OR decided_by <> requested_by)
);
CREATE INDEX inventory_approval_requests_pending_idx
    ON inventory_approval_requests (repo_id, release_id)
    WHERE state = 'pending';

CREATE TABLE inventory_discrepancy_resolutions (
    id            bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    snapshot_id   uuid NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,
    component_key text NOT NULL,                      -- purl without version
    module_path   text NOT NULL DEFAULT '',
    chosen_source_id bigint NOT NULL REFERENCES inventory_sources(id),
    request_id    bigint REFERENCES inventory_approval_requests(id),
    reason        text NOT NULL,
    decided_by    uuid NOT NULL,
    decided_at    timestamptz NOT NULL DEFAULT now(),
    UNIQUE (snapshot_id, component_key, module_path)
);
```

The ADR-045 immutability trigger on `inventory_sources` gains two allowed
transitions: setting `applied_at` once on a candidate, and setting
`revoke_approved_by` together with the revocation columns of a `manual`
row. Request rows are append-mostly: only `state`, `decided_*` and
`decision_note` change, once.

### 5. UI and CLI additions

- Releases tab: a **pending approvals** badge and list; the review queue for
  extractor candidates; "choose source" on discrepancies.
- CLI (ADR-046 conventions): `hibou release sources approve|reject
  <request-id> --note ...` and `hibou release candidates list|apply|reject`,
  all requiring a user login.
- Org settings: the `two_person_approval` toggle with its admin-count
  precondition, and the notification rule for pending requests.

## Consequences

- Orgs that need segregation of duties get it without changes to how
  evidence is stored; orgs that do not keep the simpler admin-only rules.
- Pending requests can block a release manager for up to 14 days if admins
  are unresponsive; the notification rule and the visible badge exist for
  that reason.
- The extractor review queue delays the benefit of parser fixes on pinned
  releases for orgs that enable it; the labelled automatic path of ADR-045
  remains the default.
- Three small tables and three columns; no change to the hot inventory
  tables.

## Alternatives considered

- **Ship this with ADR-045.** The first draft did. It added a workflow engine
  to an inventory feature that most orgs will never switch on, and made the
  inventory ADR too large to review. Deferred instead, with the schema
  designed now so adoption is additive.
- **Never.** Some orgs will be asked by auditors for segregation of duties on
  shipped-product records; "an admin can revoke with a reason" may not pass.
  Keeping the design ready costs little.
- **Approval by the auditor role.** Auditors are external reviewers and must
  stay read-only; approving would make them actors in the records they
  audit.
- **Hard delete with approval** instead of revocation: loses history that
  the same auditors ask for. Revocation stays the only mechanism.
