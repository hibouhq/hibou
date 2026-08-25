-- name: UpsertCVERecord :exec
-- first_seen_at is set once and never moved: it is when THIS instance learned
-- of the record, which is a different fact from when the CNA published it, and
-- the gap between them is the detection lag worth reporting.
INSERT INTO cve_records (
    cve_id, state, assigner, published_at, record_updated_at,
    cvss_score, cvss_vector, severity, cwe_ids, summary, reference_urls
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
ON CONFLICT (cve_id) DO UPDATE SET
    state = EXCLUDED.state,
    assigner = EXCLUDED.assigner,
    published_at = EXCLUDED.published_at,
    record_updated_at = EXCLUDED.record_updated_at,
    cvss_score = EXCLUDED.cvss_score,
    cvss_vector = EXCLUDED.cvss_vector,
    severity = EXCLUDED.severity,
    cwe_ids = EXCLUDED.cwe_ids,
    summary = EXCLUDED.summary,
    reference_urls = EXCLUDED.reference_urls;

-- name: GetCVERecord :one
SELECT * FROM cve_records WHERE cve_id = $1;

-- name: DeleteCVEAffectedProducts :exec
DELETE FROM cve_affected_products WHERE cve_id = $1;

-- name: InsertCVEAffectedProduct :exec
INSERT INTO cve_affected_products (
    cve_id, vendor, product, vendor_key, product_key, introduced, fixed, last_affected
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8);

-- name: ListCVEAffectedProducts :many
SELECT * FROM cve_affected_products WHERE cve_id = $1 ORDER BY product, introduced;

-- name: MatchSubscriptionsForProductKeys :many
-- Which watched products does an incoming record concern?
--
-- product_keys overlap drives the match; vendor_keys only ever NARROWS it, and
-- an empty vendor_keys means "any vendor". The reverse — requiring a vendor —
-- would miss records where the CNA moved a name across the vendor/product
-- boundary, which happens within a single CNA.
SELECT s.* FROM cve_subscriptions s
WHERE s.product_keys && $1::text[]
  AND (cardinality(s.vendor_keys) = 0 OR s.vendor_keys && $2::text[])
ORDER BY s.label;

-- name: PreviewSubscriptionMatches :many
-- "Which advisories would this subscription have caught?", answered against the
-- local corpus before the subscription is created.
--
-- A wrong alias otherwise produces silence, and silence is indistinguishable
-- from safety — this turns that into a visibly short list at the moment of the
-- decision rather than an absence of alerts nobody notices for months.
SELECT DISTINCT r.cve_id, r.published_at, r.severity, r.cvss_score, r.summary
FROM cve_records r
JOIN cve_affected_products a ON a.cve_id = r.cve_id
WHERE a.product_key = ANY($1::text[])
  AND r.state = 'PUBLISHED'
ORDER BY r.published_at DESC NULLS LAST
LIMIT $2;

-- name: CountSubscriptionMatches :one
SELECT COUNT(DISTINCT r.cve_id) FROM cve_records r
JOIN cve_affected_products a ON a.cve_id = r.cve_id
WHERE a.product_key = ANY($1::text[]) AND r.state = 'PUBLISHED';

-- name: CreateCVESubscription :one
INSERT INTO cve_subscriptions (label, product_keys, vendor_keys, created_by)
VALUES ($1, $2, $3, $4)
RETURNING *;

-- name: ListCVESubscriptions :many
-- The pending count rides along because a watched product without it reads the
-- same whether it is quiet or ignored, and the queue depth is the actionable
-- half of the row.
SELECT s.*, COALESCE(t.pending, 0)::bigint AS pending_triage
FROM cve_subscriptions s
LEFT JOIN (
    SELECT subscription_id, COUNT(*) AS pending
    FROM cve_triage_items
    WHERE state IN ('pending', 'reopened')
    GROUP BY subscription_id
) t ON t.subscription_id = s.id
ORDER BY s.label;

-- name: DeleteCVESubscription :exec
DELETE FROM cve_subscriptions WHERE id = $1;

-- name: TouchSubscriptionMatched :exec
UPDATE cve_subscriptions SET last_matched_at = now() WHERE id = $1;

-- name: UpsertTriageItem :exec
INSERT INTO cve_triage_items (subscription_id, cve_id, state)
VALUES ($1, $2, 'pending')
ON CONFLICT (subscription_id, cve_id) DO NOTHING;

-- name: ListPendingTriageItems :many
-- The queue, oldest first. It is a work list with an end, not a feed.
SELECT t.*, r.severity, r.cvss_score, r.summary, r.published_at, s.label
FROM cve_triage_items t
JOIN cve_records r ON r.cve_id = t.cve_id
JOIN cve_subscriptions s ON s.id = t.subscription_id
WHERE t.state IN ('pending', 'reopened')
ORDER BY t.created_at
LIMIT $1;

-- name: CountPendingTriageItems :one
SELECT COUNT(*) FROM cve_triage_items t
WHERE t.state IN ('pending', 'reopened');

-- name: RecordTriageDecision :exec
-- Stamps the record revision the decision was made against, so a later CNA
-- revision is detectable as such rather than silently leaving a stale mapping.
UPDATE cve_triage_items SET
    state = $2,
    decided_by = $3,
    decided_at = now(),
    triaged_record_updated_at = (SELECT record_updated_at FROM cve_records WHERE cve_id = cve_triage_items.cve_id)
WHERE id = $1;

-- name: ListTriageItemsNeedingReview :many
-- Decided items whose record has moved upstream since. A widened range can make
-- an existing mapping wrong in either direction, so these re-open rather than
-- resolve themselves.
SELECT t.*, r.record_updated_at, s.label
FROM cve_triage_items t
JOIN cve_records r ON r.cve_id = t.cve_id
JOIN cve_subscriptions s ON s.id = t.subscription_id
WHERE t.state = 'mapped'
  AND t.triaged_record_updated_at IS NOT NULL
  AND r.record_updated_at > t.triaged_record_updated_at
ORDER BY r.record_updated_at DESC;

-- name: ListWithdrawnMappedCVEs :many
-- Records we mapped that upstream has since retracted. Findings derived from
-- them must be retired; leaving them standing is a false positive with a
-- person's name attached to it.
SELECT DISTINCT t.cve_id FROM cve_triage_items t
JOIN cve_records r ON r.cve_id = t.cve_id
WHERE t.state = 'mapped' AND r.state = 'REJECTED';

-- name: CreateProductPackageMapping :one
INSERT INTO product_package_mappings (
    subscription_id, packages, decided_from_cve, decided_by, auto_apply
) VALUES ($1, $2, $3, $4, $5)
RETURNING *;

-- name: GetActiveMappingForSubscription :one
SELECT * FROM product_package_mappings
WHERE subscription_id = $1 AND revoked_at IS NULL
ORDER BY decided_at DESC
LIMIT 1;

-- name: RevokeProductPackageMapping :exec
UPDATE product_package_mappings SET revoked_at = now() WHERE id = $1;

-- name: InsertAdvisoryEvent :exec
INSERT INTO advisory_events (advisory_id, cve_id, kind, occurred_at, actor_id, detail)
VALUES ($1, $2, $3, $4, $5, $6);

-- name: ListAdvisoryEventsForCVE :many
SELECT * FROM advisory_events
WHERE cve_id = $1
ORDER BY occurred_at DESC
LIMIT $2;

-- name: ListRecentAdvisoryEvents :many
-- The activity stream: what moved since you last looked. Unmatched records are
-- counted elsewhere, never listed here — ~1,300 records a day would drown it.
SELECT * FROM advisory_events
ORDER BY occurred_at DESC
LIMIT $1;

-- name: ListWatchCandidates :many
-- Components that no advisory source has anything to say about.
--
-- Not proof of a gap — a component with no findings may simply be clean — but
-- it is the only signal available before a watch exists, and it is the
-- difference between "you were told and did not act" and "you were never told".
-- Excludes anything an existing mapping already names, so the list shrinks as
-- products get watched rather than nagging forever.
SELECT c.name, c.ecosystem,
       COUNT(DISTINCT repo.id)::bigint AS repo_count,
       COUNT(DISTINCT c.version)::bigint AS version_count
FROM components c
JOIN snapshot_components sc ON sc.component_id = c.id
JOIN snapshots snap ON snap.id = sc.snapshot_id
JOIN refs r ON r.id = snap.ref_id
JOIN repositories repo ON repo.id = r.repo_id
WHERE NOT EXISTS (
        SELECT 1 FROM vulnerabilities v WHERE v.component_id = c.id
    )
    AND NOT EXISTS (
        SELECT 1 FROM product_package_mappings m
        WHERE m.revoked_at IS NULL
          AND m.packages @> jsonb_build_array(jsonb_build_object('ecosystem', c.ecosystem, 'name', c.name))
    )
GROUP BY c.name, c.ecosystem
ORDER BY repo_count DESC, c.name
LIMIT $1;

-- name: ListTriageCandidateComponents :many
-- Components that plausibly ship the affected product.
--
-- Ranked by how many repositories carry them, because the triager's real
-- question is "which of these do we actually run", and a component in twelve
-- repos is a more consequential decision than one in a forgotten branch. The
-- name filter is a starting point, not an answer — the whole reason a person is
-- here is that no mechanical rule maps a product name to a coordinate.
SELECT c.id, c.name, c.version, c.ecosystem, c.purl,
       COUNT(DISTINCT repo.id)::bigint AS repo_count
FROM components c
JOIN snapshot_components sc ON sc.component_id = c.id
JOIN snapshots snap ON snap.id = sc.snapshot_id
JOIN refs r ON r.id = snap.ref_id
JOIN repositories repo ON repo.id = r.repo_id
WHERE c.name ILIKE $1 ESCAPE '\'
GROUP BY c.id, c.name, c.version, c.ecosystem, c.purl
ORDER BY repo_count DESC, c.name
LIMIT $2;

-- name: GetTriageItem :one
SELECT t.*, r.state, r.severity, r.cvss_score, r.cvss_vector, r.summary,
       r.published_at, r.record_updated_at, r.first_seen_at, r.assigner,
       s.label
FROM cve_triage_items t
JOIN cve_records r ON r.cve_id = t.cve_id
JOIN cve_subscriptions s ON s.id = t.subscription_id
WHERE t.id = $1;

-- name: GetCVESubscription :one
SELECT * FROM cve_subscriptions WHERE id = $1;

-- name: ReopenTriageItem :exec
-- A decision the record has moved past goes back in the queue rather than being
-- re-decided for the triager: only a person can tell a corrected typo from a
-- range that now covers versions they run.
UPDATE cve_triage_items SET state = 'reopened' WHERE id = $1 AND state = 'mapped';

-- name: GetAutoApplyMapping :one
-- The stored mapping for a subscription, but only when its owner has opted that
-- product into applying automatically.
--
-- Off by default and per-product on purpose: a mapping curated for one CVE need
-- not hold for the next, because a later flaw in the same product can live in a
-- different artifact. Opting in is a statement that this product's artifacts are
-- stable enough for that.
SELECT * FROM product_package_mappings
WHERE subscription_id = $1 AND revoked_at IS NULL AND auto_apply = true
ORDER BY decided_at DESC
LIMIT 1;

-- name: SetMappingAutoApply :exec
UPDATE product_package_mappings SET auto_apply = $2 WHERE id = $1;

-- name: UpsertLocalRoleGrant :exec
INSERT INTO local_role_grants (user_id, role, org_id, granted_by)
VALUES ($1, $2, $3, $4)
ON CONFLICT (user_id, role, org_id) DO UPDATE
SET suspended_at = NULL, suspended_reason = '';

-- name: DeleteLocalRoleGrant :exec
DELETE FROM local_role_grants WHERE user_id = $1 AND role = $2 AND org_id IS NOT DISTINCT FROM $3;

-- name: DeleteLocalRoleGrantsForOrg :exec
-- Removal from an org is not a suspension: the person may have left, so their
-- grants go with their membership.
DELETE FROM local_role_grants WHERE user_id = $1 AND org_id = $2;

-- name: SuspendLocalRoleGrants :many
-- Suspend an org's privileged grants for one user, returning what was suspended
-- so the caller can drop the matching Casbin policies and notify.
UPDATE local_role_grants
SET suspended_at = now(), suspended_reason = $3
WHERE user_id = $1 AND org_id = $2 AND suspended_at IS NULL
RETURNING *;

-- name: ListLocalRoleGrantsForUser :many
SELECT * FROM local_role_grants WHERE user_id = $1 ORDER BY org_id NULLS FIRST, role;

-- name: ListActiveLocalRoleGrants :many
-- Every active grant on the instance: the cross-org answer to "what can this
-- person do everywhere", which no per-org view can give.
SELECT g.*, u.email, u.display_name
FROM local_role_grants g
JOIN users u ON u.id = g.user_id
WHERE g.suspended_at IS NULL
ORDER BY u.email, g.org_id NULLS FIRST, g.role;

-- name: ListInstanceMembers :many
-- Every membership on the instance, across every org and forge.
--
-- One row per (user, org); the caller groups by user, because identity is the
-- person rather than the forge account and an operator should not have to
-- reconcile the same human across providers by eye.
SELECT u.id AS user_id, u.email, u.display_name,
       o.id AS org_id, o.slug, o.provider, m.role
FROM org_members m
JOIN users u ON u.id = m.user_id
JOIN organizations o ON o.id = m.org_id
ORDER BY u.email, o.provider, o.slug;

-- name: ListMappedCVEsForDivergenceCheck :many
-- CVEs we authored coordinates for, with the packages we chose. Upstream may
-- publish its own coordinates for the same CVE later; when it does, ours either
-- agree, are superseded, or diverge (ADR-028 §10) — and only a comparison can
-- tell which.
--
-- Ordered oldest-decision-first so a run that is cut short still makes progress
-- on the mappings that have had the longest to drift.
SELECT DISTINCT ON (t.cve_id)
    t.cve_id,
    m.id AS mapping_id,
    m.packages,
    t.decided_at
FROM cve_triage_items t
JOIN cve_subscriptions s ON s.id = t.subscription_id
JOIN product_package_mappings m ON m.subscription_id = s.id AND m.revoked_at IS NULL
JOIN cve_records r ON r.cve_id = t.cve_id
WHERE t.state = 'mapped' AND r.state <> 'REJECTED'
ORDER BY t.cve_id, t.decided_at ASC
LIMIT $1;
