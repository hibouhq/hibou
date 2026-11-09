-- Incidents (ADR-053).

-- name: UpsertRepoIncidentConfig :exec
INSERT INTO repo_incident_config (repo_id, config, loaded_at)
VALUES ($1, $2, NOW())
ON CONFLICT (repo_id) DO UPDATE SET config = EXCLUDED.config, loaded_at = NOW();

-- name: GetRepoIncidentConfig :one
SELECT * FROM repo_incident_config WHERE repo_id = $1;

-- name: GetIncidentSettings :one
SELECT * FROM incident_settings WHERE org_id = $1;

-- name: UpsertIncidentSettings :one
INSERT INTO incident_settings (
    org_id, owner_id, owner_team_id, default_rules, locked_rules, internal_targets, national_regimes,
    require_vex_approval, require_notice_approval, require_acknowledgement, four_eyes, due_soon_lead_minutes, updated_by, updated_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, NOW())
ON CONFLICT (org_id) DO UPDATE SET
    owner_id = EXCLUDED.owner_id,
    owner_team_id = EXCLUDED.owner_team_id,
    default_rules = EXCLUDED.default_rules,
    locked_rules = EXCLUDED.locked_rules,
    internal_targets = EXCLUDED.internal_targets,
    national_regimes = EXCLUDED.national_regimes,
    require_vex_approval = EXCLUDED.require_vex_approval,
    require_notice_approval = EXCLUDED.require_notice_approval,
    require_acknowledgement = EXCLUDED.require_acknowledgement,
    four_eyes = EXCLUDED.four_eyes,
    due_soon_lead_minutes = EXCLUDED.due_soon_lead_minutes,
    updated_by = EXCLUDED.updated_by,
    updated_at = NOW()
RETURNING *;

-- name: NextIncidentNumber :one
-- Serialised per organisation by the advisory lock the caller takes.
SELECT COALESCE(MAX(number), 0)::int + 1 FROM incidents WHERE org_id = $1;

-- name: CreateIncident :one
INSERT INTO incidents (
    org_id, number, repo_id, kind, regimes, subject_type, subject_id, title, state, priority,
    signal_source, trigger_rule, signal_at, owner_id, owner_team_id, due_at, created_by, target_seconds
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
RETURNING *;

-- name: GetIncident :one
SELECT * FROM incidents WHERE id = $1;

-- name: GetIncidentByNumber :one
SELECT * FROM incidents WHERE org_id = $1 AND number = $2;

-- name: FindIncidentForSubject :one
-- The most recent incident on a subject, whatever its state: a rule never
-- opens a second one beside a closed or withdrawn incident; scope changes
-- reopen it instead.
SELECT * FROM incidents
WHERE org_id = sqlc.arg(org_id)
  AND repo_id IS NOT DISTINCT FROM sqlc.narg(repo_id)
  AND kind = sqlc.arg(kind)
  AND subject_type = sqlc.arg(subject_type)
  AND subject_id = sqlc.arg(subject_id)
  AND merged_into IS NULL
ORDER BY created_at DESC
LIMIT 1;

-- name: ListIncidentsByOrg :many
SELECT i.*, r.slug AS repo_slug, r.name AS repo_name
FROM incidents i
LEFT JOIN repositories r ON r.id = i.repo_id
WHERE i.org_id = sqlc.arg(org_id)
  AND (sqlc.narg(state_filter)::text IS NULL
       OR (sqlc.narg(state_filter)::text = 'open' AND i.state NOT IN ('closed', 'withdrawn'))
       OR (sqlc.narg(state_filter)::text = 'closed' AND i.state IN ('closed', 'withdrawn'))
       OR i.state::text = sqlc.narg(state_filter)::text)
  AND (sqlc.narg(kind_filter)::text IS NULL OR i.kind = sqlc.narg(kind_filter)::text)
  AND (sqlc.narg(repo_filter)::uuid IS NULL OR i.repo_id = sqlc.narg(repo_filter)::uuid)
  AND (sqlc.narg(priority_filter)::text IS NULL OR i.priority = sqlc.narg(priority_filter)::text)
  AND i.merged_into IS NULL
ORDER BY (i.state IN ('closed', 'withdrawn')), i.due_at ASC NULLS LAST, i.priority ASC, i.created_at DESC
LIMIT sqlc.arg(row_limit) OFFSET sqlc.arg(row_offset);

-- name: CountIncidentsByOrg :one
SELECT COUNT(*)::bigint FROM incidents i
WHERE i.org_id = sqlc.arg(org_id)
  AND (sqlc.narg(state_filter)::text IS NULL
       OR (sqlc.narg(state_filter)::text = 'open' AND i.state NOT IN ('closed', 'withdrawn'))
       OR (sqlc.narg(state_filter)::text = 'closed' AND i.state IN ('closed', 'withdrawn'))
       OR i.state::text = sqlc.narg(state_filter)::text)
  AND (sqlc.narg(kind_filter)::text IS NULL OR i.kind = sqlc.narg(kind_filter)::text)
  AND (sqlc.narg(repo_filter)::uuid IS NULL OR i.repo_id = sqlc.narg(repo_filter)::uuid)
  AND (sqlc.narg(priority_filter)::text IS NULL OR i.priority = sqlc.narg(priority_filter)::text)
  AND i.merged_into IS NULL;

-- name: ListOpenIncidentsForOrgs :many
SELECT i.*, r.slug AS repo_slug, r.name AS repo_name, o.slug AS org_slug, o.provider AS org_provider, o.name AS org_name
FROM incidents i
JOIN organizations o ON o.id = i.org_id
LEFT JOIN repositories r ON r.id = i.repo_id
WHERE i.org_id = ANY(sqlc.arg(org_ids)::uuid[])
  AND i.state NOT IN ('closed', 'withdrawn')
  AND i.merged_into IS NULL
ORDER BY i.due_at ASC NULLS LAST, i.priority ASC, i.created_at DESC
LIMIT sqlc.arg(row_limit);

-- name: ListOpenIncidentsBySubject :many
SELECT * FROM incidents
WHERE org_id = sqlc.arg(org_id)
  AND subject_type = sqlc.arg(subject_type)
  AND subject_id = ANY(sqlc.arg(subject_ids)::text[])
  AND state NOT IN ('closed', 'withdrawn')
  AND merged_into IS NULL;

-- name: ListIncidentsByRepo :many
SELECT * FROM incidents WHERE repo_id = $1 AND merged_into IS NULL ORDER BY created_at DESC LIMIT $2;

-- name: ListOpenIncidentIDs :many
SELECT id FROM incidents WHERE state NOT IN ('closed', 'withdrawn') AND merged_into IS NULL ORDER BY created_at;

-- name: ListOpenIncidentIDsForRepo :many
SELECT id FROM incidents WHERE repo_id = $1 AND state NOT IN ('closed', 'withdrawn') AND merged_into IS NULL;

-- name: ListReopenableIncidentIDsForRepo :many
-- Closed exploited-vulnerability incidents of a repository: a new deployment
-- or release can add scope to them (ADR-053 §3).
SELECT id FROM incidents WHERE repo_id = $1 AND state = 'closed' AND kind = 'exploited_vulnerability' AND merged_into IS NULL;

-- name: UpdateIncidentState :one
UPDATE incidents SET state = $2, closed_at = $3, updated_at = NOW() WHERE id = $1 RETURNING *;

-- name: UpdateIncidentDecision :one
UPDATE incidents SET
    state = sqlc.arg(state),
    aware_at = sqlc.narg(aware_at),
    decision_reason = sqlc.arg(decision_reason),
    decision_step = sqlc.narg(decision_step),
    decided_by = sqlc.narg(decided_by),
    decided_at = NOW(),
    decided_state = sqlc.arg(state),
    proposed_decision = 'null'::jsonb,
    regimes = sqlc.arg(regimes),
    updated_at = NOW()
WHERE id = sqlc.arg(id)
RETURNING *;

-- name: SetIncidentProposedDecision :one
UPDATE incidents SET proposed_decision = $2, updated_at = NOW() WHERE id = $1 RETURNING *;

-- name: UpdateIncidentFields :one
UPDATE incidents SET
    title = sqlc.arg(title),
    priority = sqlc.arg(priority),
    owner_id = sqlc.narg(owner_id),
    owner_team_id = sqlc.narg(owner_team_id),
    regimes = sqlc.arg(regimes),
    external_ref = sqlc.arg(external_ref),
    updated_at = NOW()
WHERE id = sqlc.arg(id)
RETURNING *;

-- name: SetIncidentFixAvailable :one
UPDATE incidents SET fix_available_at = $2, updated_at = NOW() WHERE id = $1 RETURNING *;

-- name: SetIncidentDueAt :exec
UPDATE incidents SET due_at = $2 WHERE id = $1;

-- name: MergeIncidentInto :exec
UPDATE incidents SET merged_into = $2, state = 'withdrawn', closed_at = NOW(), proposed_merge = 'null'::jsonb, updated_at = NOW() WHERE id = $1;

-- name: SetIncidentProposedMerge :one
UPDATE incidents SET proposed_merge = $2, updated_at = NOW() WHERE id = $1 RETURNING *;

-- name: ListMergeCandidates :many
-- Incidents this one could merge into: same organisation, kind and
-- repository, neither withdrawn nor merged themselves.
SELECT i.* FROM incidents i
WHERE i.org_id = sqlc.arg(org_id)
  AND i.kind = sqlc.arg(kind)
  AND i.repo_id IS NOT DISTINCT FROM sqlc.narg(repo_id)::uuid
  AND i.id <> sqlc.arg(incident_id)
  AND i.merged_into IS NULL
  AND i.state <> 'withdrawn'
ORDER BY i.number DESC
LIMIT 200;

-- name: ListAdvisoryIdentifiers :many
-- Every name of an advisory: its canonical id and its aliases, upper-cased.
SELECT upper(a.canonical_id)::text AS identifier FROM advisories a WHERE a.id = sqlc.arg(advisory_id)
UNION
SELECT upper(x.alias)::text FROM advisory_aliases x WHERE x.advisory_id = sqlc.arg(advisory_id);

-- name: ListProposedMergesForOrgs :many
SELECT i.id, i.org_id, i.number, i.title, i.proposed_merge, o.slug AS org_slug, o.provider AS org_provider
FROM incidents i
JOIN organizations o ON o.id = i.org_id
WHERE i.org_id = ANY(sqlc.arg(org_ids)::uuid[]) AND i.proposed_merge <> 'null'::jsonb AND i.merged_into IS NULL AND i.state <> 'withdrawn'
ORDER BY i.updated_at DESC;

-- name: UpsertIncidentDeadline :exec
-- The due-soon / overdue marker survives a reconcile; only a new due time
-- earns a new warning.
INSERT INTO incident_deadlines (incident_id, regime, step, due_at)
VALUES ($1, $2, $3, $4)
ON CONFLICT (incident_id, regime, step) DO UPDATE SET
    due_at = EXCLUDED.due_at,
    notified = CASE WHEN incident_deadlines.due_at = EXCLUDED.due_at THEN incident_deadlines.notified ELSE '' END
WHERE incident_deadlines.met_at IS NULL;

-- name: DeleteIncidentDeadline :exec
-- An unmet clock that no longer derives (a regime dropped, a decision undone).
DELETE FROM incident_deadlines WHERE incident_id = $1 AND regime = $2 AND step = $3 AND met_at IS NULL;

-- name: MeetIncidentDeadline :execrows
UPDATE incident_deadlines SET met_at = $4, reference = $5
WHERE incident_id = $1 AND regime = $2 AND step = $3 AND met_at IS NULL;

-- name: ListIncidentDeadlines :many
SELECT * FROM incident_deadlines WHERE incident_id = $1 ORDER BY due_at;

-- name: ListDueIncidentDeadlines :many
-- Unmet deadlines due before the horizon, not yet notified at this level.
SELECT d.*, i.org_id, i.number, i.title, i.owner_id, i.repo_id
FROM incident_deadlines d
JOIN incidents i ON i.id = d.incident_id
WHERE d.met_at IS NULL
  AND i.state NOT IN ('closed', 'withdrawn')
  AND d.due_at <= sqlc.arg(horizon)
  AND d.notified <> 'overdue'
ORDER BY d.due_at;

-- name: MarkIncidentDeadlineNotified :exec
UPDATE incident_deadlines SET notified = $4 WHERE incident_id = $1 AND regime = $2 AND step = $3;

-- name: UpsertIncidentScopeRow :exec
-- Derived rows refresh their status and label; a person's decision on a row
-- (manual) is kept until the derivation contradicts it with a new match.
INSERT INTO incident_scope (incident_id, subject_type, subject_id, label, status, reason, component_purl, vex_statement_id, reachability, manual, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW())
ON CONFLICT (incident_id, subject_type, subject_id) DO UPDATE SET
    label = EXCLUDED.label,
    status = CASE WHEN incident_scope.manual AND NOT EXCLUDED.manual THEN incident_scope.status ELSE EXCLUDED.status END,
    reason = CASE WHEN incident_scope.manual AND NOT EXCLUDED.manual THEN incident_scope.reason ELSE EXCLUDED.reason END,
    component_purl = EXCLUDED.component_purl,
    vex_statement_id = EXCLUDED.vex_statement_id,
    reachability = EXCLUDED.reachability,
    manual = incident_scope.manual OR EXCLUDED.manual,
    updated_at = NOW();

-- name: SetIncidentScopeDecision :exec
UPDATE incident_scope SET status = $4, reason = $5, manual = true, decided_by = $6, decided_at = NOW(), updated_at = NOW()
WHERE incident_id = $1 AND subject_type = $2 AND subject_id = $3;

-- name: DeleteIncidentScopeRow :exec
DELETE FROM incident_scope WHERE incident_id = $1 AND subject_type = $2 AND subject_id = $3;

-- name: ListIncidentScope :many
SELECT * FROM incident_scope WHERE incident_id = $1 ORDER BY subject_type, label, subject_id;

-- name: UpsertIncidentAction :one
-- Derivation keeps an action's progress: only due date, label and the
-- obsolete flag move; state, evidence and people stay.
INSERT INTO incident_actions (incident_id, kind, subject_type, subject_id, label, automatic, optional, due_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT (incident_id, kind, subject_type, subject_id) DO UPDATE SET
    label = EXCLUDED.label,
    automatic = EXCLUDED.automatic,
    optional = EXCLUDED.optional,
    due_at = EXCLUDED.due_at,
    obsolete = false
RETURNING *;

-- name: MarkIncidentActionsObsolete :exec
UPDATE incident_actions SET obsolete = true
WHERE incident_id = $1 AND state = 'pending' AND NOT (id = ANY(sqlc.arg(keep_ids)::uuid[]));

-- name: CompleteIncidentAction :one
UPDATE incident_actions SET state = 'done', done_at = NOW(), done_by = $3, evidence = $4
WHERE id = $1 AND incident_id = $2 AND state = 'pending'
RETURNING *;

-- name: WaiveIncidentAction :one
UPDATE incident_actions SET state = 'waived', done_at = NOW(), waived_by = $3, waived_reason = $4
WHERE id = $1 AND incident_id = $2 AND state = 'pending'
RETURNING *;

-- name: ReopenIncidentAction :one
UPDATE incident_actions SET state = 'pending', done_at = NULL, done_by = NULL, evidence = '{}'::jsonb, waived_by = NULL, waived_reason = NULL
WHERE id = $1 AND incident_id = $2
RETURNING *;

-- name: AssignIncidentAction :one
UPDATE incident_actions SET assignee_id = $3 WHERE id = $1 AND incident_id = $2 RETURNING *;

-- name: GetIncidentAction :one
SELECT * FROM incident_actions WHERE id = $1;

-- name: ListIncidentActions :many
SELECT * FROM incident_actions WHERE incident_id = $1
ORDER BY obsolete,
  CASE
    WHEN kind LIKE '%early_warning' THEN 0
    WHEN kind LIKE '%notification' THEN 1
    WHEN kind = 'vex' THEN 2
    WHEN kind = 'client_notice' THEN 3
    WHEN kind = 'upstream_notice' THEN 5
    WHEN kind LIKE '%final_report' THEN 6
    ELSE 4
  END,
  due_at NULLS LAST, kind, label;

-- name: ListPendingActionsForUser :many
SELECT a.*, i.number, i.title, i.org_id, i.priority, o.slug AS org_slug, o.provider AS org_provider
FROM incident_actions a
JOIN incidents i ON i.id = a.incident_id
JOIN organizations o ON o.id = i.org_id
WHERE a.state = 'pending' AND NOT a.obsolete
  AND i.state NOT IN ('closed', 'withdrawn')
  AND i.org_id = ANY(sqlc.arg(org_ids)::uuid[])
  AND (a.assignee_id = sqlc.arg(user_id)
       OR (a.assignee_id IS NULL AND (i.owner_id = sqlc.arg(user_id)
           OR i.owner_team_id IN (SELECT team_id FROM team_members WHERE user_id = sqlc.arg(user_id)))))
ORDER BY a.due_at ASC NULLS LAST, i.priority ASC
LIMIT sqlc.arg(row_limit);

-- name: CreateIncidentEvent :one
INSERT INTO incident_events (incident_id, actor_id, actor_type, actor_display, kind, detail)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING *;

-- name: ListIncidentEvents :many
SELECT * FROM incident_events WHERE incident_id = $1 ORDER BY at, id;

-- name: CountIncidentEvents :one
SELECT COUNT(*)::int FROM incident_events WHERE incident_id = $1;

-- name: MoveIncidentChildren :exec
-- Merging (ADR-053 §3): the survivor absorbs the other incident's history.
WITH moved_events AS (
    UPDATE incident_events SET incident_id = sqlc.arg(survivor) WHERE incident_id = sqlc.arg(merged)
), moved_deliveries AS (
    UPDATE incident_deliveries SET incident_id = sqlc.arg(survivor) WHERE incident_id = sqlc.arg(merged)
)
UPDATE incident_actions a SET incident_id = sqlc.arg(survivor)
WHERE a.incident_id = sqlc.arg(merged)
  AND a.state <> 'pending'
  AND NOT EXISTS (
      SELECT 1 FROM incident_actions s
      WHERE s.incident_id = sqlc.arg(survivor) AND s.kind = a.kind AND s.subject_type = a.subject_type AND s.subject_id = a.subject_id
  );

-- name: PutIncidentDocument :one
INSERT INTO incident_documents (sha256, org_id, kind, content_type, size_bytes, object_key, content, renderer, inputs)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
ON CONFLICT (sha256) DO UPDATE SET sha256 = EXCLUDED.sha256
RETURNING *;

-- name: GetIncidentDocument :one
SELECT * FROM incident_documents WHERE sha256 = $1 AND org_id = $2;

-- name: CreateIncidentDelivery :one
INSERT INTO incident_deliveries (incident_id, client_id, action_id, channel, recipient, documents, approved_by, approved_at, status, created_by)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
RETURNING *;

-- name: GetIncidentDelivery :one
SELECT * FROM incident_deliveries WHERE id = $1;

-- name: ListIncidentDeliveries :many
SELECT d.*, c.name AS client_name, c.slug AS client_slug
FROM incident_deliveries d
LEFT JOIN clients c ON c.id = d.client_id
WHERE d.incident_id = $1
ORDER BY d.created_at;

-- name: ListDeliveriesByClient :many
SELECT d.*, i.number AS incident_number, i.title AS incident_title, i.kind AS incident_kind, i.state AS incident_state
FROM incident_deliveries d
JOIN incidents i ON i.id = d.incident_id
WHERE d.client_id = $1
ORDER BY d.created_at DESC
LIMIT $2;

-- name: ApproveIncidentDelivery :one
UPDATE incident_deliveries SET approved_by = $2, approved_at = NOW()
WHERE id = $1 AND status = 'pending_approval'
RETURNING *;

-- name: MarkIncidentDeliverySent :one
UPDATE incident_deliveries SET status = $2, error = $3, provider_ref = $4, sent_at = $5, audit_log_id = $6
WHERE id = $1
RETURNING *;

-- name: AcknowledgeIncidentDelivery :one
UPDATE incident_deliveries SET status = 'acknowledged', acknowledged_at = NOW(), ack_evidence = $2
WHERE id = $1 AND status IN ('sent', 'acknowledged') AND acknowledged_at IS NULL
RETURNING *;

-- name: UpsertIncidentTrackerLink :exec
INSERT INTO incident_tracker_links (incident_id, integration_id, external_key, external_url, synced_events, last_synced_at, last_error)
VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (incident_id, integration_id) DO UPDATE SET
    external_key = CASE WHEN EXCLUDED.external_key <> '' THEN EXCLUDED.external_key ELSE incident_tracker_links.external_key END,
    external_url = CASE WHEN EXCLUDED.external_url <> '' THEN EXCLUDED.external_url ELSE incident_tracker_links.external_url END,
    synced_events = EXCLUDED.synced_events,
    last_synced_at = EXCLUDED.last_synced_at,
    last_error = EXCLUDED.last_error;

-- name: ListIncidentTrackerLinks :many
SELECT l.*, g.name AS integration_name, g.integration_type
FROM incident_tracker_links l
JOIN integrations g ON g.id = l.integration_id
WHERE l.incident_id = $1;

-- name: FindIncidentByTrackerKey :one
SELECT incident_id FROM incident_tracker_links WHERE integration_id = $1 AND external_key = $2;

-- name: ListLaggingTrackerLinks :many
SELECT l.*, i.org_id FROM incident_tracker_links l
JOIN incidents i ON i.id = l.incident_id
WHERE l.last_error <> '' OR l.synced_events < (SELECT COUNT(*) FROM incident_events e WHERE e.incident_id = l.incident_id)
LIMIT $1;

-- name: CreateClientPortalToken :one
INSERT INTO client_portal_tokens (org_id, client_id, name, token_hash, created_by)
VALUES ($1, $2, $3, $4, $5)
RETURNING *;

-- name: GetClientPortalTokenByHash :one
SELECT * FROM client_portal_tokens WHERE token_hash = $1 AND revoked_at IS NULL;

-- name: TouchClientPortalToken :exec
UPDATE client_portal_tokens SET last_used_at = NOW() WHERE id = $1;

-- name: ListClientPortalTokens :many
SELECT * FROM client_portal_tokens WHERE client_id = $1 ORDER BY created_at DESC;

-- name: RevokeClientPortalToken :execrows
UPDATE client_portal_tokens SET revoked_at = NOW() WHERE id = $1 AND client_id = $2 AND revoked_at IS NULL;

-- name: ListPortalDeliveriesForClient :many
SELECT d.*, i.number AS incident_number, i.title AS incident_title
FROM incident_deliveries d
JOIN incidents i ON i.id = d.incident_id
WHERE d.client_id = $1 AND d.channel = 'portal' AND d.status IN ('sent', 'acknowledged')
ORDER BY d.sent_at DESC;

-- name: UpdateClientDelivery :one
UPDATE clients SET security_contacts = $2, delivery_config = $3, updated_at = NOW() WHERE id = $1 RETURNING *;

-- name: GetClientRow :one
SELECT * FROM clients WHERE id = $1;

-- name: ListReleasesWithClientsByRepo :many
-- The exposure join behind an incident's scope: every release of a
-- repository with its pinned snapshot and the clients actively on it.
SELECT r.id, r.version, r.snapshot_id, r.created_at, r.published_at,
       COALESCE(array_agg(DISTINCT c.id) FILTER (WHERE c.id IS NOT NULL), '{}')::uuid[] AS client_ids
FROM releases r
LEFT JOIN deployments d ON d.release_id = r.id AND d.status = 'active'
LEFT JOIN clients c ON c.id = d.client_id
WHERE r.repo_id = $1
GROUP BY r.id
ORDER BY r.created_at;

-- name: ListAdvisoryMatchesInSnapshots :many
-- Which of these snapshots carry a finding on this advisory, and through
-- which component and reachability verdict.
SELECT DISTINCT v.snapshot_id, COALESCE(v.component_purl, '')::text AS component_purl, COALESCE(v.reachability::text, '')::text AS reachability
FROM vulnerabilities v
WHERE v.snapshot_id = ANY(sqlc.arg(snapshot_ids)::uuid[])
  AND v.advisory_id = sqlc.arg(advisory_id);

-- name: ListFingerprintPresenceInSnapshots :many
SELECT DISTINCT v.snapshot_id
FROM vulnerabilities v
WHERE v.snapshot_id = ANY(sqlc.arg(snapshot_ids)::uuid[])
  AND v.fingerprint = sqlc.arg(fingerprint);

-- name: ListLatestSnapshotsForRepoRefs :many
-- The latest completed snapshot of every ref of a repository, with the ref
-- it belongs to, for incident rules (`all`, `default`, branch globs).
SELECT DISTINCT ON (s.ref_id) s.id AS snapshot_id, f.name AS ref_name, f.ref_type::text AS ref_type
FROM snapshots s
JOIN refs f ON f.id = s.ref_id
WHERE s.repo_id = $1
  AND s.status NOT IN ('pending', 'processing', 'failed', 'purged')
ORDER BY s.ref_id, s.created_at DESC, s.id DESC;

-- name: ListClientsByIDs :many
SELECT * FROM clients WHERE id = ANY(sqlc.arg(ids)::uuid[]) ORDER BY name;

-- name: ListUserOrgIDs :many
SELECT org_id FROM org_members WHERE user_id = $1;

-- name: CreateSecretAttestation :one
INSERT INTO secret_attestations (repo_id, fingerprint, revoked, revoked_where, revoked_by, reference, rotation, rotation_note, exposure, exposure_note, owner_external, note, attested_by)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
RETURNING *;

-- name: GetLatestSecretAttestation :one
SELECT * FROM secret_attestations WHERE repo_id = $1 AND fingerprint = $2 ORDER BY attested_at DESC, id DESC LIMIT 1;

-- name: ListSecretAttestations :many
SELECT * FROM secret_attestations WHERE repo_id = $1 AND fingerprint = $2 ORDER BY attested_at DESC, id DESC;

-- name: GetTeamBySlugInOrg :one
SELECT * FROM teams WHERE org_id = $1 AND slug = $2;

-- name: GetOrgMemberIDByLogin :one
-- An owner named in .hibou.yaml must be a member of the organisation.
SELECT u.id FROM users u
JOIN org_members m ON m.user_id = u.id AND m.org_id = $1
WHERE lower(u.forge_login) = lower($2) OR lower(u.email) = lower($2)
LIMIT 1;

-- name: ListRepositoryIDsForIncidentSweep :many
-- Repositories a periodic sweep looks at: those with releases, and those
-- analysed recently. A repository nobody scanned in months has no new facts.
SELECT repo_id FROM releases
UNION
SELECT repo_id FROM snapshots WHERE created_at > NOW() - INTERVAL '90 days';

-- name: ListAliasSiblingIncidents :many
-- Open exploited-vulnerability incidents of the same repository whose
-- advisory shares an identifier with this one: two names for one
-- vulnerability, merged into the older incident (ADR-053 §3).
SELECT i.* FROM incidents i
WHERE i.repo_id = sqlc.arg(repo_id)
  AND i.id <> sqlc.arg(incident_id)
  AND i.kind = 'exploited_vulnerability'
  AND i.subject_type = 'advisory'
  AND i.subject_id ~ '^[0-9a-f-]{36}$'
  AND i.state NOT IN ('closed', 'withdrawn')
  AND i.merged_into IS NULL
  AND (
      SELECT upper(a.canonical_id) FROM advisories a WHERE a.id = i.subject_id::uuid
  ) IN (
      SELECT upper(a.canonical_id) FROM advisories a WHERE a.id = sqlc.arg(advisory_id)::uuid
      UNION SELECT upper(x.alias) FROM advisory_aliases x WHERE x.advisory_id = sqlc.arg(advisory_id)::uuid
  )
  OR (
      i.repo_id = sqlc.arg(repo_id) AND i.id <> sqlc.arg(incident_id) AND i.kind = 'exploited_vulnerability'
      AND i.subject_type = 'advisory' AND i.subject_id ~ '^[0-9a-f-]{36}$'
      AND i.state NOT IN ('closed', 'withdrawn') AND i.merged_into IS NULL
      AND EXISTS (
          SELECT 1 FROM advisory_aliases x
          WHERE x.advisory_id = i.subject_id::uuid
            AND upper(x.alias) IN (
                SELECT upper(a.canonical_id) FROM advisories a WHERE a.id = sqlc.arg(advisory_id)::uuid
                UNION SELECT upper(y.alias) FROM advisory_aliases y WHERE y.advisory_id = sqlc.arg(advisory_id)::uuid
            )
      )
  )
ORDER BY i.number;

-- name: ProposeIncidentActionWaiver :execrows
-- Four-eyes waiver (ADR-053 §4): the proposal rides on the pending action's
-- evidence until someone else approves it.
UPDATE incident_actions SET evidence = $3 WHERE id = $1 AND incident_id = $2 AND state = 'pending';

-- name: CountClientDeliveriesForIncident :one
SELECT COUNT(*)::int FROM incident_deliveries
WHERE incident_id = $1 AND client_id = $2 AND status IN ('pending_approval', 'sent', 'acknowledged');

-- name: ListClientDeliveryTimes :many
SELECT created_at FROM incident_deliveries
WHERE incident_id = $1 AND client_id = $2 AND status IN ('sent', 'acknowledged')
ORDER BY created_at;

-- name: GetOrgEmailIntegration :one
SELECT * FROM integrations WHERE org_id = $1 AND integration_type = 'email' AND enabled ORDER BY created_at LIMIT 1;

-- name: ListOrgTrackerIntegrations :many
SELECT * FROM integrations WHERE org_id = $1 AND integration_type IN ('jira', 'github_issues', 'gitlab_issues', 'tracker_webhook') AND enabled ORDER BY created_at;

-- Home (ADR-053 §9).

-- name: ListProposedDecisionsForOrgs :many
SELECT i.id, i.org_id, i.number, i.title, i.kind, i.priority, i.proposed_decision, o.slug AS org_slug, o.provider AS org_provider
FROM incidents i JOIN organizations o ON o.id = i.org_id
WHERE i.org_id = ANY(sqlc.arg(org_ids)::uuid[]) AND i.proposed_decision <> 'null'::jsonb AND i.state NOT IN ('closed', 'withdrawn')
ORDER BY i.updated_at DESC LIMIT 50;

-- name: ListDeliveriesAwaitingApprovalForOrgs :many
SELECT d.id, d.incident_id, d.created_by, d.created_at, d.recipient, d.channel, i.org_id, i.number, i.title, c.name AS client_name, o.slug AS org_slug, o.provider AS org_provider
FROM incident_deliveries d
JOIN incidents i ON i.id = d.incident_id
JOIN organizations o ON o.id = i.org_id
LEFT JOIN clients c ON c.id = d.client_id
WHERE i.org_id = ANY(sqlc.arg(org_ids)::uuid[]) AND d.status = 'pending_approval'
ORDER BY d.created_at LIMIT 50;

-- name: ListWaiversAwaitingApprovalForOrgs :many
SELECT a.id, a.incident_id, a.label, a.kind, a.evidence, i.org_id, i.number, i.title, o.slug AS org_slug, o.provider AS org_provider
FROM incident_actions a
JOIN incidents i ON i.id = a.incident_id
JOIN organizations o ON o.id = i.org_id
WHERE i.org_id = ANY(sqlc.arg(org_ids)::uuid[]) AND a.state = 'pending' AND a.evidence ? 'waiver_proposed_by'
  AND i.state NOT IN ('closed', 'withdrawn')
ORDER BY a.created_at LIMIT 50;

-- name: ListNoisyIncidentRules :many
SELECT i.org_id, i.repo_id, r.slug AS repo_slug, i.trigger_rule, COUNT(*)::int AS opened
FROM incidents i LEFT JOIN repositories r ON r.id = i.repo_id
WHERE i.org_id = ANY(sqlc.arg(org_ids)::uuid[]) AND i.trigger_rule IS NOT NULL AND i.created_at > NOW() - INTERVAL '7 days'
GROUP BY i.org_id, i.repo_id, r.slug, i.trigger_rule
HAVING COUNT(*) >= sqlc.arg(threshold)::int
ORDER BY opened DESC LIMIT 20;

-- name: ListExposedClientsForOrgs :many
-- Clients on releases an open incident counts as affected, pending or
-- unknown: who is exposed right now.
SELECT DISTINCT c.id AS client_id, c.name AS client_name, c.slug AS client_slug, i.org_id, i.number, i.title, s.label AS version, s.status,
       o.slug AS org_slug, o.provider AS org_provider
FROM incident_scope s
JOIN incidents i ON i.id = s.incident_id
JOIN organizations o ON o.id = i.org_id
JOIN deployments d ON d.release_id = s.subject_id::uuid AND d.status = 'active'
JOIN clients c ON c.id = d.client_id
WHERE i.org_id = ANY(sqlc.arg(org_ids)::uuid[])
  AND i.state NOT IN ('closed', 'withdrawn')
  AND s.subject_type = 'release'
  AND s.status IN ('affected', 'pending', 'unknown', 'under_investigation')
ORDER BY i.number, c.name LIMIT 100;

-- name: ListUnknownReleasesForOrgs :many
SELECT s.subject_id AS release_id, s.label AS version, i.org_id, i.number, i.title, o.slug AS org_slug, o.provider AS org_provider
FROM incident_scope s
JOIN incidents i ON i.id = s.incident_id
JOIN organizations o ON o.id = i.org_id
WHERE i.org_id = ANY(sqlc.arg(org_ids)::uuid[]) AND i.state NOT IN ('closed', 'withdrawn') AND s.status = 'unknown'
ORDER BY i.number LIMIT 50;

-- name: CountNewFindingsByTypeForOrgs :many
SELECT f.type::text AS type, COUNT(*)::int AS found
FROM findings f
WHERE f.org_id = ANY(sqlc.arg(org_ids)::uuid[]) AND f.type IN ('secret', 'malware') AND f.first_seen_at > sqlc.arg(since)
GROUP BY f.type;

-- name: CountFailedGatesForOrgs :one
SELECT COUNT(*)::int FROM pr_checks p
JOIN repositories r ON r.id = p.repo_id
WHERE r.org_id = ANY(sqlc.arg(org_ids)::uuid[]) AND NOT p.passed AND p.state <> 'pending' AND p.created_at > sqlc.arg(since);

-- name: CountCatalogueSignalsForOrgs :one
SELECT COUNT(*)::int FROM incidents i
WHERE i.org_id = ANY(sqlc.arg(org_ids)::uuid[]) AND i.signal_source IN ('kev', 'euvd') AND i.created_at > sqlc.arg(since);
