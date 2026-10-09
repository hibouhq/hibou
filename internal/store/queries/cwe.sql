-- ADR-037 CWE claims. Titles, hierarchy and named sets come from the
-- embedded catalog (internal/cwe), never from the database.
--
-- Every "sync" below is one statement that deletes only the pairs that
-- disappeared and inserts with ON CONFLICT DO NOTHING. Re-ingesting an
-- unchanged scan — the common case, on every upload — therefore writes no
-- tuples at all: no dead rows, no vacuum pressure, no WAL.

-- name: SyncScanRuleCWEs :exec
-- Makes each rule in rule_ids carry exactly its (pair_rule_ids[i],
-- pair_cwe_ids[i]) CWEs: the scanner's current definition is authoritative.
-- A rule listed in rule_ids with no pair is cleared.
WITH wanted AS (
    SELECT unnest(sqlc.arg(pair_rule_ids)::uuid[]) AS scan_rule_id,
           unnest(sqlc.arg(pair_cwe_ids)::int[]) AS cwe_id
), removed AS (
    DELETE FROM scan_rule_cwes s
    WHERE s.scan_rule_id = ANY(sqlc.arg(rule_ids)::uuid[])
      AND NOT EXISTS (SELECT 1 FROM wanted w WHERE w.scan_rule_id = s.scan_rule_id AND w.cwe_id = s.cwe_id)
)
INSERT INTO scan_rule_cwes (scan_rule_id, cwe_id)
SELECT wanted.scan_rule_id, wanted.cwe_id FROM wanted
ON CONFLICT DO NOTHING;

-- name: AddAdvisoryCWEs :exec
-- Union across providers: one provider omitting a CWE never erases another's.
INSERT INTO advisory_cwes (advisory_id, cwe_id)
SELECT sqlc.arg(advisory_id)::uuid, unnest(sqlc.arg(cwe_ids)::int[])
ON CONFLICT DO NOTHING;

-- name: SyncCVERecordCWEs :exec
WITH removed AS (
    DELETE FROM cve_record_cwes
    WHERE cve_record_cwes.cve_id = sqlc.arg(cve_id) AND cve_record_cwes.cwe_id <> ALL(sqlc.arg(cwe_ids)::int[])
)
INSERT INTO cve_record_cwes (cve_id, cwe_id)
SELECT sqlc.arg(cve_id)::text, unnest(sqlc.arg(cwe_ids)::int[])
ON CONFLICT DO NOTHING;

-- name: ListCVERecordCWEs :many
SELECT cwe_id FROM cve_record_cwes WHERE cve_id = $1 ORDER BY cwe_id;

-- name: ListAdvisoryCWEs :many
SELECT advisory_id, cwe_id FROM advisory_cwes
WHERE advisory_id = ANY(sqlc.arg(advisory_ids)::uuid[])
ORDER BY advisory_id, cwe_id;

-- name: ListScanRuleCWEs :many
SELECT scan_rule_id, cwe_id FROM scan_rule_cwes
WHERE scan_rule_id = ANY(sqlc.arg(scan_rule_ids)::uuid[])
ORDER BY scan_rule_id, cwe_id;

-- name: SyncDeclaredFindingCWEs :exec
-- A pair that survives keeps its original declarer: the audit log records
-- who changed the set, the row records who first asserted the CWE.
WITH removed AS (
    DELETE FROM finding_cwe_assertions fa
    WHERE fa.repo_id = sqlc.arg(repo_id) AND fa.fingerprint = sqlc.arg(fingerprint)
      AND fa.source = 'declared' AND fa.cwe_id <> ALL(sqlc.arg(cwe_ids)::int[])
)
INSERT INTO finding_cwe_assertions (repo_id, fingerprint, cwe_id, source, declared_by, declared_api_key_id)
SELECT sqlc.arg(repo_id)::uuid, sqlc.arg(fingerprint)::text, unnest(sqlc.arg(cwe_ids)::int[]),
       'declared'::finding_cwe_source, sqlc.narg(declared_by)::uuid, sqlc.narg(declared_api_key_id)::uuid
ON CONFLICT DO NOTHING;

-- name: ListFindingCWEs :many
-- Every CWE the given findings carry. Ordered by source precedence (the view's
-- branch order) so a caller deduplicating by id keeps the strongest source.
SELECT fc.vulnerability_id, fc.cwe_id, fc.source
FROM finding_cwes fc
WHERE fc.vulnerability_id = ANY(sqlc.arg(vulnerability_ids)::uuid[])
ORDER BY fc.vulnerability_id, fc.cwe_id,
         CASE fc.source WHEN 'rule' THEN 0 WHEN 'advisory' THEN 1 WHEN 'sarif_result' THEN 2 WHEN 'declared' THEN 3 ELSE 4 END;

-- name: SyncSnapshotSARIFResultCWEs :exec
-- Makes every fingerprint one SARIF artifact reports carry exactly its
-- result.taxa CWEs (ADR-037 §2.2): fingerprints[] is everything reported,
-- (pair_fingerprints[i], pair_cwe_ids[i]) what each now lists.
WITH scope AS (
    SELECT s.repo_id FROM snapshots s WHERE s.id = sqlc.arg(snapshot_id)
), wanted AS (
    SELECT unnest(sqlc.arg(pair_fingerprints)::text[]) AS fingerprint,
           unnest(sqlc.arg(pair_cwe_ids)::int[]) AS cwe_id
), removed AS (
    DELETE FROM finding_cwe_assertions fa
    USING scope
    WHERE fa.repo_id = scope.repo_id
      AND fa.source = 'sarif_result'
      AND fa.fingerprint = ANY(sqlc.arg(fingerprints)::text[])
      AND NOT EXISTS (SELECT 1 FROM wanted w WHERE w.fingerprint = fa.fingerprint AND w.cwe_id = fa.cwe_id)
)
INSERT INTO finding_cwe_assertions (repo_id, fingerprint, cwe_id, source)
SELECT scope.repo_id, wanted.fingerprint, wanted.cwe_id, 'sarif_result'::finding_cwe_source
FROM scope CROSS JOIN wanted
ON CONFLICT DO NOTHING;
