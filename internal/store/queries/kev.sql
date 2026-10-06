-- name: UpsertKEVEntries :exec
-- One statement for the whole catalog (same unnest batching as pr_checks.sql):
-- per-row round trips made each sync pass ~2,900 sequential statements inside
-- the leader-locked transaction. Dates travel as text with '' meaning NULL —
-- sqlc's date[] binding cannot carry NULLs. cve_ids arrive uppercased by the
-- sync; see the table comment. updated_at = now() on every conflict is the
-- point, not waste: it is the "last seen in this catalog" fact the grace
-- delete below measures against.
INSERT INTO kev_entries (
    source, cve_id, vendor_project, product, vulnerability_name,
    date_added, due_date, known_ransomware_campaign_use, updated_at
)
SELECT sqlc.arg(source),
       unnest(sqlc.arg(cve_ids)::text[]),
       unnest(sqlc.arg(vendor_projects)::text[]),
       unnest(sqlc.arg(products)::text[]),
       unnest(sqlc.arg(vulnerability_names)::text[]),
       nullif(unnest(sqlc.arg(dates_added)::text[]), '')::date,
       nullif(unnest(sqlc.arg(due_dates)::text[]), '')::date,
       unnest(sqlc.arg(ransomware_uses)::boolean[]),
       now()
ON CONFLICT (source, cve_id) DO UPDATE SET
    vendor_project = EXCLUDED.vendor_project,
    product = EXCLUDED.product,
    vulnerability_name = EXCLUDED.vulnerability_name,
    date_added = EXCLUDED.date_added,
    due_date = EXCLUDED.due_date,
    known_ransomware_campaign_use = EXCLUDED.known_ransomware_campaign_use,
    updated_at = now();

-- name: DeleteKEVSourceEntriesNotSeen :exec
-- Withdrawal, scoped to one source and grace-aware. grace_seconds = 0 deletes
-- immediately (CISA: one atomic document, absence IS withdrawal). A positive
-- grace keeps an unseen row until it has been missing for the window (EUVD:
-- the paginated walk has no stable sort order, so a record shifting between
-- pages mid-walk can be skipped once — un-listing an exploited CVE over a
-- pagination artifact is the worse error; a real withdrawal lands one pass
-- later).
DELETE FROM kev_entries
WHERE source = sqlc.arg(source)
  AND NOT (cve_id = ANY(sqlc.arg(keep)::text[]))
  AND updated_at < now() - make_interval(secs => sqlc.arg(grace_seconds)::int);

-- name: DeleteKEVEntriesForOtherSources :exec
-- A source an operator disabled must stop gating: its sync no longer runs, so
-- its rows would otherwise be a frozen catalog with no withdrawal path. The
-- active sources' pass deletes everyone else's rows.
DELETE FROM kev_entries WHERE NOT (source = ANY(sqlc.arg(sources)::text[]));

-- name: DeleteAllKEVEntries :exec
-- The kev.enabled=false path: with no sync running at all, stored rows would
-- block forever on data nobody refreshes.
DELETE FROM kev_entries;

-- name: CountKEVEntries :one
SELECT COUNT(*) FROM kev_entries;

-- name: FilterKEVAdvisoryIDs :many
-- Which of these advisories are on ANY exploited catalog? The identifier set
-- (canonical id plus every alias) is built first so the catalog probe is an
-- equi-join the kev_entries_cve_id_idx index serves; the previous
-- OR-across-two-columns join condition forced a nested loop on every gate
-- evaluation. upper() on the advisory side only — kev_entries is uppercase by
-- construction.
SELECT DISTINCT candidate.id
FROM (
    SELECT a.id, upper(a.canonical_id) AS identifier
    FROM advisories a
    WHERE a.id = ANY(sqlc.arg(advisory_ids)::uuid[])
    UNION
    SELECT al.advisory_id, upper(al.alias)
    FROM advisory_aliases al
    WHERE al.advisory_id = ANY(sqlc.arg(advisory_ids)::uuid[])
) candidate
JOIN kev_entries k ON k.cve_id = candidate.identifier;

-- name: FilterKEVIdentifiers :many
-- Membership check for raw identifier strings (already uppercased by the
-- caller), for findings that carry no advisory row.
SELECT DISTINCT cve_id FROM kev_entries WHERE cve_id = ANY($1::text[]);

-- name: ListKEVEntriesForIdentifiers :many
-- Every catalog entry matching any of an advisory's identifiers (canonical id
-- plus aliases, uppercased by the caller) — one row per (source, cve), so the
-- finding detail can say WHO lists it. 'cisa' is ordered first EXPLICITLY, not
-- by the alphabetical accident of its name: it is the source carrying the
-- richest facts (due date, ransomware use) and the detail reads its row's
-- scalars. Every other source sorts by name — first-class for membership,
-- which is a union, and for attribution, which lists them all (deduplicated by
-- the caller: two aliases on one catalog are still one source).
SELECT * FROM kev_entries
WHERE cve_id = ANY($1::text[])
ORDER BY (source <> 'cisa'), source, cve_id;
