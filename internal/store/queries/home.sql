-- Home (ADR-053 §9).

-- name: RecordRepoVisit :exec
INSERT INTO user_repo_visits (user_id, repo_id) VALUES ($1, $2)
ON CONFLICT (user_id, repo_id) DO UPDATE SET
    visit_count = CASE WHEN user_repo_visits.last_visited_at < NOW() - INTERVAL '30 minutes'
                       THEN user_repo_visits.visit_count + 1 ELSE user_repo_visits.visit_count END,
    last_visited_at = NOW();

-- name: ListTopVisitedRepos :many
-- The person's repositories by use: visits weighed down by days since the
-- last one, so a repository opened daily last month yields to this week's.
SELECT r.id, r.org_id, r.slug, r.name, o.slug AS org_slug, o.provider AS org_provider,
       v.last_visited_at, v.visit_count
  FROM user_repo_visits v
  JOIN repositories r ON r.id = v.repo_id
  JOIN organizations o ON o.id = r.org_id
 WHERE v.user_id = sqlc.arg(user_id) AND r.org_id = ANY(sqlc.arg(org_ids)::uuid[])
 ORDER BY v.visit_count::float8 / (1 + EXTRACT(EPOCH FROM NOW() - v.last_visited_at) / 86400) DESC, r.slug
 LIMIT sqlc.arg(row_limit);

-- name: ListRecentlyAnalysedRepos :many
-- Repositories of these organisations by their latest analysis: what Home
-- shows before the person has opened any.
SELECT r.id, r.org_id, r.slug, r.name, o.slug AS org_slug, o.provider AS org_provider,
       MAX(s.created_at)::timestamptz AS last_analysed_at
  FROM repositories r
  JOIN organizations o ON o.id = r.org_id
  JOIN snapshots s ON s.repo_id = r.id AND s.status IN ('complete', 'active')
 WHERE r.org_id = ANY(sqlc.arg(org_ids)::uuid[])
 GROUP BY r.id, o.slug, o.provider
 ORDER BY MAX(s.created_at) DESC, r.slug
 LIMIT sqlc.arg(row_limit);
