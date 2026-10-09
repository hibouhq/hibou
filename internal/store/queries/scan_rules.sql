-- name: UpsertScanRule :one
INSERT INTO scan_rules (
    tool,
    rule_id,
    name,
    short_description,
    full_description,
    help_uri,
    help_markdown,
    default_level,
    security_severity,
    rule_precision,
    tags,
    properties
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
ON CONFLICT (tool, rule_id) DO UPDATE SET
    name              = EXCLUDED.name,
    short_description = EXCLUDED.short_description,
    full_description  = EXCLUDED.full_description,
    help_uri          = EXCLUDED.help_uri,
    help_markdown     = EXCLUDED.help_markdown,
    default_level     = EXCLUDED.default_level,
    security_severity = EXCLUDED.security_severity,
    rule_precision    = EXCLUDED.rule_precision,
    tags              = EXCLUDED.tags,
    properties        = EXCLUDED.properties,
    updated_at        = NOW()
RETURNING id;

-- name: GetScanRule :one
SELECT * FROM scan_rules WHERE tool = $1 AND rule_id = $2;

-- name: ListScanRulesBySnapshot :many
SELECT DISTINCT sr.*
FROM scan_rules sr
JOIN vulnerabilities v ON v.rule_ref_id = sr.id
WHERE v.snapshot_id = $1
ORDER BY sr.tool, sr.rule_id;
