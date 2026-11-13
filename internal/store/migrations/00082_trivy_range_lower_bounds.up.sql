-- Trivy reports an affected installed version, not an affected lower bound.
-- The original installed version cannot be recovered from these ranges.
DELETE FROM affected_ranges
WHERE source = 'trivy' AND introduced IN ('', '0');

-- Cached mapped responses would otherwise reintroduce the invalid ranges.
DELETE FROM advisory_cache WHERE provider = 'trivy';
