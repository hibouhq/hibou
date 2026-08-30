-- Efficiency pass, measured against a full-corpus database (383k cve_records,
-- 906k cve_affected_products, 522 MB). Every change here reproduces under
-- EXPLAIN / pg_stat on that data; nothing is speculative.

-- The subscription preview/backfill/count queries all end in
--   WHERE state = 'PUBLISHED' ... ORDER BY published_at DESC NULLS LAST
-- and without an index in exactly that shape they seq-scan the whole
-- cve_records heap (263 MB) and spill an external merge sort (~130 MB of temp
-- I/O) on every hot-key call. Measured: 115 ms warm for product_key 'linux'
-- versus 5 ms with this index. The explicit NULLS LAST is load-bearing — a
-- plain DESC index sorts nulls first and the planner will not use it here.
CREATE INDEX cve_records_published_pub_idx
    ON cve_records (published_at DESC NULLS LAST, cve_id)
    WHERE state = 'PUBLISHED';

-- Unused, and worse than unused: 12 MB, idx_scan ≈ 0, no query orders or
-- filters on record_updated_at through an index (the one ORDER BY runs off a
-- pkey-driven join), and because the CVE resync rewrites record_updated_at on
-- every visited row, its presence disqualifies HOT updates on the hottest
-- write path in the schema (measured 2% HOT rate on 33k updates).
DROP INDEX IF EXISTS cve_records_updated_idx;

-- Unused: nothing anywhere filters snapshot_components.labels — the column is
-- read back whole. A GIN index on a jsonb nothing queries by key is pure write
-- amplification, and the labels-accumulating upsert on this branch would be
-- its first real writer.
DROP INDEX IF EXISTS idx_snapshot_components_labels;

-- The surrogate uuid key on cve_affected_products costs ~50 MB (36 MB pkey
-- index + 14 MB of column) — 9.4% of the whole database — and is referenced by
-- no FK, no query, and no Go consumer: rows are addressed exclusively by
-- cve_id (delete-and-reinsert on every resync), which also means the pkey
-- btree absorbs ~900k random uuid insertions per full sync for nothing.
--
-- The table is left without a primary key deliberately: gen_random_uuid()
-- guaranteed no semantic uniqueness, and no natural key exists —
-- (cve_id, product_key, introduced) can legitimately repeat. If logical
-- replication ever needs an identity, add a bigint IDENTITY column then.
ALTER TABLE cve_affected_products DROP CONSTRAINT cve_affected_products_pkey;
ALTER TABLE cve_affected_products DROP COLUMN id;
