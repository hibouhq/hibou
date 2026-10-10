-- ADR-038 §3: "no source rates this" is its own severity, distinct from
-- 'info' (a producer's deliberate "informational"). It sorts between medium
-- and low, which is where enum order places it.
--
-- Its own file: Postgres cannot use an enum value in the transaction that
-- adds it, and 00042 does.
ALTER TYPE severity_level ADD VALUE IF NOT EXISTS 'unknown' BEFORE 'low';
