-- Updater cooldown (Renovate, Dependabot) read at extraction, compared
-- with the install-time setting (ADR-048 §3.1). Per-module install
-- settings live in the modules JSON.
ALTER TABLE dep_extraction_runs ADD COLUMN updaters jsonb NOT NULL DEFAULT '[]'::jsonb;
