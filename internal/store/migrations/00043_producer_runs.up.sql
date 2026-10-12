-- ADR-034 §2: every upload records, per producer, what actually ran — the
-- scan coverage of a snapshot. A finding is only resolved on evidence that
-- its producer ran again and covered it; this table is that evidence.

-- What the uploader declared about the run (CLI flags / upload parameters).
-- SARIF values win over these when both are present.
ALTER TABLE snapshot_artifacts
    ADD COLUMN scope text CHECK (scope IN ('full', 'partial')),
    ADD COLUMN scope_paths text[] NOT NULL DEFAULT '{}',
    ADD COLUMN tool_version text,
    ADD COLUMN config_digest text;

CREATE TYPE producer_run_scope AS ENUM ('full', 'partial');
CREATE TYPE producer_run_outcome AS ENUM ('completed', 'partial', 'failed');

CREATE TABLE producer_runs (
    id uuid DEFAULT gen_random_uuid() PRIMARY KEY,
    snapshot_id uuid NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,
    -- The artifact the run came from; NULL for server-side producers
    -- (secret scanning, SBOM advisory matching).
    artifact_id uuid REFERENCES snapshot_artifacts(id) ON DELETE CASCADE,
    -- Position of the run inside a multi-run SARIF document.
    run_index integer NOT NULL DEFAULT 0,
    -- Tool name as ingested: lower(tool.driver.name), 'secret-scanning:<p>',
    -- 'sbom-matching'. Matches vulnerabilities.scanner_name for SARIF.
    producer text NOT NULL,
    version text,
    config_digest text,
    scope producer_run_scope NOT NULL DEFAULT 'full',
    -- false when nobody said: scope 'full' is then hibou's assumption, not
    -- evidence, and cannot satisfy a strict coverage policy (ADR-035/036).
    scope_declared boolean NOT NULL DEFAULT false,
    scope_paths text[] NOT NULL DEFAULT '{}',
    outcome producer_run_outcome NOT NULL,
    -- [{path, reason}] — reason: timeout, too_large, parse_error,
    -- resource_limit, other.
    skipped_files jsonb NOT NULL DEFAULT '[]'::jsonb,
    finding_count integer NOT NULL DEFAULT 0,
    -- Failure message or the scanner's own notification text.
    detail text,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

-- Re-processing an artifact replaces its runs; server-side producers upsert
-- one row per snapshot.
CREATE UNIQUE INDEX producer_runs_artifact_run_key
    ON producer_runs (artifact_id, run_index) WHERE artifact_id IS NOT NULL;
CREATE UNIQUE INDEX producer_runs_snapshot_producer_key
    ON producer_runs (snapshot_id, producer) WHERE artifact_id IS NULL;
CREATE INDEX producer_runs_snapshot_idx ON producer_runs (snapshot_id);
