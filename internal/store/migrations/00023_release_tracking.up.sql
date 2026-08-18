-- Release tracking (ADR-024). Releases are derived — from version tags with an
-- analysis snapshot, or from forge release events — never hand-created.
--   html_url             link back to the forge release page
--   source               how the row was born: tag | forge
--   pending_snapshot_id  re-tag divergence candidate: the tag now points at a
--                        different commit than what clients run; a release
--                        manager decides to adopt or keep (ADR-024 §5)
--   diverged_at          when the divergence was detected (NULL = aligned)
--   dismissed_commit_sha re-tag the manager chose to ignore ("keep old build"),
--                        so the same candidate does not re-flag on every scan
ALTER TABLE releases
    ADD COLUMN html_url text,
    ADD COLUMN source text DEFAULT 'tag' NOT NULL,
    ADD COLUMN pending_snapshot_id uuid REFERENCES snapshots(id) ON DELETE SET NULL,
    ADD COLUMN diverged_at timestamp with time zone,
    ADD COLUMN dismissed_commit_sha text;

-- The enriched release listing joins deployments by release; only the reverse
-- (client → deployments) was indexed.
CREATE INDEX IF NOT EXISTS idx_deployments_release_id ON deployments USING btree (release_id);

-- Rollout history must never vanish as a side effect of a release row going
-- away (ADR-024 §5b): the original CASCADE meant deleting a release silently
-- erased who ran it. Release removal is guarded in code; the FK now enforces
-- it at the last line of defense.
ALTER TABLE deployments DROP CONSTRAINT deployments_release_id_fkey;
ALTER TABLE deployments
    ADD CONSTRAINT deployments_release_id_fkey FOREIGN KEY (release_id) REFERENCES releases(id) ON DELETE RESTRICT;
