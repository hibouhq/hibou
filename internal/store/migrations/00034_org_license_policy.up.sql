-- Completes the license_policies table so an organization can hold one license
-- policy, which repositories inherit and may override in their .hibou.yaml.
--
-- The table shipped in 00001 with zero Go callers and a schema from the earlier
-- id-list design (allowed_licenses / denied_licenses). Those two columns are
-- exactly `allow` and `deny` in the current model, so this completes the row
-- rather than replacing it: the category axis, package exemptions, the
-- unknown-license stance, and the delta scope are what were missing.
--
-- The policy lives here rather than on quality_gates because it is one legal
-- stance per org, not one per gate row — N gate rows each carrying a policy
-- would have undefined precedence.
ALTER TABLE license_policies
    ADD COLUMN denied_categories text[] DEFAULT ARRAY[]::text[] NOT NULL,
    ADD COLUMN exempt_purls text[] DEFAULT ARRAY[]::text[] NOT NULL,
    -- Matches the config-layer default: an unreviewed license is a legal risk
    -- until someone looks at it.
    ADD COLUMN deny_unknown boolean DEFAULT TRUE NOT NULL,
    -- 'new' gates only what a change introduces; 'all' gates the whole tree.
    ADD COLUMN evaluate text DEFAULT 'new' NOT NULL
        CONSTRAINT license_policies_evaluate_check CHECK (evaluate IN ('new', 'all')),
    ADD COLUMN updated_by uuid REFERENCES users(id) ON DELETE SET NULL;

-- The one-enabled-policy rule is new: 00001 constrained only (org_id, name), so
-- an existing deployment may legally hold several enabled rows for one org.
-- Creating the index below over that state fails and aborts the migration, so
-- retire the extras first — keeping the most recently updated one, which is the
-- closest thing to "the current policy" that the old schema recorded.
--
-- Rows are disabled, never deleted: this is someone's recorded policy history.
-- In practice the table has never had a writer, so this is expected to affect
-- nothing; it exists so the migration cannot block a deploy if it does.
UPDATE license_policies
SET enabled = FALSE,
    updated_at = NOW()
WHERE enabled
  AND id NOT IN (
      SELECT DISTINCT ON (org_id) id
      FROM license_policies
      WHERE enabled
      ORDER BY org_id, updated_at DESC, id
  );

-- One enabled policy per org. Without this, "the org policy" is ambiguous the
-- moment a second row is enabled, which is the precedence problem this table was
-- chosen to avoid.
CREATE UNIQUE INDEX license_policies_one_enabled_per_org
    ON license_policies (org_id)
    WHERE enabled;
