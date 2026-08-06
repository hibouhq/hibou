ALTER TABLE pr_checks
    ADD COLUMN override_state text DEFAULT ''::text NOT NULL,
    ADD COLUMN override_reason text DEFAULT ''::text NOT NULL,
    ADD COLUMN override_by uuid,
    ADD COLUMN override_at timestamp with time zone,
    ADD CONSTRAINT pr_checks_override_state_check CHECK ((override_state = ANY (ARRAY[''::text, 'pass'::text, 'fail'::text])));
