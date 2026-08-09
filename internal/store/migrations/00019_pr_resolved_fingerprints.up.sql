-- "A PR already fixes this finding" (TODO-FEAT §1): the resolved set of each
-- published gate run, so the findings list can join instead of recomputing a
-- delta per render. Rows die with their pr_check.
CREATE TABLE pr_check_resolved_fingerprints (
    pr_check_id uuid NOT NULL REFERENCES pr_checks(id) ON DELETE CASCADE,
    fingerprint text NOT NULL,
    PRIMARY KEY (pr_check_id, fingerprint)
);

CREATE INDEX pr_check_resolved_fingerprints_fingerprint_idx
    ON pr_check_resolved_fingerprints (fingerprint);
