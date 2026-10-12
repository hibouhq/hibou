-- ADR-034 open question: a producer removed from CI on purpose kept its
-- findings carried as "not re-checked" forever. An org admin can now retire
-- it: while it does not run, its findings resolve as producer_retired — an
-- explicit decision, never counted as a fix.
ALTER TABLE producer_policies DROP CONSTRAINT producer_policies_policy_check;
ALTER TABLE producer_policies ADD CONSTRAINT producer_policies_policy_check
    CHECK (policy IN ('coverage', 'consecutive-absence', 'explicit', 'retired'));
ALTER TABLE finding_resolutions DROP CONSTRAINT finding_resolutions_reason_check;
ALTER TABLE finding_resolutions ADD CONSTRAINT finding_resolutions_reason_check
    CHECK (reason IN ('fixed', 'file_removed', 'no_longer_reported', 'producer_changed', 'producer_retired'));
