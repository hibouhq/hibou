DELETE FROM finding_resolutions WHERE reason = 'producer_retired';
DELETE FROM producer_policies WHERE policy = 'retired';
ALTER TABLE finding_resolutions DROP CONSTRAINT finding_resolutions_reason_check;
ALTER TABLE finding_resolutions ADD CONSTRAINT finding_resolutions_reason_check
    CHECK (reason IN ('fixed', 'file_removed', 'no_longer_reported', 'producer_changed'));
ALTER TABLE producer_policies DROP CONSTRAINT producer_policies_policy_check;
ALTER TABLE producer_policies ADD CONSTRAINT producer_policies_policy_check
    CHECK (policy IN ('coverage', 'consecutive-absence', 'explicit'));
