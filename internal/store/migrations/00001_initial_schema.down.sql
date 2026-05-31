-- License
DROP TABLE IF EXISTS license_exceptions;
DROP TABLE IF EXISTS license_policies;

-- Secret scanning
DROP TABLE IF EXISTS secret_finding_sources;
DROP TABLE IF EXISTS secret_findings;

-- Analysis engine
DROP TABLE IF EXISTS vex_statements;
DROP TABLE IF EXISTS audit_logs;
DROP TABLE IF EXISTS integrations;
DROP TABLE IF EXISTS notifications;
DROP TABLE IF EXISTS quality_gates;
DROP TABLE IF EXISTS vuln_matches;
DROP TABLE IF EXISTS scan_providers;
DROP TABLE IF EXISTS scans;
DROP TABLE IF EXISTS advisory_cache;
DROP TABLE IF EXISTS affected_ranges;
DROP TABLE IF EXISTS advisory_sources;
DROP TABLE IF EXISTS advisory_aliases;
DROP TABLE IF EXISTS advisories;

-- Core
DROP TABLE IF EXISTS notification_rules;
DROP TABLE IF EXISTS casbin_rules;
DROP TABLE IF EXISTS api_keys;
DROP TABLE IF EXISTS deployments;
DROP TABLE IF EXISTS clients;
DROP TABLE IF EXISTS releases;
DROP TABLE IF EXISTS findings;
DROP TABLE IF EXISTS snapshot_components;
DROP TABLE IF EXISTS components;
DROP TABLE IF EXISTS snapshots;
DROP TABLE IF EXISTS refs;
DROP TABLE IF EXISTS repositories;
DROP TABLE IF EXISTS team_members;
DROP TABLE IF EXISTS teams;
DROP TABLE IF EXISTS org_members;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS organizations;

-- Enums
DROP TYPE IF EXISTS secret_status;
DROP TYPE IF EXISTS vex_source;
DROP TYPE IF EXISTS vex_justification;
DROP TYPE IF EXISTS vex_status;
DROP TYPE IF EXISTS integration_type;
DROP TYPE IF EXISTS notification_status;
DROP TYPE IF EXISTS malware_type;
DROP TYPE IF EXISTS cvss_version;
DROP TYPE IF EXISTS scan_status;
DROP TYPE IF EXISTS notification_destination_type;
DROP TYPE IF EXISTS deployment_status;
DROP TYPE IF EXISTS severity_level;
DROP TYPE IF EXISTS snapshot_status;
DROP TYPE IF EXISTS ref_type;
DROP TYPE IF EXISTS member_role;
