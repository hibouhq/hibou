-- Flattened schema (ADR db-review). Migration history 00001-00030 squashed
-- into a single canonical schema; early alpha, no back-compat required.
-- Regenerate by pg_dump --schema-only of a fully-migrated database.

--
-- PostgreSQL database dump
--


-- Dumped from database version 18.4 (Debian 18.4-1.pgdg13+1)
-- Dumped by pg_dump version 18.4 (Debian 18.4-1.pgdg13+1)


--
-- Name: pg_trgm; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS pg_trgm WITH SCHEMA public;


--
-- Name: pgcrypto; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;


--
-- Name: cvss_version; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE cvss_version AS ENUM (
    'v2',
    'v3.0',
    'v3.1',
    'v4.0'
);


--
-- Name: deployment_status; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE deployment_status AS ENUM (
    'active',
    'rolled_back',
    'superseded'
);


--
-- Name: dismissal_reason; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE dismissal_reason AS ENUM (
    'acceptable_risk',
    'false_positive',
    'mitigating_control',
    'not_applicable',
    'used_in_tests'
);


--
-- Name: integration_type; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE integration_type AS ENUM (
    'slack',
    'teams',
    'discord',
    'webhook',
    'email'
);


--
-- Name: malware_type; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE malware_type AS ENUM (
    'typosquat',
    'dependency_confusion',
    'backdoor',
    'cryptominer',
    'data_exfiltration',
    'other'
);


--
-- Name: member_role; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE member_role AS ENUM (
    'admin',
    'developer',
    'release_manager',
    'auditor',
    'viewer'
);


--
-- Name: notification_destination_type; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE notification_destination_type AS ENUM (
    'webhook',
    'slack',
    'teams',
    'email',
    'discord'
);


--
-- Name: notification_status; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE notification_status AS ENUM (
    'unread',
    'read',
    'dismissed'
);


--
-- Name: reachability; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE reachability AS ENUM (
    'reachable',
    'not_reachable',
    'unknown'
);


--
-- Name: ref_type; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE ref_type AS ENUM (
    'branch',
    'tag',
    'pull_request'
);


--
-- Name: scan_status; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE scan_status AS ENUM (
    'pending',
    'running',
    'complete',
    'failed',
    'cancelled'
);


--
-- Name: severity_level; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE severity_level AS ENUM (
    'critical',
    'high',
    'medium',
    'low',
    'info'
);


--
-- Name: snapshot_status; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE snapshot_status AS ENUM (
    'pending',
    'processing',
    'complete',
    'failed',
    'active',
    'archived',
    'purged'
);


--
-- Name: vex_justification; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE vex_justification AS ENUM (
    'component_not_present',
    'vulnerable_code_not_present',
    'vulnerable_code_not_in_execute_path',
    'vulnerable_code_cannot_be_controlled_by_adversary',
    'inline_mitigations_already_exist'
);


--
-- Name: vex_source; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE vex_source AS ENUM (
    'manual',
    'imported',
    'propagated',
    'automated'
);


--
-- Name: vex_status; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE vex_status AS ENUM (
    'not_affected',
    'affected',
    'fixed',
    'under_investigation'
);


--
-- Name: vulnerability_status; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE vulnerability_status AS ENUM (
    'detected',
    'confirmed',
    'dismissed',
    'resolved'
);


--
-- Name: vulnerability_type; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE vulnerability_type AS ENUM (
    'dependency',
    'sast',
    'secret',
    'malware',
    'dast',
    'container',
    'fuzzing',
    'manual',
    'generic'
);


--
-- Name: snapshots_set_tenant(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION snapshots_set_tenant() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    SELECT repo.org_id, r.repo_id
    INTO NEW.org_id, NEW.repo_id
    FROM refs r
    JOIN repositories repo ON repo.id = r.repo_id
    WHERE r.id = NEW.ref_id;
    RETURN NEW;
END;
$$;


--
-- Name: vulnerabilities_set_tenant(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION vulnerabilities_set_tenant() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    SELECT s.org_id, s.repo_id
    INTO NEW.org_id, NEW.repo_id
    FROM snapshots s
    WHERE s.id = NEW.snapshot_id;
    RETURN NEW;
END;
$$;




--
-- Name: advisories; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE advisories (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    canonical_id text NOT NULL,
    title text DEFAULT ''::text NOT NULL,
    description text DEFAULT ''::text NOT NULL,
    severity severity_level DEFAULT 'info'::severity_level NOT NULL,
    cvss_score numeric(4,2),
    cvss_version cvss_version,
    cvss_vector text DEFAULT ''::text NOT NULL,
    cwe_ids text[] DEFAULT ARRAY[]::text[] NOT NULL,
    is_malware boolean DEFAULT false NOT NULL,
    malware_type malware_type,
    published_at timestamp with time zone,
    withdrawn_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT advisories_cvss_score_check CHECK (((cvss_score IS NULL) OR ((cvss_score >= (0)::numeric) AND (cvss_score <= (10)::numeric))))
);


--
-- Name: advisory_aliases; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE advisory_aliases (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    advisory_id uuid NOT NULL,
    alias text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: advisory_cache; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE advisory_cache (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    ecosystem text NOT NULL,
    package_name text NOT NULL,
    provider text NOT NULL,
    response_data jsonb DEFAULT '{}'::jsonb NOT NULL,
    advisory_count integer DEFAULT 0 NOT NULL,
    fetched_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL
);


--
-- Name: advisory_sources; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE advisory_sources (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    advisory_id uuid NOT NULL,
    provider text NOT NULL,
    provider_id text NOT NULL,
    severity severity_level,
    cvss_score numeric(4,2),
    cvss_version cvss_version,
    cvss_vector text DEFAULT ''::text NOT NULL,
    raw_data jsonb DEFAULT '{}'::jsonb NOT NULL,
    fetched_at timestamp with time zone DEFAULT now() NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT advisory_sources_cvss_score_check CHECK (((cvss_score IS NULL) OR ((cvss_score >= (0)::numeric) AND (cvss_score <= (10)::numeric))))
);


--
-- Name: affected_ranges; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE affected_ranges (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    advisory_id uuid NOT NULL,
    ecosystem text NOT NULL,
    package_name text NOT NULL,
    introduced text DEFAULT ''::text NOT NULL,
    fixed text DEFAULT ''::text NOT NULL,
    last_affected text DEFAULT ''::text NOT NULL,
    source text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: api_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE api_keys (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    name text NOT NULL,
    key_hash text NOT NULL,
    scopes jsonb DEFAULT '[]'::jsonb NOT NULL,
    expires_at timestamp with time zone,
    last_used_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: audit_logs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE audit_logs (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    actor_id uuid,
    actor_type text DEFAULT 'user'::text NOT NULL,
    actor_display text DEFAULT ''::text NOT NULL,
    action text NOT NULL,
    resource_type text NOT NULL,
    resource_id text NOT NULL,
    org_id uuid,
    context jsonb DEFAULT '{}'::jsonb NOT NULL,
    ip_address text DEFAULT ''::text NOT NULL,
    user_agent text DEFAULT ''::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: casbin_rules; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE casbin_rules (
    id integer NOT NULL,
    ptype text,
    v0 text,
    v1 text,
    v2 text,
    v3 text,
    v4 text,
    v5 text
);


--
-- Name: casbin_rules_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE casbin_rules_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: casbin_rules_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE casbin_rules_id_seq OWNED BY casbin_rules.id;


--
-- Name: clients; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE clients (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    org_id uuid NOT NULL,
    name text NOT NULL,
    slug text NOT NULL,
    client_type text DEFAULT 'external'::text NOT NULL,
    contact_email text,
    contact_name text,
    notification_prefs jsonb DEFAULT '{}'::jsonb NOT NULL,
    labels jsonb DEFAULT '{}'::jsonb NOT NULL,
    metadata jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: component_dependencies; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE component_dependencies (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    snapshot_id uuid NOT NULL,
    component_id uuid NOT NULL,
    depends_on_component_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: components; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE components (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    purl text NOT NULL,
    name text NOT NULL,
    version text NOT NULL,
    ecosystem text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    licenses text[] DEFAULT ARRAY[]::text[] CONSTRAINT components_licenses_arr_not_null NOT NULL
);


--
-- Name: coverage_files; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE coverage_files (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    coverage_report_id uuid NOT NULL,
    file_path text NOT NULL,
    line_rate double precision,
    branch_rate double precision,
    lines_valid integer DEFAULT 0 NOT NULL,
    lines_covered integer DEFAULT 0 NOT NULL,
    branches_valid integer DEFAULT 0 NOT NULL,
    branches_covered integer DEFAULT 0 NOT NULL
);


--
-- Name: coverage_lines; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE coverage_lines (
    coverage_file_id uuid NOT NULL,
    line_number integer NOT NULL,
    hits integer NOT NULL
);


--
-- Name: coverage_reports; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE coverage_reports (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    snapshot_id uuid NOT NULL,
    format text NOT NULL,
    line_rate double precision,
    branch_rate double precision,
    lines_valid integer DEFAULT 0 NOT NULL,
    lines_covered integer DEFAULT 0 NOT NULL,
    branches_valid integer DEFAULT 0 NOT NULL,
    branches_covered integer DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: deployments; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE deployments (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    client_id uuid NOT NULL,
    release_id uuid NOT NULL,
    environment text NOT NULL,
    status deployment_status NOT NULL,
    deployed_at timestamp with time zone NOT NULL,
    deployed_by text,
    rollback_target_id uuid,
    notes text,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: forge_org_admins; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE forge_org_admins (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    provider text NOT NULL,
    account text NOT NULL,
    provider_user_id text NOT NULL,
    org_id uuid,
    granted boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: forge_repositories; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE forge_repositories (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    provider text NOT NULL,
    installation_id bigint,
    provider_repo_id text,
    account_login text NOT NULL,
    owner text NOT NULL,
    name text NOT NULL,
    full_name text NOT NULL,
    provider_key text NOT NULL,
    private boolean DEFAULT false NOT NULL,
    default_branch text DEFAULT ''::text NOT NULL,
    html_url text DEFAULT ''::text NOT NULL,
    archived boolean DEFAULT false NOT NULL,
    last_seen_at timestamp with time zone DEFAULT now() NOT NULL,
    removed_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: integrations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE integrations (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    org_id uuid NOT NULL,
    name text NOT NULL,
    integration_type integration_type NOT NULL,
    config jsonb DEFAULT '{}'::jsonb NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    last_success_at timestamp with time zone,
    last_failure_at timestamp with time zone,
    failure_count integer DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: license_exceptions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE license_exceptions (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    policy_id uuid NOT NULL,
    component_purl text NOT NULL,
    license_id text NOT NULL,
    justification text DEFAULT ''::text NOT NULL,
    expires_at timestamp with time zone,
    created_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: license_policies; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE license_policies (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    org_id uuid NOT NULL,
    name text NOT NULL,
    allowed_licenses text[] DEFAULT ARRAY[]::text[] NOT NULL,
    denied_licenses text[] DEFAULT ARRAY[]::text[] NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: notification_rules; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE notification_rules (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    org_id uuid NOT NULL,
    name text NOT NULL,
    event_type text NOT NULL,
    conditions jsonb DEFAULT '{}'::jsonb NOT NULL,
    destination_type notification_destination_type NOT NULL,
    destination_config jsonb DEFAULT '{}'::jsonb NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: notifications; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE notifications (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    type text NOT NULL,
    title text NOT NULL,
    body text DEFAULT ''::text NOT NULL,
    link text DEFAULT ''::text NOT NULL,
    severity severity_level,
    status notification_status DEFAULT 'unread'::notification_status NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: org_members; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE org_members (
    org_id uuid NOT NULL,
    user_id uuid NOT NULL,
    role member_role NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    source text DEFAULT 'invite'::text NOT NULL,
    synced_at timestamp with time zone,
    expires_at timestamp with time zone,
    CONSTRAINT org_members_source_check CHECK ((source = ANY (ARRAY['forge'::text, 'invite'::text])))
);


--
-- Name: organizations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE organizations (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    name text NOT NULL,
    slug text NOT NULL,
    display_name text NOT NULL,
    provider text DEFAULT 'github'::text NOT NULL,
    settings jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: pr_checks; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE pr_checks (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    repo_id uuid NOT NULL,
    ref_id uuid,
    head_sha text NOT NULL,
    context text DEFAULT 'hibou/security'::text NOT NULL,
    state text NOT NULL,
    conclusion text DEFAULT ''::text NOT NULL,
    enforcement text DEFAULT 'advisory'::text NOT NULL,
    passed boolean DEFAULT false NOT NULL,
    reasons jsonb DEFAULT '[]'::jsonb NOT NULL,
    delta_summary jsonb DEFAULT '{}'::jsonb NOT NULL,
    external_id text DEFAULT ''::text NOT NULL,
    target_url text DEFAULT ''::text NOT NULL,
    forge_synced_at timestamp with time zone,
    last_error text DEFAULT ''::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT pr_checks_enforcement_check CHECK ((enforcement = ANY (ARRAY['advisory'::text, 'blocking'::text])))
);


--
-- Name: quality_gates; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE quality_gates (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    org_id uuid NOT NULL,
    repo_id uuid,
    name text NOT NULL,
    description text DEFAULT ''::text NOT NULL,
    max_critical integer DEFAULT 0 NOT NULL,
    max_high integer DEFAULT 0 NOT NULL,
    max_medium integer,
    max_new_findings integer,
    finding_severities text[] DEFAULT ARRAY['critical'::text, 'high'::text] NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: refs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE refs (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    repo_id uuid NOT NULL,
    name text NOT NULL,
    ref_type ref_type NOT NULL,
    provider_id text,
    merge_target_ref_id uuid,
    latest_commit_sha text,
    pr_state text,
    pr_title text DEFAULT ''::text NOT NULL,
    pr_source_branch text DEFAULT ''::text NOT NULL,
    pr_merged_at timestamp with time zone,
    pr_closed_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    pr_number text,
    CONSTRAINT refs_merge_target_not_self_check CHECK (((merge_target_ref_id IS NULL) OR (merge_target_ref_id <> id)))
);


--
-- Name: releases; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE releases (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    repo_id uuid NOT NULL,
    ref_id uuid NOT NULL,
    snapshot_id uuid,
    version text NOT NULL,
    build_metadata jsonb DEFAULT '{}'::jsonb NOT NULL,
    artifact_ids jsonb DEFAULT '[]'::jsonb NOT NULL,
    provenance jsonb DEFAULT '{}'::jsonb NOT NULL,
    image_digests text[] DEFAULT ARRAY[]::text[] NOT NULL,
    published_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: repositories; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE repositories (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    org_id uuid NOT NULL,
    team_id uuid,
    name text NOT NULL,
    slug text NOT NULL,
    provider text NOT NULL,
    provider_id text NOT NULL,
    default_branch text NOT NULL,
    sync_state text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    retention_artifact_bytes bigint DEFAULT 0 NOT NULL
);


--
-- Name: scan_providers; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE scan_providers (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    scan_id uuid NOT NULL,
    provider text NOT NULL,
    status scan_status DEFAULT 'pending'::scan_status NOT NULL,
    cache_hits integer DEFAULT 0 NOT NULL,
    cache_misses integer DEFAULT 0 NOT NULL,
    advisories_found integer DEFAULT 0 NOT NULL,
    response_time_ms integer,
    db_version text DEFAULT ''::text NOT NULL,
    error_message text DEFAULT ''::text NOT NULL,
    started_at timestamp with time zone,
    completed_at timestamp with time zone
);


--
-- Name: scan_rules; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE scan_rules (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tool text NOT NULL,
    rule_id text NOT NULL,
    name text DEFAULT ''::text NOT NULL,
    short_description text DEFAULT ''::text NOT NULL,
    full_description text DEFAULT ''::text NOT NULL,
    help_uri text DEFAULT ''::text NOT NULL,
    help_markdown text DEFAULT ''::text NOT NULL,
    default_level text DEFAULT ''::text NOT NULL,
    security_severity text DEFAULT ''::text NOT NULL,
    rule_precision text DEFAULT ''::text NOT NULL,
    cwe_ids text[] DEFAULT ARRAY[]::text[] NOT NULL,
    tags text[] DEFAULT ARRAY[]::text[] NOT NULL,
    properties jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: scans; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE scans (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    snapshot_id uuid NOT NULL,
    status scan_status DEFAULT 'pending'::scan_status NOT NULL,
    providers_requested text[] DEFAULT ARRAY[]::text[] NOT NULL,
    triggered_by text DEFAULT 'system'::text NOT NULL,
    error_message text DEFAULT ''::text NOT NULL,
    started_at timestamp with time zone,
    completed_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: snapshot_artifacts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE snapshot_artifacts (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    snapshot_id uuid NOT NULL,
    kind text NOT NULL,
    format text,
    tool_name text,
    object_key text NOT NULL,
    sha256 text,
    size_bytes bigint DEFAULT 0 NOT NULL,
    content_type text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    filename text DEFAULT ''::text NOT NULL
);


--
-- Name: snapshot_components; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE snapshot_components (
    snapshot_id uuid NOT NULL,
    component_id uuid NOT NULL,
    labels jsonb DEFAULT '{}'::jsonb NOT NULL
);


--
-- Name: snapshot_dependency_roots; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE snapshot_dependency_roots (
    snapshot_id uuid NOT NULL,
    component_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: snapshot_vuln_rollup; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE snapshot_vuln_rollup (
    snapshot_id uuid NOT NULL,
    counts jsonb DEFAULT '{}'::jsonb NOT NULL,
    total integer DEFAULT 0 NOT NULL,
    rolled_up_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: snapshots; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE snapshots (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    ref_id uuid NOT NULL,
    commit_sha text NOT NULL,
    status snapshot_status DEFAULT 'pending'::snapshot_status NOT NULL,
    labels jsonb DEFAULT '{}'::jsonb NOT NULL,
    image_digest text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    build_url text,
    run_id text,
    run_number text,
    pr_number text,
    pr_target_branch text,
    tag text,
    expected_uploads integer,
    received_uploads integer DEFAULT 0 NOT NULL,
    run_attempt text,
    pinned boolean DEFAULT false NOT NULL,
    retention_hold boolean DEFAULT false NOT NULL,
    artifact_bytes bigint DEFAULT 0 NOT NULL,
    artifact_processing_claimed_by text,
    artifact_processing_claim_expires_at timestamp with time zone,
    artifact_processing_started_at timestamp with time zone,
    artifact_processing_finished_at timestamp with time zone,
    artifact_processing_attempts integer DEFAULT 0 NOT NULL,
    artifact_processing_last_error text,
    org_id uuid NOT NULL,
    repo_id uuid NOT NULL
);


--
-- Name: team_members; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE team_members (
    team_id uuid NOT NULL,
    user_id uuid NOT NULL,
    role member_role NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: teams; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE teams (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    org_id uuid NOT NULL,
    name text NOT NULL,
    slug text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: test_cases; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE test_cases (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    test_report_id uuid NOT NULL,
    suite text DEFAULT ''::text NOT NULL,
    name text NOT NULL,
    classname text DEFAULT ''::text NOT NULL,
    status text NOT NULL,
    duration_seconds double precision DEFAULT 0 NOT NULL,
    message text DEFAULT ''::text NOT NULL,
    file_path text DEFAULT ''::text NOT NULL,
    CONSTRAINT test_cases_status_check CHECK ((status = ANY (ARRAY['passed'::text, 'failed'::text, 'skipped'::text, 'error'::text])))
);


--
-- Name: test_reports; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE test_reports (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    snapshot_id uuid NOT NULL,
    format text NOT NULL,
    total integer DEFAULT 0 NOT NULL,
    passed integer DEFAULT 0 NOT NULL,
    failed integer DEFAULT 0 NOT NULL,
    skipped integer DEFAULT 0 NOT NULL,
    errors integer DEFAULT 0 NOT NULL,
    duration_seconds double precision DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    source text DEFAULT ''::text NOT NULL
);


--
-- Name: user_repo_access; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE user_repo_access (
    user_id uuid NOT NULL,
    repo_id uuid NOT NULL,
    role member_role NOT NULL,
    source text DEFAULT 'forge'::text NOT NULL,
    synced_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT user_repo_access_source_check CHECK ((source = ANY (ARRAY['forge'::text, 'invite'::text])))
);


--
-- Name: users; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE users (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    email text NOT NULL,
    display_name text NOT NULL,
    avatar_url text,
    provider text NOT NULL,
    provider_id text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: vex_statements; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE vex_statements (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    org_id uuid NOT NULL,
    advisory_id uuid NOT NULL,
    repo_id uuid,
    component_purl text,
    status vex_status NOT NULL,
    justification vex_justification,
    impact_statement text DEFAULT ''::text NOT NULL,
    action_statement text DEFAULT ''::text NOT NULL,
    source vex_source DEFAULT 'manual'::vex_source NOT NULL,
    source_document_url text DEFAULT ''::text NOT NULL,
    supplier text DEFAULT ''::text NOT NULL,
    created_by uuid,
    expires_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT vex_justification_required CHECK (((status <> 'not_affected'::vex_status) OR (justification IS NOT NULL))),
    CONSTRAINT vex_scope_valid CHECK (((component_purl IS NULL) OR (repo_id IS NOT NULL)))
);


--
-- Name: vulnerabilities; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE vulnerabilities (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    type vulnerability_type NOT NULL,
    snapshot_id uuid NOT NULL,
    title text DEFAULT ''::text NOT NULL,
    description text DEFAULT ''::text NOT NULL,
    original_severity severity_level NOT NULL,
    severity severity_level NOT NULL,
    severity_override_reason text,
    severity_override_by uuid,
    status vulnerability_status DEFAULT 'detected'::vulnerability_status NOT NULL,
    dismissal_reason dismissal_reason,
    state_comment text,
    detected_at timestamp with time zone DEFAULT now() NOT NULL,
    confirmed_at timestamp with time zone,
    confirmed_by uuid,
    dismissed_at timestamp with time zone,
    dismissed_by uuid,
    resolved_at timestamp with time zone,
    resolved_by uuid,
    scanner_name text DEFAULT ''::text NOT NULL,
    scanner_vendor text DEFAULT ''::text NOT NULL,
    scanner_version text DEFAULT ''::text NOT NULL,
    scanner_external_id text DEFAULT ''::text NOT NULL,
    file_path text,
    start_line integer,
    end_line integer,
    location_hash text,
    fingerprint text NOT NULL,
    component_id uuid,
    component_name text,
    component_version text,
    component_purl text,
    ecosystem text,
    advisory_id uuid,
    affected_range_id uuid,
    language text,
    confidence text,
    solution text,
    has_remediation boolean DEFAULT false NOT NULL,
    remediation_link text,
    reachability reachability,
    owasp_top_10 text,
    due_date date,
    present_on_default_branch boolean DEFAULT true NOT NULL,
    resolved_on_default_branch boolean DEFAULT false NOT NULL,
    secret_type text,
    secret_hash text,
    commit_sha text,
    author_email text,
    verified boolean,
    created_by uuid,
    metadata jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    first_seen_at timestamp with time zone DEFAULT now() NOT NULL,
    last_seen_at timestamp with time zone DEFAULT now() NOT NULL,
    severity_rank smallint GENERATED ALWAYS AS (
CASE severity
    WHEN 'critical'::severity_level THEN 5
    WHEN 'high'::severity_level THEN 4
    WHEN 'medium'::severity_level THEN 3
    WHEN 'low'::severity_level THEN 2
    WHEN 'info'::severity_level THEN 1
    ELSE 0
END) STORED,
    rule_ref_id uuid,
    primary_identifier_kind text DEFAULT ''::text NOT NULL,
    primary_identifier_value text DEFAULT ''::text NOT NULL,
    org_id uuid NOT NULL,
    repo_id uuid NOT NULL,
    CONSTRAINT vulnerabilities_line_bounds_check CHECK (((start_line IS NULL) OR (start_line > 0))),
    CONSTRAINT vulnerabilities_line_range_check CHECK (((end_line IS NULL) OR (start_line IS NULL) OR (end_line >= start_line))),
    CONSTRAINT vulnerabilities_manual_created_by CHECK (((type <> 'manual'::vulnerability_type) OR (created_by IS NOT NULL)))
);


--
-- Name: vulnerability_external_issues; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE vulnerability_external_issues (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    vulnerability_id uuid NOT NULL,
    tracker_type text NOT NULL,
    external_id text NOT NULL,
    url text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: vulnerability_state_transitions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE vulnerability_state_transitions (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    vulnerability_id uuid NOT NULL,
    state vulnerability_status NOT NULL,
    changed_by uuid,
    changed_at timestamp with time zone DEFAULT now() NOT NULL,
    comment text DEFAULT ''::text NOT NULL
);


--
-- Name: casbin_rules id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY casbin_rules ALTER COLUMN id SET DEFAULT nextval('casbin_rules_id_seq'::regclass);


--
-- Name: advisories advisories_canonical_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY advisories
    ADD CONSTRAINT advisories_canonical_id_key UNIQUE (canonical_id);


--
-- Name: advisories advisories_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY advisories
    ADD CONSTRAINT advisories_pkey PRIMARY KEY (id);


--
-- Name: advisory_aliases advisory_aliases_alias_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY advisory_aliases
    ADD CONSTRAINT advisory_aliases_alias_key UNIQUE (alias);


--
-- Name: advisory_aliases advisory_aliases_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY advisory_aliases
    ADD CONSTRAINT advisory_aliases_pkey PRIMARY KEY (id);


--
-- Name: advisory_cache advisory_cache_package_provider_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY advisory_cache
    ADD CONSTRAINT advisory_cache_package_provider_key UNIQUE (ecosystem, package_name, provider);


--
-- Name: advisory_cache advisory_cache_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY advisory_cache
    ADD CONSTRAINT advisory_cache_pkey PRIMARY KEY (id);


--
-- Name: advisory_sources advisory_sources_advisory_provider_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY advisory_sources
    ADD CONSTRAINT advisory_sources_advisory_provider_key UNIQUE (advisory_id, provider);


--
-- Name: advisory_sources advisory_sources_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY advisory_sources
    ADD CONSTRAINT advisory_sources_pkey PRIMARY KEY (id);


--
-- Name: affected_ranges affected_ranges_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY affected_ranges
    ADD CONSTRAINT affected_ranges_pkey PRIMARY KEY (id);


--
-- Name: api_keys api_keys_key_hash_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY api_keys
    ADD CONSTRAINT api_keys_key_hash_key UNIQUE (key_hash);


--
-- Name: api_keys api_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY api_keys
    ADD CONSTRAINT api_keys_pkey PRIMARY KEY (id);


--
-- Name: audit_logs audit_logs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY audit_logs
    ADD CONSTRAINT audit_logs_pkey PRIMARY KEY (id);


--
-- Name: casbin_rules casbin_rules_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY casbin_rules
    ADD CONSTRAINT casbin_rules_pkey PRIMARY KEY (id);


--
-- Name: clients clients_org_slug_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY clients
    ADD CONSTRAINT clients_org_slug_key UNIQUE (org_id, slug);


--
-- Name: clients clients_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY clients
    ADD CONSTRAINT clients_pkey PRIMARY KEY (id);


--
-- Name: component_dependencies component_dependencies_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY component_dependencies
    ADD CONSTRAINT component_dependencies_pkey PRIMARY KEY (id);


--
-- Name: component_dependencies component_dependencies_unique; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY component_dependencies
    ADD CONSTRAINT component_dependencies_unique UNIQUE (snapshot_id, component_id, depends_on_component_id);


--
-- Name: components components_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY components
    ADD CONSTRAINT components_pkey PRIMARY KEY (id);


--
-- Name: components components_purl_version_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY components
    ADD CONSTRAINT components_purl_version_key UNIQUE (purl, version);


--
-- Name: coverage_files coverage_files_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY coverage_files
    ADD CONSTRAINT coverage_files_pkey PRIMARY KEY (id);


--
-- Name: coverage_files coverage_files_report_path_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY coverage_files
    ADD CONSTRAINT coverage_files_report_path_key UNIQUE (coverage_report_id, file_path);


--
-- Name: coverage_lines coverage_lines_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY coverage_lines
    ADD CONSTRAINT coverage_lines_pkey PRIMARY KEY (coverage_file_id, line_number);


--
-- Name: coverage_reports coverage_reports_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY coverage_reports
    ADD CONSTRAINT coverage_reports_pkey PRIMARY KEY (id);


--
-- Name: coverage_reports coverage_reports_snapshot_format_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY coverage_reports
    ADD CONSTRAINT coverage_reports_snapshot_format_key UNIQUE (snapshot_id, format);


--
-- Name: deployments deployments_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY deployments
    ADD CONSTRAINT deployments_pkey PRIMARY KEY (id);


--
-- Name: forge_org_admins forge_org_admins_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY forge_org_admins
    ADD CONSTRAINT forge_org_admins_pkey PRIMARY KEY (id);


--
-- Name: forge_repositories forge_repositories_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY forge_repositories
    ADD CONSTRAINT forge_repositories_pkey PRIMARY KEY (id);


--
-- Name: integrations integrations_org_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY integrations
    ADD CONSTRAINT integrations_org_name_key UNIQUE (org_id, name);


--
-- Name: integrations integrations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY integrations
    ADD CONSTRAINT integrations_pkey PRIMARY KEY (id);


--
-- Name: license_exceptions license_exceptions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY license_exceptions
    ADD CONSTRAINT license_exceptions_pkey PRIMARY KEY (id);


--
-- Name: license_policies license_policies_org_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY license_policies
    ADD CONSTRAINT license_policies_org_name_key UNIQUE (org_id, name);


--
-- Name: license_policies license_policies_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY license_policies
    ADD CONSTRAINT license_policies_pkey PRIMARY KEY (id);


--
-- Name: notification_rules notification_rules_org_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY notification_rules
    ADD CONSTRAINT notification_rules_org_name_key UNIQUE (org_id, name);


--
-- Name: notification_rules notification_rules_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY notification_rules
    ADD CONSTRAINT notification_rules_pkey PRIMARY KEY (id);


--
-- Name: notifications notifications_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY notifications
    ADD CONSTRAINT notifications_pkey PRIMARY KEY (id);


--
-- Name: org_members org_members_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY org_members
    ADD CONSTRAINT org_members_pkey PRIMARY KEY (org_id, user_id);


--
-- Name: organizations organizations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY organizations
    ADD CONSTRAINT organizations_pkey PRIMARY KEY (id);


--
-- Name: organizations organizations_provider_slug_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY organizations
    ADD CONSTRAINT organizations_provider_slug_key UNIQUE (provider, slug);


--
-- Name: pr_checks pr_checks_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY pr_checks
    ADD CONSTRAINT pr_checks_key UNIQUE (repo_id, head_sha, context);


--
-- Name: pr_checks pr_checks_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY pr_checks
    ADD CONSTRAINT pr_checks_pkey PRIMARY KEY (id);


--
-- Name: quality_gates quality_gates_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY quality_gates
    ADD CONSTRAINT quality_gates_pkey PRIMARY KEY (id);


--
-- Name: refs refs_id_repo_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY refs
    ADD CONSTRAINT refs_id_repo_id_key UNIQUE (id, repo_id);


--
-- Name: refs refs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY refs
    ADD CONSTRAINT refs_pkey PRIMARY KEY (id);


--
-- Name: refs refs_repo_identity_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY refs
    ADD CONSTRAINT refs_repo_identity_key UNIQUE (repo_id, name, ref_type);


--
-- Name: releases releases_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY releases
    ADD CONSTRAINT releases_pkey PRIMARY KEY (id);


--
-- Name: releases releases_repo_version_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY releases
    ADD CONSTRAINT releases_repo_version_key UNIQUE (repo_id, version);


--
-- Name: repositories repositories_org_slug_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY repositories
    ADD CONSTRAINT repositories_org_slug_key UNIQUE (org_id, slug);


--
-- Name: repositories repositories_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY repositories
    ADD CONSTRAINT repositories_pkey PRIMARY KEY (id);


--
-- Name: repositories repositories_provider_identity_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY repositories
    ADD CONSTRAINT repositories_provider_identity_key UNIQUE (org_id, provider, provider_id);


--
-- Name: scan_providers scan_providers_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY scan_providers
    ADD CONSTRAINT scan_providers_pkey PRIMARY KEY (id);


--
-- Name: scan_providers scan_providers_scan_provider_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY scan_providers
    ADD CONSTRAINT scan_providers_scan_provider_key UNIQUE (scan_id, provider);


--
-- Name: scan_rules scan_rules_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY scan_rules
    ADD CONSTRAINT scan_rules_pkey PRIMARY KEY (id);


--
-- Name: scan_rules scan_rules_tool_rule_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY scan_rules
    ADD CONSTRAINT scan_rules_tool_rule_key UNIQUE (tool, rule_id);


--
-- Name: scans scans_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY scans
    ADD CONSTRAINT scans_pkey PRIMARY KEY (id);


--
-- Name: snapshot_artifacts snapshot_artifacts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY snapshot_artifacts
    ADD CONSTRAINT snapshot_artifacts_pkey PRIMARY KEY (id);


--
-- Name: snapshot_components snapshot_components_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY snapshot_components
    ADD CONSTRAINT snapshot_components_pkey PRIMARY KEY (snapshot_id, component_id);


--
-- Name: snapshot_dependency_roots snapshot_dependency_roots_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY snapshot_dependency_roots
    ADD CONSTRAINT snapshot_dependency_roots_pkey PRIMARY KEY (snapshot_id);


--
-- Name: snapshot_vuln_rollup snapshot_vuln_rollup_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY snapshot_vuln_rollup
    ADD CONSTRAINT snapshot_vuln_rollup_pkey PRIMARY KEY (snapshot_id);


--
-- Name: snapshots snapshots_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY snapshots
    ADD CONSTRAINT snapshots_pkey PRIMARY KEY (id);


--
-- Name: team_members team_members_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY team_members
    ADD CONSTRAINT team_members_pkey PRIMARY KEY (team_id, user_id);


--
-- Name: teams teams_id_org_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY teams
    ADD CONSTRAINT teams_id_org_id_key UNIQUE (id, org_id);


--
-- Name: teams teams_org_slug_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY teams
    ADD CONSTRAINT teams_org_slug_key UNIQUE (org_id, slug);


--
-- Name: teams teams_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY teams
    ADD CONSTRAINT teams_pkey PRIMARY KEY (id);


--
-- Name: test_cases test_cases_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY test_cases
    ADD CONSTRAINT test_cases_pkey PRIMARY KEY (id);


--
-- Name: test_reports test_reports_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY test_reports
    ADD CONSTRAINT test_reports_pkey PRIMARY KEY (id);


--
-- Name: test_reports test_reports_snapshot_source_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY test_reports
    ADD CONSTRAINT test_reports_snapshot_source_key UNIQUE (snapshot_id, source);


--
-- Name: user_repo_access user_repo_access_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY user_repo_access
    ADD CONSTRAINT user_repo_access_pkey PRIMARY KEY (user_id, repo_id);


--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);


--
-- Name: users users_provider_identity_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY users
    ADD CONSTRAINT users_provider_identity_key UNIQUE (provider, provider_id);


--
-- Name: vex_statements vex_statements_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY vex_statements
    ADD CONSTRAINT vex_statements_pkey PRIMARY KEY (id);


--
-- Name: vulnerability_external_issues vuln_ext_issues_dedup; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY vulnerability_external_issues
    ADD CONSTRAINT vuln_ext_issues_dedup UNIQUE (vulnerability_id, tracker_type, external_id);


--
-- Name: vulnerabilities vulnerabilities_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY vulnerabilities
    ADD CONSTRAINT vulnerabilities_pkey PRIMARY KEY (id);


--
-- Name: vulnerabilities vulnerabilities_snapshot_dedup_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY vulnerabilities
    ADD CONSTRAINT vulnerabilities_snapshot_dedup_key UNIQUE (snapshot_id, type, fingerprint);


--
-- Name: vulnerability_external_issues vulnerability_external_issues_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY vulnerability_external_issues
    ADD CONSTRAINT vulnerability_external_issues_pkey PRIMARY KEY (id);


--
-- Name: vulnerability_state_transitions vulnerability_state_transitions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY vulnerability_state_transitions
    ADD CONSTRAINT vulnerability_state_transitions_pkey PRIMARY KEY (id);


--
-- Name: forge_org_admins_account_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX forge_org_admins_account_idx ON forge_org_admins USING btree (provider, account);


--
-- Name: forge_org_admins_identity_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX forge_org_admins_identity_key ON forge_org_admins USING btree (provider, account, provider_user_id);


--
-- Name: forge_org_admins_pending_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX forge_org_admins_pending_idx ON forge_org_admins USING btree (provider, provider_user_id) WHERE (granted = false);


--
-- Name: forge_repositories_provider_account_login_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX forge_repositories_provider_account_login_idx ON forge_repositories USING btree (provider, account_login);


--
-- Name: forge_repositories_provider_key_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX forge_repositories_provider_key_key ON forge_repositories USING btree (provider, provider_key);


--
-- Name: idx_advisories_canonical_id_trgm; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_advisories_canonical_id_trgm ON advisories USING gin (canonical_id gin_trgm_ops);


--
-- Name: idx_advisories_title_trgm; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_advisories_title_trgm ON advisories USING gin (title gin_trgm_ops);


--
-- Name: idx_advisory_aliases_advisory_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_advisory_aliases_advisory_id ON advisory_aliases USING btree (advisory_id);


--
-- Name: idx_advisory_cache_expires; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_advisory_cache_expires ON advisory_cache USING btree (expires_at);


--
-- Name: idx_affected_ranges_advisory_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_affected_ranges_advisory_id ON affected_ranges USING btree (advisory_id);


--
-- Name: idx_affected_ranges_package; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_affected_ranges_package ON affected_ranges USING btree (ecosystem, package_name);


--
-- Name: idx_api_keys_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_api_keys_user_id ON api_keys USING btree (user_id);


--
-- Name: idx_audit_logs_action; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_audit_logs_action ON audit_logs USING btree (action);


--
-- Name: idx_audit_logs_actor; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_audit_logs_actor ON audit_logs USING btree (actor_id);


--
-- Name: idx_audit_logs_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_audit_logs_created ON audit_logs USING btree (created_at);


--
-- Name: idx_audit_logs_created_brin; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_audit_logs_created_brin ON audit_logs USING brin (created_at);


--
-- Name: idx_audit_logs_org; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_audit_logs_org ON audit_logs USING btree (org_id);


--
-- Name: idx_audit_logs_resource; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_audit_logs_resource ON audit_logs USING btree (resource_type, resource_id);


--
-- Name: idx_casbin_rules_unique; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_casbin_rules_unique ON casbin_rules USING btree (ptype, v0, v1, v2, v3, v4, v5);


--
-- Name: idx_clients_name_trgm; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_clients_name_trgm ON clients USING gin (name gin_trgm_ops);


--
-- Name: idx_clients_org_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_clients_org_id ON clients USING btree (org_id);


--
-- Name: idx_component_dependencies_snapshot; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_component_dependencies_snapshot ON component_dependencies USING btree (snapshot_id);


--
-- Name: idx_components_licenses; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_components_licenses ON components USING gin (licenses);


--
-- Name: idx_components_name_trgm; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_components_name_trgm ON components USING gin (name gin_trgm_ops);


--
-- Name: idx_components_purl_trgm; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_components_purl_trgm ON components USING gin (purl gin_trgm_ops);


--
-- Name: idx_deployments_client_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_deployments_client_id ON deployments USING btree (client_id);


--
-- Name: idx_deployments_release_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_deployments_release_id ON deployments USING btree (release_id);


--
-- Name: idx_deployments_rollback_target_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_deployments_rollback_target_id ON deployments USING btree (rollback_target_id);


--
-- Name: idx_license_exceptions_policy_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_license_exceptions_policy_id ON license_exceptions USING btree (policy_id);


--
-- Name: idx_license_policies_org_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_license_policies_org_id ON license_policies USING btree (org_id);


--
-- Name: idx_notification_rules_event_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_notification_rules_event_type ON notification_rules USING btree (event_type);


--
-- Name: idx_notification_rules_org_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_notification_rules_org_id ON notification_rules USING btree (org_id);


--
-- Name: idx_notifications_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_notifications_user_id ON notifications USING btree (user_id);


--
-- Name: idx_notifications_user_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_notifications_user_status ON notifications USING btree (user_id, status);


--
-- Name: idx_org_members_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_org_members_user_id ON org_members USING btree (user_id);


--
-- Name: idx_pr_checks_ref; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_pr_checks_ref ON pr_checks USING btree (ref_id);


--
-- Name: idx_pr_checks_repo; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_pr_checks_repo ON pr_checks USING btree (repo_id);


--
-- Name: idx_pr_checks_unsynced; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_pr_checks_unsynced ON pr_checks USING btree (created_at) WHERE (forge_synced_at IS NULL);


--
-- Name: idx_quality_gates_org_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_quality_gates_org_id ON quality_gates USING btree (org_id);


--
-- Name: idx_quality_gates_repo_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_quality_gates_repo_id ON quality_gates USING btree (repo_id);


--
-- Name: idx_refs_merge_target_ref_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_refs_merge_target_ref_id ON refs USING btree (merge_target_ref_id);


--
-- Name: idx_refs_repo_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_refs_repo_id ON refs USING btree (repo_id);


--
-- Name: idx_releases_ref_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_releases_ref_id ON releases USING btree (ref_id);


--
-- Name: idx_releases_snapshot_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_releases_snapshot_id ON releases USING btree (snapshot_id);


--
-- Name: idx_repositories_org_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_repositories_org_id ON repositories USING btree (org_id);


--
-- Name: idx_repositories_team_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_repositories_team_id ON repositories USING btree (team_id);


--
-- Name: idx_scan_rules_cwe_ids; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_scan_rules_cwe_ids ON scan_rules USING gin (cwe_ids);


--
-- Name: idx_scans_snapshot_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_scans_snapshot_id ON scans USING btree (snapshot_id);


--
-- Name: idx_scans_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_scans_status ON scans USING btree (status);


--
-- Name: idx_snapshot_components_component_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_snapshot_components_component_id ON snapshot_components USING btree (component_id);


--
-- Name: idx_snapshot_components_labels; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_snapshot_components_labels ON snapshot_components USING gin (labels);


--
-- Name: idx_snapshots_artifact_processing_ready; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_snapshots_artifact_processing_ready ON snapshots USING btree (status, artifact_processing_finished_at, artifact_processing_claim_expires_at, created_at, id) WHERE (status = ANY (ARRAY['complete'::snapshot_status, 'failed'::snapshot_status]));


--
-- Name: idx_snapshots_commit_sha; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_snapshots_commit_sha ON snapshots USING btree (commit_sha);


--
-- Name: idx_snapshots_labels; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_snapshots_labels ON snapshots USING gin (labels);


--
-- Name: idx_snapshots_org_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_snapshots_org_id ON snapshots USING btree (org_id);


--
-- Name: idx_snapshots_ref_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_snapshots_ref_id ON snapshots USING btree (ref_id);


--
-- Name: idx_snapshots_repo_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_snapshots_repo_id ON snapshots USING btree (repo_id);


--
-- Name: idx_snapshots_status_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_snapshots_status_created ON snapshots USING btree (status, created_at);


--
-- Name: idx_team_members_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_team_members_user_id ON team_members USING btree (user_id);


--
-- Name: idx_teams_org_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_teams_org_id ON teams USING btree (org_id);


--
-- Name: idx_test_cases_report; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_test_cases_report ON test_cases USING btree (test_report_id);


--
-- Name: idx_test_cases_report_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_test_cases_report_status ON test_cases USING btree (test_report_id, status);


--
-- Name: idx_vex_statements_advisory_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_vex_statements_advisory_id ON vex_statements USING btree (advisory_id);


--
-- Name: idx_vex_statements_expires; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_vex_statements_expires ON vex_statements USING btree (expires_at) WHERE (expires_at IS NOT NULL);


--
-- Name: idx_vex_statements_org_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_vex_statements_org_id ON vex_statements USING btree (org_id);


--
-- Name: idx_vex_statements_repo_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_vex_statements_repo_id ON vex_statements USING btree (repo_id);


--
-- Name: idx_vex_statements_scope; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_vex_statements_scope ON vex_statements USING btree (org_id, advisory_id, COALESCE(repo_id, '00000000-0000-0000-0000-000000000000'::uuid), COALESCE(component_purl, ''::text));


--
-- Name: idx_vex_statements_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_vex_statements_status ON vex_statements USING btree (status);


--
-- Name: idx_vuln_external_issues_vuln_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_vuln_external_issues_vuln_id ON vulnerability_external_issues USING btree (vulnerability_id);


--
-- Name: idx_vuln_state_transitions_vuln_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_vuln_state_transitions_vuln_id ON vulnerability_state_transitions USING btree (vulnerability_id);


--
-- Name: idx_vulnerabilities_advisory_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_vulnerabilities_advisory_id ON vulnerabilities USING btree (advisory_id);


--
-- Name: idx_vulnerabilities_component_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_vulnerabilities_component_id ON vulnerabilities USING btree (component_id);


--
-- Name: idx_vulnerabilities_detected_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_vulnerabilities_detected_at ON vulnerabilities USING btree (detected_at DESC);


--
-- Name: idx_vulnerabilities_detected_brin; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_vulnerabilities_detected_brin ON vulnerabilities USING brin (detected_at);


--
-- Name: idx_vulnerabilities_fingerprint; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_vulnerabilities_fingerprint ON vulnerabilities USING btree (fingerprint);


--
-- Name: idx_vulnerabilities_org_sev_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_vulnerabilities_org_sev_status ON vulnerabilities USING btree (org_id, severity, status);


--
-- Name: idx_vulnerabilities_primary_ident; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_vulnerabilities_primary_ident ON vulnerabilities USING btree (primary_identifier_value);


--
-- Name: idx_vulnerabilities_primary_ident_trgm; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_vulnerabilities_primary_ident_trgm ON vulnerabilities USING gin (primary_identifier_value gin_trgm_ops);


--
-- Name: idx_vulnerabilities_repo_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_vulnerabilities_repo_id ON vulnerabilities USING btree (repo_id);


--
-- Name: idx_vulnerabilities_rule_ref; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_vulnerabilities_rule_ref ON vulnerabilities USING btree (rule_ref_id);


--
-- Name: idx_vulnerabilities_severity; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_vulnerabilities_severity ON vulnerabilities USING btree (severity);


--
-- Name: idx_vulnerabilities_snapshot_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_vulnerabilities_snapshot_id ON vulnerabilities USING btree (snapshot_id);


--
-- Name: idx_vulnerabilities_snapshot_sevrank; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_vulnerabilities_snapshot_sevrank ON vulnerabilities USING btree (snapshot_id, severity_rank DESC, detected_at DESC);


--
-- Name: idx_vulnerabilities_snapshot_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_vulnerabilities_snapshot_type ON vulnerabilities USING btree (snapshot_id, type);


--
-- Name: idx_vulnerabilities_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_vulnerabilities_status ON vulnerabilities USING btree (status);


--
-- Name: idx_vulnerabilities_title_trgm; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_vulnerabilities_title_trgm ON vulnerabilities USING gin (title gin_trgm_ops);


--
-- Name: idx_vulnerabilities_type_priority; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_vulnerabilities_type_priority ON vulnerabilities USING btree (snapshot_id, (
CASE
    WHEN (type = ANY (ARRAY['malware'::vulnerability_type, 'secret'::vulnerability_type])) THEN 0
    ELSE 1
END), detected_at DESC);


--
-- Name: idx_vulnerabilities_type_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_vulnerabilities_type_status ON vulnerabilities USING btree (type, status);


--
-- Name: org_members_org_id_source_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX org_members_org_id_source_idx ON org_members USING btree (org_id, source);


--
-- Name: snapshot_artifacts_snapshot_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX snapshot_artifacts_snapshot_id_idx ON snapshot_artifacts USING btree (snapshot_id);


--
-- Name: snapshots_build_identity_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX snapshots_build_identity_key ON snapshots USING btree (ref_id, commit_sha, COALESCE(run_id, ''::text), COALESCE(run_attempt, ''::text));


--
-- Name: user_repo_access_repo_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX user_repo_access_repo_id_idx ON user_repo_access USING btree (repo_id);


--
-- Name: user_repo_access_user_id_source_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX user_repo_access_user_id_source_idx ON user_repo_access USING btree (user_id, source);


--
-- Name: snapshots snapshots_set_tenant_trg; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER snapshots_set_tenant_trg BEFORE INSERT ON snapshots FOR EACH ROW EXECUTE FUNCTION snapshots_set_tenant();


--
-- Name: vulnerabilities vulnerabilities_set_tenant_trg; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER vulnerabilities_set_tenant_trg BEFORE INSERT ON vulnerabilities FOR EACH ROW EXECUTE FUNCTION vulnerabilities_set_tenant();


--
-- Name: advisory_aliases advisory_aliases_advisory_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY advisory_aliases
    ADD CONSTRAINT advisory_aliases_advisory_id_fkey FOREIGN KEY (advisory_id) REFERENCES advisories(id) ON DELETE CASCADE;


--
-- Name: advisory_sources advisory_sources_advisory_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY advisory_sources
    ADD CONSTRAINT advisory_sources_advisory_id_fkey FOREIGN KEY (advisory_id) REFERENCES advisories(id) ON DELETE CASCADE;


--
-- Name: affected_ranges affected_ranges_advisory_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY affected_ranges
    ADD CONSTRAINT affected_ranges_advisory_id_fkey FOREIGN KEY (advisory_id) REFERENCES advisories(id) ON DELETE CASCADE;


--
-- Name: api_keys api_keys_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY api_keys
    ADD CONSTRAINT api_keys_user_id_fkey FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;


--
-- Name: audit_logs audit_logs_actor_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY audit_logs
    ADD CONSTRAINT audit_logs_actor_id_fkey FOREIGN KEY (actor_id) REFERENCES users(id) ON DELETE SET NULL;


--
-- Name: audit_logs audit_logs_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY audit_logs
    ADD CONSTRAINT audit_logs_org_id_fkey FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE SET NULL;


--
-- Name: clients clients_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY clients
    ADD CONSTRAINT clients_org_id_fkey FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE;


--
-- Name: component_dependencies component_dependencies_component_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY component_dependencies
    ADD CONSTRAINT component_dependencies_component_id_fkey FOREIGN KEY (component_id) REFERENCES components(id) ON DELETE CASCADE;


--
-- Name: component_dependencies component_dependencies_depends_on_component_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY component_dependencies
    ADD CONSTRAINT component_dependencies_depends_on_component_id_fkey FOREIGN KEY (depends_on_component_id) REFERENCES components(id) ON DELETE CASCADE;


--
-- Name: component_dependencies component_dependencies_snapshot_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY component_dependencies
    ADD CONSTRAINT component_dependencies_snapshot_id_fkey FOREIGN KEY (snapshot_id) REFERENCES snapshots(id) ON DELETE CASCADE;


--
-- Name: coverage_files coverage_files_coverage_report_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY coverage_files
    ADD CONSTRAINT coverage_files_coverage_report_id_fkey FOREIGN KEY (coverage_report_id) REFERENCES coverage_reports(id) ON DELETE CASCADE;


--
-- Name: coverage_lines coverage_lines_coverage_file_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY coverage_lines
    ADD CONSTRAINT coverage_lines_coverage_file_id_fkey FOREIGN KEY (coverage_file_id) REFERENCES coverage_files(id) ON DELETE CASCADE;


--
-- Name: coverage_reports coverage_reports_snapshot_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY coverage_reports
    ADD CONSTRAINT coverage_reports_snapshot_id_fkey FOREIGN KEY (snapshot_id) REFERENCES snapshots(id) ON DELETE CASCADE;


--
-- Name: deployments deployments_client_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY deployments
    ADD CONSTRAINT deployments_client_id_fkey FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE;


--
-- Name: deployments deployments_release_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY deployments
    ADD CONSTRAINT deployments_release_id_fkey FOREIGN KEY (release_id) REFERENCES releases(id) ON DELETE CASCADE;


--
-- Name: deployments deployments_rollback_target_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY deployments
    ADD CONSTRAINT deployments_rollback_target_id_fkey FOREIGN KEY (rollback_target_id) REFERENCES deployments(id) ON DELETE SET NULL;


--
-- Name: forge_org_admins forge_org_admins_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY forge_org_admins
    ADD CONSTRAINT forge_org_admins_org_id_fkey FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE;


--
-- Name: integrations integrations_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY integrations
    ADD CONSTRAINT integrations_org_id_fkey FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE;


--
-- Name: license_exceptions license_exceptions_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY license_exceptions
    ADD CONSTRAINT license_exceptions_created_by_fkey FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL;


--
-- Name: license_exceptions license_exceptions_policy_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY license_exceptions
    ADD CONSTRAINT license_exceptions_policy_id_fkey FOREIGN KEY (policy_id) REFERENCES license_policies(id) ON DELETE CASCADE;


--
-- Name: license_policies license_policies_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY license_policies
    ADD CONSTRAINT license_policies_org_id_fkey FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE;


--
-- Name: notification_rules notification_rules_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY notification_rules
    ADD CONSTRAINT notification_rules_org_id_fkey FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE;


--
-- Name: notifications notifications_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY notifications
    ADD CONSTRAINT notifications_user_id_fkey FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;


--
-- Name: org_members org_members_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY org_members
    ADD CONSTRAINT org_members_org_id_fkey FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE;


--
-- Name: org_members org_members_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY org_members
    ADD CONSTRAINT org_members_user_id_fkey FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;


--
-- Name: pr_checks pr_checks_ref_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY pr_checks
    ADD CONSTRAINT pr_checks_ref_id_fkey FOREIGN KEY (ref_id) REFERENCES refs(id) ON DELETE SET NULL;


--
-- Name: pr_checks pr_checks_repo_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY pr_checks
    ADD CONSTRAINT pr_checks_repo_id_fkey FOREIGN KEY (repo_id) REFERENCES repositories(id) ON DELETE CASCADE;


--
-- Name: quality_gates quality_gates_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY quality_gates
    ADD CONSTRAINT quality_gates_org_id_fkey FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE;


--
-- Name: quality_gates quality_gates_repo_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY quality_gates
    ADD CONSTRAINT quality_gates_repo_id_fkey FOREIGN KEY (repo_id) REFERENCES repositories(id) ON DELETE CASCADE;


--
-- Name: refs refs_merge_target_repo_lineage_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY refs
    ADD CONSTRAINT refs_merge_target_repo_lineage_fkey FOREIGN KEY (merge_target_ref_id, repo_id) REFERENCES refs(id, repo_id) ON DELETE SET NULL (merge_target_ref_id);


--
-- Name: refs refs_repo_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY refs
    ADD CONSTRAINT refs_repo_id_fkey FOREIGN KEY (repo_id) REFERENCES repositories(id) ON DELETE CASCADE;


--
-- Name: releases releases_ref_repo_lineage_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY releases
    ADD CONSTRAINT releases_ref_repo_lineage_fkey FOREIGN KEY (ref_id, repo_id) REFERENCES refs(id, repo_id) ON DELETE RESTRICT;


--
-- Name: releases releases_repo_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY releases
    ADD CONSTRAINT releases_repo_id_fkey FOREIGN KEY (repo_id) REFERENCES repositories(id) ON DELETE CASCADE;


--
-- Name: releases releases_snapshot_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY releases
    ADD CONSTRAINT releases_snapshot_id_fkey FOREIGN KEY (snapshot_id) REFERENCES snapshots(id) ON DELETE SET NULL;


--
-- Name: repositories repositories_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY repositories
    ADD CONSTRAINT repositories_org_id_fkey FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE;


--
-- Name: repositories repositories_team_lineage_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY repositories
    ADD CONSTRAINT repositories_team_lineage_fkey FOREIGN KEY (team_id, org_id) REFERENCES teams(id, org_id) ON DELETE SET NULL (team_id);


--
-- Name: scan_providers scan_providers_scan_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY scan_providers
    ADD CONSTRAINT scan_providers_scan_id_fkey FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE;


--
-- Name: scans scans_snapshot_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY scans
    ADD CONSTRAINT scans_snapshot_id_fkey FOREIGN KEY (snapshot_id) REFERENCES snapshots(id) ON DELETE CASCADE;


--
-- Name: snapshot_artifacts snapshot_artifacts_snapshot_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY snapshot_artifacts
    ADD CONSTRAINT snapshot_artifacts_snapshot_id_fkey FOREIGN KEY (snapshot_id) REFERENCES snapshots(id) ON DELETE CASCADE;


--
-- Name: snapshot_components snapshot_components_component_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY snapshot_components
    ADD CONSTRAINT snapshot_components_component_id_fkey FOREIGN KEY (component_id) REFERENCES components(id) ON DELETE CASCADE;


--
-- Name: snapshot_components snapshot_components_snapshot_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY snapshot_components
    ADD CONSTRAINT snapshot_components_snapshot_id_fkey FOREIGN KEY (snapshot_id) REFERENCES snapshots(id) ON DELETE CASCADE;


--
-- Name: snapshot_dependency_roots snapshot_dependency_roots_component_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY snapshot_dependency_roots
    ADD CONSTRAINT snapshot_dependency_roots_component_id_fkey FOREIGN KEY (component_id) REFERENCES components(id) ON DELETE CASCADE;


--
-- Name: snapshot_dependency_roots snapshot_dependency_roots_snapshot_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY snapshot_dependency_roots
    ADD CONSTRAINT snapshot_dependency_roots_snapshot_id_fkey FOREIGN KEY (snapshot_id) REFERENCES snapshots(id) ON DELETE CASCADE;


--
-- Name: snapshot_vuln_rollup snapshot_vuln_rollup_snapshot_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY snapshot_vuln_rollup
    ADD CONSTRAINT snapshot_vuln_rollup_snapshot_id_fkey FOREIGN KEY (snapshot_id) REFERENCES snapshots(id) ON DELETE CASCADE;


--
-- Name: snapshots snapshots_org_fk; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY snapshots
    ADD CONSTRAINT snapshots_org_fk FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE;


--
-- Name: snapshots snapshots_ref_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY snapshots
    ADD CONSTRAINT snapshots_ref_id_fkey FOREIGN KEY (ref_id) REFERENCES refs(id) ON DELETE CASCADE;


--
-- Name: snapshots snapshots_repo_fk; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY snapshots
    ADD CONSTRAINT snapshots_repo_fk FOREIGN KEY (repo_id) REFERENCES repositories(id) ON DELETE CASCADE;


--
-- Name: team_members team_members_team_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY team_members
    ADD CONSTRAINT team_members_team_id_fkey FOREIGN KEY (team_id) REFERENCES teams(id) ON DELETE CASCADE;


--
-- Name: team_members team_members_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY team_members
    ADD CONSTRAINT team_members_user_id_fkey FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;


--
-- Name: teams teams_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY teams
    ADD CONSTRAINT teams_org_id_fkey FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE;


--
-- Name: test_cases test_cases_test_report_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY test_cases
    ADD CONSTRAINT test_cases_test_report_id_fkey FOREIGN KEY (test_report_id) REFERENCES test_reports(id) ON DELETE CASCADE;


--
-- Name: test_reports test_reports_snapshot_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY test_reports
    ADD CONSTRAINT test_reports_snapshot_id_fkey FOREIGN KEY (snapshot_id) REFERENCES snapshots(id) ON DELETE CASCADE;


--
-- Name: user_repo_access user_repo_access_repo_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY user_repo_access
    ADD CONSTRAINT user_repo_access_repo_id_fkey FOREIGN KEY (repo_id) REFERENCES repositories(id) ON DELETE CASCADE;


--
-- Name: user_repo_access user_repo_access_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY user_repo_access
    ADD CONSTRAINT user_repo_access_user_id_fkey FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;


--
-- Name: vex_statements vex_statements_advisory_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY vex_statements
    ADD CONSTRAINT vex_statements_advisory_id_fkey FOREIGN KEY (advisory_id) REFERENCES advisories(id) ON DELETE CASCADE;


--
-- Name: vex_statements vex_statements_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY vex_statements
    ADD CONSTRAINT vex_statements_created_by_fkey FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL;


--
-- Name: vex_statements vex_statements_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY vex_statements
    ADD CONSTRAINT vex_statements_org_id_fkey FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE;


--
-- Name: vex_statements vex_statements_repo_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY vex_statements
    ADD CONSTRAINT vex_statements_repo_id_fkey FOREIGN KEY (repo_id) REFERENCES repositories(id) ON DELETE CASCADE;


--
-- Name: vulnerabilities vulnerabilities_advisory_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY vulnerabilities
    ADD CONSTRAINT vulnerabilities_advisory_id_fkey FOREIGN KEY (advisory_id) REFERENCES advisories(id) ON DELETE SET NULL;


--
-- Name: vulnerabilities vulnerabilities_affected_range_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY vulnerabilities
    ADD CONSTRAINT vulnerabilities_affected_range_id_fkey FOREIGN KEY (affected_range_id) REFERENCES affected_ranges(id) ON DELETE SET NULL;


--
-- Name: vulnerabilities vulnerabilities_component_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY vulnerabilities
    ADD CONSTRAINT vulnerabilities_component_id_fkey FOREIGN KEY (component_id) REFERENCES components(id) ON DELETE SET NULL;


--
-- Name: vulnerabilities vulnerabilities_confirmed_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY vulnerabilities
    ADD CONSTRAINT vulnerabilities_confirmed_by_fkey FOREIGN KEY (confirmed_by) REFERENCES users(id) ON DELETE SET NULL;


--
-- Name: vulnerabilities vulnerabilities_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY vulnerabilities
    ADD CONSTRAINT vulnerabilities_created_by_fkey FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL;


--
-- Name: vulnerabilities vulnerabilities_dismissed_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY vulnerabilities
    ADD CONSTRAINT vulnerabilities_dismissed_by_fkey FOREIGN KEY (dismissed_by) REFERENCES users(id) ON DELETE SET NULL;


--
-- Name: vulnerabilities vulnerabilities_org_fk; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY vulnerabilities
    ADD CONSTRAINT vulnerabilities_org_fk FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE;


--
-- Name: vulnerabilities vulnerabilities_repo_fk; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY vulnerabilities
    ADD CONSTRAINT vulnerabilities_repo_fk FOREIGN KEY (repo_id) REFERENCES repositories(id) ON DELETE CASCADE;


--
-- Name: vulnerabilities vulnerabilities_resolved_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY vulnerabilities
    ADD CONSTRAINT vulnerabilities_resolved_by_fkey FOREIGN KEY (resolved_by) REFERENCES users(id) ON DELETE SET NULL;


--
-- Name: vulnerabilities vulnerabilities_rule_ref_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY vulnerabilities
    ADD CONSTRAINT vulnerabilities_rule_ref_id_fkey FOREIGN KEY (rule_ref_id) REFERENCES scan_rules(id) ON DELETE SET NULL;


--
-- Name: vulnerabilities vulnerabilities_severity_override_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY vulnerabilities
    ADD CONSTRAINT vulnerabilities_severity_override_by_fkey FOREIGN KEY (severity_override_by) REFERENCES users(id) ON DELETE SET NULL;


--
-- Name: vulnerabilities vulnerabilities_snapshot_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY vulnerabilities
    ADD CONSTRAINT vulnerabilities_snapshot_id_fkey FOREIGN KEY (snapshot_id) REFERENCES snapshots(id) ON DELETE CASCADE;


--
-- Name: vulnerability_external_issues vulnerability_external_issues_vulnerability_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY vulnerability_external_issues
    ADD CONSTRAINT vulnerability_external_issues_vulnerability_id_fkey FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(id) ON DELETE CASCADE;


--
-- Name: vulnerability_state_transitions vulnerability_state_transitions_changed_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY vulnerability_state_transitions
    ADD CONSTRAINT vulnerability_state_transitions_changed_by_fkey FOREIGN KEY (changed_by) REFERENCES users(id) ON DELETE SET NULL;


--
-- Name: vulnerability_state_transitions vulnerability_state_transitions_vulnerability_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY vulnerability_state_transitions
    ADD CONSTRAINT vulnerability_state_transitions_vulnerability_id_fkey FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(id) ON DELETE CASCADE;


--
-- PostgreSQL database dump complete
--


