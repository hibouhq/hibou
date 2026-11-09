-- +goose Up
-- Incidents (ADR-053): an org-scoped object of a declared kind, opened by a
-- rule or by a person, whose actions are derived from data hibou holds, with
-- a timeline that is the register, deliveries recorded with the digest of
-- what was sent, and a closure that is computed.

ALTER TYPE integration_type ADD VALUE IF NOT EXISTS 'jira';
ALTER TYPE integration_type ADD VALUE IF NOT EXISTS 'github_issues';
ALTER TYPE integration_type ADD VALUE IF NOT EXISTS 'gitlab_issues';
ALTER TYPE integration_type ADD VALUE IF NOT EXISTS 'tracker_webhook';

-- Clients: several security contacts (§5); `contact_email` stays as the
-- general contact.
ALTER TABLE clients ADD COLUMN security_contacts jsonb NOT NULL DEFAULT '[]'::jsonb;
-- How notices reach the client (§5): channel and its parameters, with the
-- webhook secret sealed like integration secrets. Never returned unmasked.
ALTER TABLE clients ADD COLUMN delivery_config jsonb NOT NULL DEFAULT '{}'::jsonb;

-- Organisation settings: owner, default and locked rules, regimes, the
-- approval and acknowledgement switches (§1, §5, §"Before building").
CREATE TABLE incident_settings (
    org_id                   uuid PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
    owner_id                 uuid REFERENCES users(id) ON DELETE SET NULL,
    owner_team_id            uuid REFERENCES teams(id) ON DELETE SET NULL,
    default_rules            jsonb NOT NULL DEFAULT 'null'::jsonb, -- JSON null: the built-in defaults
    locked_rules             jsonb NOT NULL DEFAULT '[]'::jsonb,
    internal_targets         jsonb NOT NULL DEFAULT '{}'::jsonb,
    national_regimes         jsonb NOT NULL DEFAULT '[]'::jsonb,
    require_vex_approval     boolean NOT NULL DEFAULT false,
    require_notice_approval  boolean NOT NULL DEFAULT false,
    require_acknowledgement  boolean NOT NULL DEFAULT false,
    four_eyes                boolean NOT NULL DEFAULT false,
    due_soon_lead_minutes    integer NOT NULL DEFAULT 360,
    updated_by               uuid REFERENCES users(id) ON DELETE SET NULL,
    updated_at               timestamptz NOT NULL DEFAULT now()
);

-- The `incidents` section of a repository's .hibou.yaml, persisted each time
-- the file is read, so sweeps triggered by catalogue and advisory refreshes
-- do not call the forge once per repository.
CREATE TABLE repo_incident_config (
    repo_id   uuid PRIMARY KEY REFERENCES repositories(id) ON DELETE CASCADE,
    config    jsonb NOT NULL,
    loaded_at timestamptz NOT NULL DEFAULT now()
);

CREATE TYPE incident_state AS ENUM (
    'signal', 'assessing', 'reportable', 'not_reportable', 'confirmed', 'dismissed', 'closed', 'withdrawn'
);

CREATE TABLE incidents (
    id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id            uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    number            integer NOT NULL,
    repo_id           uuid REFERENCES repositories(id) ON DELETE RESTRICT,
    kind              text NOT NULL,
    regimes           text[] NOT NULL DEFAULT '{}',
    subject_type      text NOT NULL DEFAULT 'none',
    subject_id        text NOT NULL DEFAULT '',
    title             text NOT NULL,
    state             incident_state NOT NULL DEFAULT 'signal',
    priority          text NOT NULL DEFAULT 'P2',
    signal_source     text NOT NULL,
    trigger_rule      text,
    signal_at         timestamptz NOT NULL DEFAULT now(),
    aware_at          timestamptz,
    decision_reason   text,
    decision_step     text,
    decided_by        uuid REFERENCES users(id) ON DELETE SET NULL,
    decided_at        timestamptz,
    -- The decision survives closure, so a closed incident whose scope grows
    -- reopens into the state it was decided in (§3).
    decided_state     incident_state,
    proposed_decision jsonb NOT NULL DEFAULT 'null'::jsonb,
    fix_available_at  timestamptz,
    owner_id          uuid REFERENCES users(id) ON DELETE SET NULL,
    owner_team_id     uuid REFERENCES teams(id) ON DELETE SET NULL,
    due_at            timestamptz,
    -- A rule's `due` (policy breaches): the internal target the clock counts.
    target_seconds    bigint,
    merged_into       uuid REFERENCES incidents(id) ON DELETE SET NULL,
    closed_at         timestamptz,
    created_by        uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now(),
    UNIQUE (org_id, number),
    CONSTRAINT incident_priority_valid CHECK (priority IN ('P1', 'P2', 'P3')),
    -- A decision state carries its reason. Closure does not need one: an
    -- incident under internal targets only closes when its actions are
    -- done, decided or not (§7).
    CONSTRAINT incident_decision_recorded CHECK (state IN ('signal', 'assessing', 'withdrawn', 'closed') OR decision_reason IS NOT NULL)
);
-- One open incident per subject and product (§1).
CREATE UNIQUE INDEX incidents_open_subject ON incidents (org_id, COALESCE(repo_id, '00000000-0000-0000-0000-000000000000'::uuid), kind, subject_type, subject_id)
    WHERE state NOT IN ('closed', 'withdrawn') AND subject_type <> 'none';
CREATE INDEX incidents_org_state_idx ON incidents (org_id, state);
CREATE INDEX incidents_repo_idx ON incidents (repo_id);
CREATE INDEX incidents_subject_idx ON incidents (subject_type, subject_id);

CREATE TABLE incident_deadlines (
    incident_id uuid NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    regime      text NOT NULL,
    step        text NOT NULL,
    due_at      timestamptz NOT NULL,
    met_at      timestamptz,
    reference   text NOT NULL DEFAULT '',
    notified    text NOT NULL DEFAULT '',                  -- '' | due_soon | overdue: what the ticker already sent
    PRIMARY KEY (incident_id, regime, step)
);
CREATE INDEX incident_deadlines_open_idx ON incident_deadlines (due_at) WHERE met_at IS NULL;

CREATE TABLE incident_scope (
    incident_id      uuid NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    subject_type     text NOT NULL,
    subject_id       text NOT NULL,
    label            text NOT NULL DEFAULT '',
    status           text NOT NULL DEFAULT 'pending',
    reason           text NOT NULL DEFAULT '',
    component_purl   text NOT NULL DEFAULT '',
    vex_statement_id uuid REFERENCES vex_statements(id) ON DELETE SET NULL,
    reachability     text,
    manual           boolean NOT NULL DEFAULT false,
    decided_by       uuid REFERENCES users(id) ON DELETE SET NULL,
    decided_at       timestamptz,
    updated_at       timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (incident_id, subject_type, subject_id),
    CONSTRAINT incident_scope_status_valid CHECK (status IN ('pending', 'affected', 'not_affected', 'fixed', 'under_investigation', 'unknown', 'excluded', 'not_matched', 'present', 'absent'))
);

CREATE TABLE incident_actions (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id   uuid NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    kind          text NOT NULL,
    subject_type  text NOT NULL DEFAULT '',
    subject_id    text NOT NULL DEFAULT '',
    label         text NOT NULL DEFAULT '',
    automatic     boolean NOT NULL DEFAULT false,
    -- Optional actions are tracked but never hold closure (hygiene such as
    -- removing a revoked secret from history).
    optional      boolean NOT NULL DEFAULT false,
    obsolete      boolean NOT NULL DEFAULT false,
    due_at        timestamptz,
    state         text NOT NULL DEFAULT 'pending',
    assignee_id   uuid REFERENCES users(id) ON DELETE SET NULL,
    done_at       timestamptz,
    done_by       uuid REFERENCES users(id) ON DELETE SET NULL,
    evidence      jsonb NOT NULL DEFAULT '{}'::jsonb,
    waived_by     uuid REFERENCES users(id) ON DELETE SET NULL,
    waived_reason text,
    created_at    timestamptz NOT NULL DEFAULT now(),
    UNIQUE (incident_id, kind, subject_type, subject_id),
    CONSTRAINT incident_action_state_valid CHECK (state IN ('pending', 'done', 'waived')),
    CONSTRAINT incident_action_waiver_reasoned CHECK (state <> 'waived' OR waived_reason IS NOT NULL)
);
CREATE INDEX incident_actions_assignee_idx ON incident_actions (assignee_id) WHERE state = 'pending';

-- Documents are content-addressed and immutable: the bytes live in the object
-- store under their digest; the inputs they were rendered from are kept so
-- `verify` can re-render and compare (§5).
CREATE TABLE incident_documents (
    sha256       text PRIMARY KEY,
    org_id       uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    kind         text NOT NULL,
    content_type text NOT NULL,
    size_bytes   bigint NOT NULL,
    object_key   text NOT NULL,
    -- The bytes themselves when the instance has no artifact store.
    content      bytea,
    renderer     text NOT NULL,
    inputs       jsonb NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE incident_deliveries (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id     uuid NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    client_id       uuid REFERENCES clients(id) ON DELETE RESTRICT,
    action_id       uuid REFERENCES incident_actions(id) ON DELETE SET NULL,
    channel         text NOT NULL,
    recipient       text NOT NULL,
    documents       jsonb NOT NULL,
    approved_by     uuid REFERENCES users(id) ON DELETE SET NULL,
    approved_at     timestamptz,
    status          text NOT NULL,
    error           text NOT NULL DEFAULT '',
    provider_ref    text NOT NULL DEFAULT '',
    created_by      uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    sent_at         timestamptz,
    acknowledged_at timestamptz,
    ack_evidence    jsonb NOT NULL DEFAULT '{}'::jsonb,
    audit_log_id    uuid,
    CONSTRAINT incident_delivery_channel_valid CHECK (channel IN ('email', 'webhook', 'portal', 'manual')),
    CONSTRAINT incident_delivery_status_valid CHECK (status IN ('pending_approval', 'sent', 'failed', 'acknowledged'))
);
CREATE INDEX incident_deliveries_incident_idx ON incident_deliveries (incident_id);
CREATE INDEX incident_deliveries_client_idx ON incident_deliveries (client_id);

CREATE TABLE incident_events (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id uuid NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    at          timestamptz NOT NULL DEFAULT now(),
    actor_id    uuid,
    actor_type  text NOT NULL DEFAULT 'user',
    actor_display text NOT NULL DEFAULT '',
    kind        text NOT NULL,
    detail      jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX incident_events_incident_idx ON incident_events (incident_id, at);

-- Tracker mirror (§8): one link per incident and tracker integration.
CREATE TABLE incident_tracker_links (
    incident_id    uuid NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    integration_id uuid NOT NULL REFERENCES integrations(id) ON DELETE CASCADE,
    external_key   text NOT NULL DEFAULT '',
    external_url   text NOT NULL DEFAULT '',
    synced_events  integer NOT NULL DEFAULT 0,
    last_synced_at timestamptz,
    last_error     text NOT NULL DEFAULT '',
    PRIMARY KEY (incident_id, integration_id)
);
CREATE INDEX incident_tracker_links_key_idx ON incident_tracker_links (integration_id, external_key);

-- Secret revocation checklist (ADR-053 §4, amending ADR-023): what the
-- person attesting a leaked credential's revocation recorded. The latest row
-- per finding is the current attestation; earlier rows stay as history.
CREATE TABLE secret_attestations (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    repo_id        uuid NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    fingerprint    text NOT NULL,
    revoked        boolean NOT NULL DEFAULT false,
    revoked_where  text NOT NULL DEFAULT '',
    revoked_by     text NOT NULL DEFAULT '',
    reference      text NOT NULL DEFAULT '',
    rotation       text NOT NULL DEFAULT '',                -- '' | rotated | not_needed
    rotation_note  text NOT NULL DEFAULT '',
    exposure       text NOT NULL DEFAULT '',                -- '' | assessed
    exposure_note  text NOT NULL DEFAULT '',
    owner_external boolean NOT NULL DEFAULT false,
    note           text NOT NULL DEFAULT '',
    attested_by    uuid REFERENCES users(id) ON DELETE SET NULL,
    attested_at    timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT secret_attestation_rotation_valid CHECK (rotation IN ('', 'rotated', 'not_needed')),
    CONSTRAINT secret_attestation_rotation_reasoned CHECK (rotation <> 'not_needed' OR rotation_note <> '')
);
CREATE INDEX secret_attestations_finding_idx ON secret_attestations (repo_id, fingerprint, attested_at DESC);

-- Client portal (§5 `portal` channel): a token bound to one client that can
-- list and download that client's documents and nothing else.
CREATE TABLE client_portal_tokens (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id       uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    client_id    uuid NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    name         text NOT NULL,
    token_hash   text NOT NULL UNIQUE,
    created_by   uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    last_used_at timestamptz,
    revoked_at   timestamptz
);
CREATE INDEX client_portal_tokens_client_idx ON client_portal_tokens (client_id);
