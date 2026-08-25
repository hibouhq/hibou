-- ADR-028: watch products whose advisories may carry no package coordinates,
-- and let a person map them to packages once.
--
-- Coverage is per-advisory rather than per-product: one CVE for a product can
-- be curated upstream with package coordinates while the next carries only a
-- product name and a version range.
--
-- Nothing here changes advisories, advisory_aliases, advisory_sources,
-- affected_ranges or components. That is the central claim of the ADR: triage
-- does not add a matching lane, it adds a way to AUTHOR advisory data, which is
-- then written into affected_ranges through the existing ingest path with a
-- 'manual:<org>' source and picked up by the ordinary purl matcher.

-- ---------------------------------------------------------------------------
-- The local copy of the CVE list.
--
-- Stored as a projection, never as raw records: the published corpus is 3.14 GB
-- of JSON with a 23.4 MB outlier in it, while the fields below are ~0.9 KB per
-- record — about 340 MB for all ~382,000. Raw bytes for the handful of records
-- a triager actually opens live in object storage, not here.
-- ---------------------------------------------------------------------------
CREATE TABLE cve_records (
    cve_id text PRIMARY KEY,
    state text NOT NULL,
    assigner text DEFAULT ''::text NOT NULL,
    published_at timestamp with time zone,
    -- The CNA's own dateUpdated, NOT our ingest time. Revision detection is a
    -- comparison against the value a mapping was triaged at, so this must stay
    -- upstream's clock; first_seen_at below is ours.
    record_updated_at timestamp with time zone,
    first_seen_at timestamp with time zone DEFAULT now() NOT NULL,
    cvss_score numeric(4,2),
    cvss_vector text DEFAULT ''::text NOT NULL,
    severity text DEFAULT ''::text NOT NULL,
    cwe_ids text[] DEFAULT ARRAY[]::text[] NOT NULL,
    summary text DEFAULT ''::text NOT NULL,
    reference_urls text[] DEFAULT ARRAY[]::text[] NOT NULL,
    CONSTRAINT cve_records_score_range CHECK (
        cvss_score IS NULL OR (cvss_score >= 0 AND cvss_score <= 10))
);

-- Revision detection runs over every sweep ("what moved since I last looked"),
-- and 73% of a delta is revisions rather than new records, so this must be an
-- index scan.
CREATE INDEX cve_records_updated_idx ON cve_records (record_updated_at DESC);
CREATE INDEX cve_records_state_idx ON cve_records (state) WHERE state <> 'PUBLISHED';

-- ---------------------------------------------------------------------------
-- affected[] lifted out of the record.
--
-- Both the subscription matcher and the "which CVEs would this have caught?"
-- preview ask "which records name this product?". Left nested in JSON that is a
-- scan of the whole corpus; flattened it is an index lookup. Density measured
-- at ~2.6 ranges per product, so the full corpus is a few million narrow rows.
-- ---------------------------------------------------------------------------
CREATE TABLE cve_affected_products (
    id uuid DEFAULT gen_random_uuid() PRIMARY KEY,
    cve_id text NOT NULL REFERENCES cve_records(cve_id) ON DELETE CASCADE,
    -- The CNA's own spelling, for display.
    vendor text DEFAULT ''::text NOT NULL,
    product text NOT NULL,
    -- Casefolded, non-alphanumerics stripped. Matching and indexing use these;
    -- display never does. Vendor and product names are free text and differ
    -- between CNAs and sometimes within one.
    vendor_key text DEFAULT ''::text NOT NULL,
    product_key text NOT NULL,
    introduced text DEFAULT ''::text NOT NULL,
    -- Exactly one upper bound is set. last_affected is inclusive (the CNA's
    -- lessThanOrEqual); fixed is exclusive (lessThan). A range with neither was
    -- dropped at decode rather than widened to every future release.
    fixed text DEFAULT ''::text NOT NULL,
    last_affected text DEFAULT ''::text NOT NULL,
    CONSTRAINT cve_affected_products_bounded CHECK (fixed <> '' OR last_affected <> '')
);

CREATE INDEX cve_affected_products_product_key_idx ON cve_affected_products (product_key);
CREATE INDEX cve_affected_products_cve_idx ON cve_affected_products (cve_id);

-- ---------------------------------------------------------------------------
-- Subscriptions: the products we watch. Instance-wide, with no org column.
--
-- An earlier draft made scope a per-row choice. It has no deployment: on a
-- single-company instance every org is the same company, so org scope only
-- means watching Tomcat five times; on a multi-tenant instance one tenant
-- authoring for the others is a cross-tenant escalation, and that case is
-- served by advisories we curate centrally and ship as data instead. Supporting
-- both is what created the escalation path rather than defending against it.
-- ---------------------------------------------------------------------------
CREATE TABLE cve_subscriptions (
    id uuid DEFAULT gen_random_uuid() PRIMARY KEY,
    label text NOT NULL,
    -- An alias SET, not one name: the vendor/product boundary moves between
    -- records, so a product may need several keys to be caught reliably.
    product_keys text[] NOT NULL,
    -- Optional narrowing only. Never required, and never the assigner, which
    -- names the CNA rather than the vendor — one third-party CNA files for
    -- dozens of unrelated vendors.
    vendor_keys text[] DEFAULT ARRAY[]::text[] NOT NULL,
    created_by uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    last_matched_at timestamp with time zone,
    CONSTRAINT cve_subscriptions_keys_present CHECK (cardinality(product_keys) > 0)
);

CREATE INDEX cve_subscriptions_product_keys_idx ON cve_subscriptions USING gin (product_keys);

-- ---------------------------------------------------------------------------
-- The queue. One row per (subscription, CVE) awaiting or holding a decision.
-- ---------------------------------------------------------------------------
CREATE TABLE cve_triage_items (
    id uuid DEFAULT gen_random_uuid() PRIMARY KEY,
    subscription_id uuid NOT NULL REFERENCES cve_subscriptions(id) ON DELETE CASCADE,
    cve_id text NOT NULL REFERENCES cve_records(cve_id) ON DELETE CASCADE,
    -- The record's dateUpdated when this item was last decided. A later value
    -- upstream means the CNA revised the record after we triaged it, which
    -- re-opens the item rather than silently leaving a stale mapping standing.
    triaged_record_updated_at timestamp with time zone,
    state text DEFAULT 'pending'::text NOT NULL,
    decided_by uuid REFERENCES users(id) ON DELETE SET NULL,
    decided_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    UNIQUE (subscription_id, cve_id),
    CONSTRAINT cve_triage_items_state CHECK (state IN ('pending', 'mapped', 'dismissed', 'reopened'))
);

CREATE INDEX cve_triage_items_pending_idx ON cve_triage_items (created_at)
    WHERE state IN ('pending', 'reopened');

-- ---------------------------------------------------------------------------
-- The durable artefact: product -> packages, reusable for every future CVE of
-- that product. This is what makes the effort per product rather than per CVE.
-- ---------------------------------------------------------------------------
CREATE TABLE product_package_mappings (
    id uuid DEFAULT gen_random_uuid() PRIMARY KEY,
    subscription_id uuid NOT NULL REFERENCES cve_subscriptions(id) ON DELETE CASCADE,
    -- [{"ecosystem": "Maven", "name": "group:artifact"}, …]
    packages jsonb NOT NULL,
    decided_from_cve text NOT NULL,
    decided_by uuid REFERENCES users(id) ON DELETE SET NULL,
    decided_at timestamp with time zone DEFAULT now() NOT NULL,
    -- Off by default: a mapping curated for one CVE may not hold for the next,
    -- because a later flaw in the same product can live in a different artifact.
    auto_apply boolean DEFAULT false NOT NULL,
    revoked_at timestamp with time zone
);

CREATE INDEX product_package_mappings_subscription_idx
    ON product_package_mappings (subscription_id) WHERE revoked_at IS NULL;

-- ---------------------------------------------------------------------------
-- Advisory timeline. Append-only, and it must carry BOTH what people did and
-- what changed upstream — a CVE triaged in July and revised by its CNA in
-- August has to show both, in order, or a triager cannot tell a typo fix from a
-- widened range.
--
-- Partitioned by month like audit_logs: it is append-only and always queried by
-- time, so expiry is a DROP PARTITION rather than a large DELETE. This is NOT
-- the audit log — that records who did what for compliance; this is a
-- user-facing narrative that includes activity nobody here caused.
-- ---------------------------------------------------------------------------
CREATE TABLE advisory_events (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    advisory_id uuid REFERENCES advisories(id) ON DELETE CASCADE,
    cve_id text DEFAULT ''::text NOT NULL,
    kind text NOT NULL,
    -- When it happened upstream, versus when we observed it. A CVE can be
    -- published weeks before this instance learns of it, and reporting our
    -- clock as the event time would hide exactly that gap.
    occurred_at timestamp with time zone NOT NULL,
    observed_at timestamp with time zone DEFAULT now() NOT NULL,
    actor_id uuid,
    detail jsonb DEFAULT '{}'::jsonb NOT NULL,
    PRIMARY KEY (id, occurred_at)
) PARTITION BY RANGE (occurred_at);

-- Safety net so a write can never fail for lack of a partition.
CREATE TABLE advisory_events_default PARTITION OF advisory_events DEFAULT;

DO $$
DECLARE
    month_start date := date_trunc('month', now())::date;
    part_start date;
BEGIN
    FOR offset_months IN 0..1 LOOP
        part_start := (month_start + make_interval(months => offset_months))::date;
        EXECUTE format(
            'CREATE TABLE %I PARTITION OF advisory_events FOR VALUES FROM (%L) TO (%L)',
            'advisory_events_p' || to_char(part_start, 'YYYYMM'),
            part_start,
            (part_start + interval '1 month')::date
        );
    END LOOP;
END $$;

CREATE INDEX advisory_events_cve_idx ON advisory_events (cve_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS advisory_events_kind_idx ON advisory_events (kind, occurred_at DESC);
