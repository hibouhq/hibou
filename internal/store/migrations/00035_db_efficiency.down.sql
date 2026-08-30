ALTER TABLE cve_affected_products ADD COLUMN id uuid DEFAULT gen_random_uuid() NOT NULL;
ALTER TABLE cve_affected_products ADD CONSTRAINT cve_affected_products_pkey PRIMARY KEY (id);

CREATE INDEX idx_snapshot_components_labels ON snapshot_components USING gin (labels);

CREATE INDEX cve_records_updated_idx ON cve_records (record_updated_at);

DROP INDEX IF EXISTS cve_records_published_pub_idx;
