CREATE EXTENSION IF NOT EXISTS pg_trgm;

CREATE INDEX idx_advisories_canonical_id_trgm ON advisories USING gin (canonical_id gin_trgm_ops);
CREATE INDEX idx_advisories_title_trgm ON advisories USING gin (title gin_trgm_ops);
CREATE INDEX idx_components_name_trgm ON components USING gin (name gin_trgm_ops);
CREATE INDEX idx_components_purl_trgm ON components USING gin (purl gin_trgm_ops);
CREATE INDEX idx_findings_rule_id_trgm ON findings USING gin (rule_id gin_trgm_ops);
CREATE INDEX idx_findings_tool_trgm ON findings USING gin (tool gin_trgm_ops);
CREATE INDEX idx_findings_message_trgm ON findings USING gin (message gin_trgm_ops);
CREATE INDEX idx_clients_name_trgm ON clients USING gin (name gin_trgm_ops);
