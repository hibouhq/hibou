-- +goose Down
DROP TABLE client_portal_tokens;
DROP TABLE secret_attestations;
DROP TABLE incident_tracker_links;
DROP TABLE incident_events;
DROP TABLE incident_deliveries;
DROP TABLE incident_documents;
DROP TABLE incident_actions;
DROP TABLE incident_scope;
DROP TABLE incident_deadlines;
DROP TABLE incidents;
DROP TYPE incident_state;
DROP TABLE repo_incident_config;
DROP TABLE incident_settings;
ALTER TABLE clients DROP COLUMN delivery_config;
ALTER TABLE clients DROP COLUMN security_contacts;
-- integration_type values added here stay: PostgreSQL cannot drop an enum value.
