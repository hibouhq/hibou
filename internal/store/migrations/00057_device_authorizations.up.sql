-- ADR-043: pending OAuth 2.0 device logins (RFC 8628). A row lives for the
-- ten minutes between `hibou login` asking for a code and the user approving
-- it in the browser. Codes are stored as SHA-256 hashes; the raw token is
-- minted at the successful poll and never stored here.
CREATE TABLE device_authorizations (
    id uuid DEFAULT gen_random_uuid() NOT NULL PRIMARY KEY,
    device_code_hash text NOT NULL,
    user_code_hash text NOT NULL,
    client_id text NOT NULL,
    client_name text NOT NULL DEFAULT '',
    requested_preset text NOT NULL,
    requester_ip text NOT NULL DEFAULT '',
    requester_user_agent text NOT NULL DEFAULT '',
    status text NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'approved', 'denied', 'consumed')),
    poll_interval_seconds integer NOT NULL DEFAULT 5,
    approved_by uuid REFERENCES users(id) ON DELETE CASCADE,
    approved_preset text,
    token_expires_at timestamp with time zone,
    api_key_id uuid REFERENCES api_keys(id) ON DELETE SET NULL,
    created_at timestamp with time zone NOT NULL DEFAULT now(),
    expires_at timestamp with time zone NOT NULL,
    decided_at timestamp with time zone,
    last_polled_at timestamp with time zone
);

CREATE UNIQUE INDEX device_authorizations_device_code_idx ON device_authorizations (device_code_hash);
-- A user code only has to be unique while someone can still type it in.
CREATE UNIQUE INDEX device_authorizations_live_user_code_idx ON device_authorizations (user_code_hash)
    WHERE status IN ('pending', 'approved');
CREATE INDEX device_authorizations_expires_idx ON device_authorizations (expires_at);
CREATE INDEX device_authorizations_pending_ip_idx ON device_authorizations (requester_ip)
    WHERE status = 'pending';
