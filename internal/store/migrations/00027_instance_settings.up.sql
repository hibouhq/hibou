-- Instance-wide settings, keyed by name. First consumer: announcement banners
-- (key 'announcement_banners', value = JSON array of banner objects), editable
-- at runtime by instance admins.
CREATE TABLE instance_settings (
    key text PRIMARY KEY,
    value jsonb NOT NULL DEFAULT '{}'::jsonb,
    updated_at timestamptz NOT NULL DEFAULT now()
);
