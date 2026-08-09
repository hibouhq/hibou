DELETE FROM notification_dedup WHERE identifier <> '';
ALTER TABLE notification_dedup DROP CONSTRAINT notification_dedup_pkey;
ALTER TABLE notification_dedup DROP COLUMN identifier;
ALTER TABLE notification_dedup ADD PRIMARY KEY (event_type, repo_id);
