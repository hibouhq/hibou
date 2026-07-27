-- Distro advisories (apk/deb/rpm) are only valid within one distribution
-- release: a fix lands in Alpine 3.18 and 3.19 at different package versions,
-- so a range without its release matches versions from other releases and
-- produces false positives. Empty means "not release-scoped" (all language
-- ecosystems).
ALTER TABLE affected_ranges ADD COLUMN release text DEFAULT ''::text NOT NULL;
