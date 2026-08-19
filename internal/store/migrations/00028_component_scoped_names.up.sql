-- CycloneDX splits scoped npm names into group + name and the parser dropped
-- the group, so scoped packages were stored (and matched against OSV) under
-- their bare name — fabricating malware matches on unscoped typosquats and
-- missing real advisories for the scoped package. The parser now derives the
-- name from the PURL; recover existing rows the same way.
-- The LIKE pattern escapes '%' so it matches the literal percent-encoded scope
-- prefix 'pkg:npm/%40' only ('pkg:npm/' is 8 characters). In a matching purl
-- the namespace's '@' is percent-encoded, so the first literal '@' always
-- separates name from version and the extracted name always starts with '@'.
UPDATE components
SET name = replace(split_part(substring(purl from 9), '@', 1), '%40', '@')
WHERE ecosystem = 'npm'
  AND purl LIKE 'pkg:npm/\%40%' ESCAPE '\'
  AND name NOT LIKE '@%';
