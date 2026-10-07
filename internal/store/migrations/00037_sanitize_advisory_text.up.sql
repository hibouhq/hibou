-- One-time repair of advisory/finding text stored before ingest sanitized it
-- (PLAN §6): upstream feeds shipped HTML-entity-encoded titles, sometimes
-- truncated mid-entity ("…SHIFT_JISX0213 -&gt"), and they rendered literally
-- in every view and export. New writes are decoded at ingest
-- (internal/sanitize); this fixes what is already stored. Deliberately only
-- the entities seen in advisory prose — a general HTML decoder does not exist
-- in SQL and is not needed.
--
-- Order matters twice: terminated entities decode BEFORE their unterminated
-- stumps (or '&gt;' would be eaten as '&gt' + ';'), and '&amp;' decodes LAST
-- ('&amp;gt;' means a literal '&gt;'; decoding '&amp;' first would
-- double-decode it).
UPDATE advisories
SET title = btrim(regexp_replace(regexp_replace(
        replace(replace(replace(replace(replace(title,
            '&lt;', '<'), '&gt;', '>'), '&quot;', '"'), '&#39;', ''''), '&amp;', '&'),
        '&lt$', '<'), '&gt$', '>')),
    description = btrim(regexp_replace(regexp_replace(
        replace(replace(replace(replace(replace(description,
            '&lt;', '<'), '&gt;', '>'), '&quot;', '"'), '&#39;', ''''), '&amp;', '&'),
        '&lt$', '<'), '&gt$', '>'))
WHERE title LIKE '%&%' OR description LIKE '%&%';

UPDATE vulnerabilities
SET title = btrim(regexp_replace(regexp_replace(
        replace(replace(replace(replace(replace(title,
            '&lt;', '<'), '&gt;', '>'), '&quot;', '"'), '&#39;', ''''), '&amp;', '&'),
        '&lt$', '<'), '&gt$', '>')),
    description = btrim(regexp_replace(regexp_replace(
        replace(replace(replace(replace(replace(description,
            '&lt;', '<'), '&gt;', '>'), '&quot;', '"'), '&#39;', ''''), '&amp;', '&'),
        '&lt$', '<'), '&gt$', '>'))
WHERE title LIKE '%&%' OR description LIKE '%&%';
