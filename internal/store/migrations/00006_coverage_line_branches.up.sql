-- Per-line branch counters so a line can render as PARTIALLY covered: executed
-- (hits > 0) but some conditions never took both outcomes
-- (branches_covered < branches_valid). branches_valid = 0 means the line has no
-- branch; formats without branch data (gocover) never set them.
ALTER TABLE coverage_lines
    ADD COLUMN branches_covered integer DEFAULT 0 NOT NULL,
    ADD COLUMN branches_valid integer DEFAULT 0 NOT NULL;
