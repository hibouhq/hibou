-- ADR-023: scanner-suppressed findings (SARIF suppressions[]) are an
-- observation state of their own — visible, never open, never a human
-- decision. Distinct from 'dismissed' (a human act in Hibou).
ALTER TYPE vulnerability_status ADD VALUE IF NOT EXISTS 'suppressed';
