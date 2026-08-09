-- Reference inventory a CI reachability analysis posts alongside its verdicts
-- (a few KB per snapshot). Kept so the DAILY ADVISORY SCAN can classify a
-- NEWLY PUBLISHED CVE on unchanged code immediately — without waiting for the
-- next CI run. One row per snapshot, replaced on re-analysis.
CREATE TABLE snapshot_code_refs (
    snapshot_id uuid PRIMARY KEY REFERENCES snapshots(id) ON DELETE CASCADE,
    -- Go: the reachable third-party symbols ("import/path.Func",
    -- "import/path.Type.Method") from the CI call-graph analysis. Lets a new
    -- Go advisory with declared vulnerable symbols get a SYMBOL-level verdict
    -- on frozen refs.
    go_symbols text[] NOT NULL DEFAULT '{}',
    -- Java packages the compiled app's bytecode references (class-level).
    java_packages text[] NOT NULL DEFAULT '{}',
    -- Rust crates the workspace source names / merely carries (crate-level).
    rust_referenced text[] NOT NULL DEFAULT '{}',
    rust_present text[] NOT NULL DEFAULT '{}',
    updated_at timestamptz NOT NULL DEFAULT now()
);
