-- Worker registry (ADR-025): every replica upserts one row keyed by its
-- artifact worker ID (hostname:pid:uuid, the same string written to the
-- claimed_by columns) and heartbeats it with self-reported resource usage.
-- Liveness is derived from last_heartbeat_at, never stored.
CREATE TABLE worker_instances (
    id text PRIMARY KEY,
    hostname text NOT NULL,
    pid integer NOT NULL,
    version text NOT NULL DEFAULT '',
    -- Background loops enabled on this replica, for role visibility
    -- (api-only vs worker vs combined).
    loops text[] NOT NULL DEFAULT '{}',
    started_at timestamp with time zone NOT NULL,
    last_heartbeat_at timestamp with time zone NOT NULL,
    -- Set on graceful shutdown; cleared if the same ID heartbeats again.
    stopped_at timestamp with time zone,
    -- Self-reported, process-level (not cgroup limits): CPU share since the
    -- previous heartbeat, resident set size, Go heap, goroutine count.
    cpu_percent real,
    memory_rss_bytes bigint,
    heap_alloc_bytes bigint,
    goroutines integer,
    gomaxprocs integer,
    active_jobs integer NOT NULL DEFAULT 0
);

CREATE INDEX idx_worker_instances_last_heartbeat ON worker_instances (last_heartbeat_at);
