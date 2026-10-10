package storageusage

import (
	"sync/atomic"

	"github.com/prometheus/client_golang/prometheus"
)

// Labels never carry tenant data (ADR-039 §3): no org, repo, user, bucket,
// endpoint or object key. table and kind are schema/server-assigned names.
var (
	descSampleTimestamp = prometheus.NewDesc("hibou_storage_sample_timestamp_seconds",
		"Unix time the storage sample source was last collected.", []string{"source"}, nil)
	descSampleDuration = prometheus.NewDesc("hibou_storage_sample_duration_seconds",
		"Time spent collecting the storage sample source.", []string{"source"}, nil)
	descSampleSuccess = prometheus.NewDesc("hibou_storage_sample_success",
		"1 when the storage sample source was collected without error, 0 otherwise.", []string{"source"}, nil)

	descDBSize = prometheus.NewDesc("hibou_db_size_bytes",
		"Size of the hibou database.", nil, nil)
	descDBTableSize = prometheus.NewDesc("hibou_db_table_size_bytes",
		"Size of a public-schema table (part=table: heap+TOAST, part=index: its indexes); partitions are folded into their root.",
		[]string{"table", "part"}, nil)
	descDBTableRows = prometheus.NewDesc("hibou_db_table_rows",
		"Estimated live and dead tuples of a public-schema table.", []string{"table", "state"}, nil)
	descDBConnUsed = prometheus.NewDesc("hibou_db_connections_used",
		"Client backends connected to the Postgres server.", nil, nil)
	descDBConnMax = prometheus.NewDesc("hibou_db_connections_max",
		"Postgres max_connections.", nil, nil)
	descDBXIDAge = prometheus.NewDesc("hibou_db_xid_age",
		"Transaction-ID age of the database (wraparound forces a shutdown near 2^31).", nil, nil)
	descDBOldestTx = prometheus.NewDesc("hibou_db_oldest_transaction_seconds",
		"Age of the oldest open transaction visible to the hibou role.", nil, nil)
	descDBCacheHit = prometheus.NewDesc("hibou_db_cache_hit_ratio",
		"Share of block reads served from shared buffers since stats reset.", nil, nil)

	descLedgerObjects = prometheus.NewDesc("hibou_artifact_ledger_objects",
		"Artifacts hibou recorded as stored, by kind.", []string{"kind"}, nil)
	descLedgerBytes = prometheus.NewDesc("hibou_artifact_ledger_bytes",
		"Bytes hibou recorded as stored, by kind.", []string{"kind"}, nil)

	descBackendObjects = prometheus.NewDesc("hibou_artifact_backend_objects",
		"Objects present in the artifact backend (inventory scan).", nil, nil)
	descBackendBytes = prometheus.NewDesc("hibou_artifact_backend_bytes",
		"Bytes present in the artifact backend (inventory scan).", nil, nil)
	descBackendTruncated = prometheus.NewDesc("hibou_artifact_backend_scan_truncated",
		"1 when the inventory scan stopped at its object cap.", nil, nil)
	descVolumeCapacity = prometheus.NewDesc("hibou_artifact_volume_capacity_bytes",
		"Capacity of the filesystem volume holding artifacts.", nil, nil)
	descVolumeFree = prometheus.NewDesc("hibou_artifact_volume_free_bytes",
		"Free bytes available to hibou on the artifact volume.", nil, nil)
)

// Exporter renders the latest published Sample on each scrape. Being a
// custom collector, a table that disappears from the sample disappears from
// the output instead of lingering as a stale series.
type Exporter struct {
	current atomic.Pointer[Sample]
}

// Default is registered on the default Prometheus registry, alongside the
// counters in internal/metrics.
var Default = &Exporter{}

func init() {
	prometheus.MustRegister(Default)
}

// Publish replaces the sample served to scrapers.
func (e *Exporter) Publish(s *Sample) { e.current.Store(s) }

// Describe implements prometheus.Collector.
func (e *Exporter) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{
		descSampleTimestamp, descSampleDuration, descSampleSuccess,
		descDBSize, descDBTableSize, descDBTableRows, descDBConnUsed, descDBConnMax,
		descDBXIDAge, descDBOldestTx, descDBCacheHit,
		descLedgerObjects, descLedgerBytes,
		descBackendObjects, descBackendBytes, descBackendTruncated, descVolumeCapacity, descVolumeFree,
	} {
		ch <- d
	}
}

// Collect implements prometheus.Collector.
func (e *Exporter) Collect(ch chan<- prometheus.Metric) {
	s := e.current.Load()
	if s == nil {
		return
	}
	if p := s.Postgres; p != nil {
		section(ch, "postgres", p.Section)
		if p.OK() {
			gauge(ch, descDBSize, float64(p.DatabaseBytes))
			for _, t := range p.Tables {
				gauge(ch, descDBTableSize, float64(t.TableBytes), t.Name, "table")
				gauge(ch, descDBTableSize, float64(t.IndexBytes), t.Name, "index")
				gauge(ch, descDBTableRows, float64(t.LiveRows), t.Name, "live")
				gauge(ch, descDBTableRows, float64(t.DeadRows), t.Name, "dead")
			}
			gauge(ch, descDBConnUsed, float64(p.ConnectionsUsed))
			gauge(ch, descDBConnMax, float64(p.ConnectionsMax))
			gauge(ch, descDBXIDAge, float64(p.XIDAge))
			if p.OldestTransactionSeconds != nil {
				gauge(ch, descDBOldestTx, *p.OldestTransactionSeconds)
			}
			if p.CacheHitRatio != nil {
				gauge(ch, descDBCacheHit, *p.CacheHitRatio)
			}
		}
	}
	if l := s.Ledger; l != nil {
		section(ch, "ledger", l.Section)
		if l.OK() {
			for _, k := range l.Kinds {
				gauge(ch, descLedgerObjects, float64(k.Objects), k.Kind)
				gauge(ch, descLedgerBytes, float64(k.Bytes), k.Kind)
			}
		}
	}
	if b := s.Backend; b != nil {
		section(ch, "backend", b.Section)
		if b.OK() {
			gauge(ch, descBackendObjects, float64(b.Objects))
			gauge(ch, descBackendBytes, float64(b.Bytes))
			truncated := 0.0
			if b.Truncated {
				truncated = 1
			}
			gauge(ch, descBackendTruncated, truncated)
			if b.VolumeCapacityBytes != nil {
				gauge(ch, descVolumeCapacity, float64(*b.VolumeCapacityBytes))
			}
			if b.VolumeFreeBytes != nil {
				gauge(ch, descVolumeFree, float64(*b.VolumeFreeBytes))
			}
		}
	}
}

func section(ch chan<- prometheus.Metric, source string, s Section) {
	gauge(ch, descSampleTimestamp, float64(s.CollectedAt.UnixMilli())/1000, source)
	gauge(ch, descSampleDuration, s.DurationSeconds, source)
	success := 0.0
	if s.OK() {
		success = 1
	}
	gauge(ch, descSampleSuccess, success, source)
}

func gauge(ch chan<- prometheus.Metric, desc *prometheus.Desc, v float64, labels ...string) {
	ch <- prometheus.MustNewConstMetric(desc, prometheus.GaugeValue, v, labels...)
}
