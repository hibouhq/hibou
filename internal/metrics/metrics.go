package metrics

import "github.com/prometheus/client_golang/prometheus"

var (
	ScansTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "hibou",
		Name:      "scans_total",
		Help:      "Total number of scans processed.",
	}, []string{"status"})

	ScanDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: "hibou",
		Name:      "scan_duration_seconds",
		Help:      "Duration of scan processing in seconds.",
		Buckets:   prometheus.DefBuckets,
	})

	CacheHits = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "hibou",
		Name:      "advisory_cache_hits_total",
		Help:      "Advisory cache hits.",
	}, []string{"provider"})

	CacheMisses = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "hibou",
		Name:      "advisory_cache_misses_total",
		Help:      "Advisory cache misses.",
	}, []string{"provider"})

	WebSocketConnections = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "hibou",
		Name:      "websocket_connections_active",
		Help:      "Number of active WebSocket connections.",
	})

	NotificationDeliveries = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "hibou",
		Name:      "notification_deliveries_total",
		Help:      "Total notification deliveries.",
	}, []string{"type", "status"})

	UploadsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "hibou",
		Name:      "uploads_total",
		Help:      "Total uploads processed.",
	}, []string{"upload_type", "status"})

	// Secret scan jobs clone repositories, so duration and outcome are the
	// signals that tell an operator whether workers are keeping up or a repo is
	// pathological. Queue depth is exposed separately on /metrics as the
	// autoscaling signal.
	SecretScansTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "hibou",
		Name:      "secret_scans_total",
		Help:      "Secret scan jobs finished, by mode and outcome.",
	}, []string{"mode", "status"})

	SecretScanDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "hibou",
		Name:      "secret_scan_duration_seconds",
		Help:      "Wall-clock duration of secret scan jobs, including the clone.",
		// Clone-dominated work: seconds to minutes, so the buckets span that.
		Buckets: []float64{1, 5, 15, 30, 60, 120, 300, 600},
	}, []string{"mode"})
)

func init() {
	prometheus.MustRegister(
		ScansTotal,
		ScanDuration,
		CacheHits,
		CacheMisses,
		WebSocketConnections,
		NotificationDeliveries,
		UploadsTotal,
		SecretScansTotal,
		SecretScanDuration,
	)
}
