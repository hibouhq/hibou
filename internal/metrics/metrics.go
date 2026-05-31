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
	)
}
