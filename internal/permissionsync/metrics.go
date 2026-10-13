package permissionsync

import "github.com/prometheus/client_golang/prometheus"

// revalidationOutcomes counts what membership re-validation decided, per
// row: confirmed, removed, error, control_failed, last_admin_kept,
// unverifiable_<reason>, and aborted runs. Unverifiable memberships are kept,
// so this counter is how an operator sees how many the forge cannot vouch for.
var revalidationOutcomes = prometheus.NewCounterVec(prometheus.CounterOpts{
	Namespace: "hibou",
	Name:      "membership_revalidation_total",
	Help:      "Forge membership re-validation outcomes, per membership row.",
}, []string{"outcome"})

func init() {
	prometheus.MustRegister(revalidationOutcomes)
}
