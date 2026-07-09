package graceful

import (
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

var (
	permissionDeniedTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "graceful_permission_denied_total",
			Help: "403 errors handled",
		},
		[]string{"resource", "verb", "reason"},
	)

	permissionRestoredTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "graceful_permission_restored_total",
			Help: "Permission restorations detected",
		},
	)
)

func init() {
	metrics.Registry.MustRegister(
		permissionDeniedTotal,
		permissionRestoredTotal,
	)
}
