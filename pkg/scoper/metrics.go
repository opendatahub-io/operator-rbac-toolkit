package scoper

import (
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

var (
	roleBindingCreatedTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "rbac_scoper_rolebinding_created_total",
			Help: "Total RoleBindings created",
		},
		[]string{"target_sa", "namespace", "source"},
	)

	roleBindingDeletedTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "rbac_scoper_rolebinding_deleted_total",
			Help: "Total RoleBindings deleted",
		},
		[]string{"target_sa", "namespace"},
	)

	reconcileErrorsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "rbac_scoper_reconcile_errors_total",
			Help: "Total reconciliation errors",
		},
		[]string{"error_type"},
	)

	reconcileDuration = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "rbac_scoper_reconcile_duration_seconds",
			Help:    "Reconciliation latency",
			Buckets: prometheus.DefBuckets,
		},
	)

	orphanRoleBindings = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "rbac_scoper_orphan_rolebindings",
			Help: "Current count of orphan RoleBindings pending cleanup",
		},
	)

	clusterRoleMissing = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "rbac_scoper_clusterrole_missing",
			Help: "Whether a configured ClusterRole does not exist (0=present, 1=missing)",
		},
		[]string{"clusterrole"},
	)

	webhookRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "rbac_scoper_webhook_requests_total",
			Help: "Webhook invocations",
		},
		[]string{"gvk", "result", "reason"},
	)

	webhookDuration = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "rbac_scoper_webhook_duration_seconds",
			Help:    "Webhook latency",
			Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0},
		},
	)

	webhookRoleBindingCreatedTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "rbac_scoper_webhook_rolebinding_created_total",
			Help: "RoleBindings created via webhook path",
		},
	)

	webhookAlreadyExistsTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "rbac_scoper_webhook_already_exists_total",
			Help: "AlreadyExists responses in webhook (concurrent create)",
		},
	)

	webhookErrorsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "rbac_scoper_webhook_errors_total",
			Help: "Webhook failures",
		},
		[]string{"error_type"},
	)

	labelTriggerEvaluationsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "rbac_scoper_label_trigger_evaluations_total",
			Help: "Label trigger evaluations",
		},
		[]string{"result"},
	)
)

func init() {
	metrics.Registry.MustRegister(
		roleBindingCreatedTotal,
		roleBindingDeletedTotal,
		reconcileErrorsTotal,
		reconcileDuration,
		orphanRoleBindings,
		clusterRoleMissing,
		webhookRequestsTotal,
		webhookDuration,
		webhookRoleBindingCreatedTotal,
		webhookAlreadyExistsTotal,
		webhookErrorsTotal,
		labelTriggerEvaluationsTotal,
	)
}
