package scoper

import (
	"context"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

func Setup(mgr ctrl.Manager, cfg Config) error {
	logger := log.Log.WithName("scoper-setup")

	if len(cfg.Targets) == 0 {
		return fmt.Errorf("no scoping targets configured")
	}

	denyList := cfg.DenyList
	if len(denyList.Namespaces) == 0 && len(denyList.Prefixes) == 0 {
		denyList = DefaultDenyList(cfg.ControllerNamespace)
	}

	recorder := mgr.GetEventRecorderFor("rbac-scoper")

	for i, target := range cfg.Targets {
		if err := validateTarget(target); err != nil {
			return fmt.Errorf("invalid target %d: %w", i, err)
		}

		if err := ValidateClusterRole(context.Background(), mgr.GetClient(), target.ClusterRoleName); err != nil {
			logger.Error(err, "ClusterRole validation failed at startup, will retry at reconcile time",
				"clusterRole", target.ClusterRoleName)
		}

		rec, err := NewScopingReconciler(mgr.GetClient(), target, denyList, recorder)
		if err != nil {
			return fmt.Errorf("creating reconciler for target %d: %w", i, err)
		}

		watchObj := &unstructured.Unstructured{}
		watchObj.SetGroupVersionKind(target.WatchGVK)

		builder := ctrl.NewControllerManagedBy(mgr).
			Named(fmt.Sprintf("scoper-%d-%s", i, target.ManagedRoleBindingName)).
			For(watchObj).
			Owns(&rbacv1.RoleBinding{})

		if target.NamespaceSelector != nil {
			builder = builder.Watches(
				&corev1.Namespace{},
				handler.EnqueueRequestsFromMapFunc(namespaceToRequests(mgr.GetClient(), target)),
			)
		}

		// MAJOR 6: Check CRD availability before completing the controller.
		// If the CRD for the watched GVK doesn't exist yet, the informer will fail.
		// Log a warning and skip this target rather than failing startup.
		// TODO: implement exponential backoff retry for CRD availability,
		// re-registering the controller once the CRD becomes available.
		if !isCRDAvailable(mgr, target.WatchGVK) {
			logger.Info("CRD not available, skipping controller registration (will not auto-retry)",
				"gvk", target.WatchGVK.String())
			continue
		}

		if err := builder.Complete(rec); err != nil {
			return fmt.Errorf("building controller for target %d: %w", i, err)
		}

		logger.Info("registered scoping controller",
			"gvk", target.WatchGVK.String(),
			"targetSA", targetSALogValue(target),
			"clusterRole", target.ClusterRoleName)

		// Register label trigger controller if NamespaceLabelTrigger is configured
		if target.NamespaceLabelTrigger != nil {
			labelTriggerRec, err := NewLabelTriggerReconciler(mgr.GetClient(), target, denyList)
			if err != nil {
				return fmt.Errorf("creating label trigger reconciler for target %d: %w", i, err)
			}

			labelTriggerBuilder := ctrl.NewControllerManagedBy(mgr).
				Named(fmt.Sprintf("label-trigger-%d-%s", i, target.ManagedRoleBindingName)).
				For(&corev1.Namespace{})

			if err := labelTriggerBuilder.Complete(labelTriggerRec); err != nil {
				return fmt.Errorf("building label trigger controller for target %d: %w", i, err)
			}

			logger.Info("registered label trigger controller",
				"targetSA", targetSALogValue(target),
				"clusterRole", target.ClusterRoleName)
		}
	}

	cleanupInterval := 5 * time.Minute
	if cfg.CleanupInterval.Duration > 0 {
		cleanupInterval = cfg.CleanupInterval.Duration
	}
	cleanupTargets := filterCleanupTargets(cfg.Targets)
	if len(cleanupTargets) > 0 {
		cleanup := &CleanupReconciler{
			Client:   mgr.GetClient(),
			Targets:  cleanupTargets,
			DenyList: denyList,
			Interval: cleanupInterval,
		}
		if err := mgr.Add(cleanup); err != nil {
			return fmt.Errorf("adding cleanup reconciler: %w", err)
		}
	}

	return nil
}

func validateTarget(t ScopingTarget) error {
	if t.WatchGVK.Kind == "" {
		return fmt.Errorf("WatchGVK.Kind is required")
	}
	if t.ClusterRoleName == "" {
		return fmt.Errorf("ClusterRoleName is required")
	}
	if t.ManagedRoleBindingName == "" && t.ManagedRoleBindingNameFunc == nil {
		return fmt.Errorf("ManagedRoleBindingName or ManagedRoleBindingNameFunc is required")
	}

	// Exactly one SA resolution strategy must be set.
	saOptions := 0
	if t.TargetSA.Name != "" {
		saOptions++
	}
	if t.TargetSASource != nil {
		saOptions++
	}
	if t.TargetSAFunc != nil {
		saOptions++
	}
	if saOptions == 0 {
		return fmt.Errorf("one of TargetSA, TargetSASource, or TargetSAFunc is required")
	}
	if saOptions > 1 {
		return fmt.Errorf("only one of TargetSA, TargetSASource, or TargetSAFunc may be set")
	}

	if t.TargetSA.Name != "" && t.TargetSA.Namespace == "" {
		return fmt.Errorf("TargetSA.Namespace is required when TargetSA is set")
	}

	if t.TargetSASource != nil {
		if t.TargetSASource.NameFieldPath == "" {
			return fmt.Errorf("TargetSASource.NameFieldPath is required")
		}
		for _, fp := range []string{t.TargetSASource.NameFieldPath, t.TargetSASource.NamespaceFieldPath} {
			if fp == "" {
				continue
			}
			normalized := strings.TrimPrefix(fp, ".")
			if !strings.HasPrefix(normalized, "spec.") {
				return fmt.Errorf("TargetSASource field paths must start with \".spec.\" to prevent reading user-controlled fields, got %q", fp)
			}
		}
	}

	if t.TargetNamespaceSource != nil {
		fp := t.TargetNamespaceSource.FieldPath
		normalized := strings.TrimPrefix(fp, ".")
		if !strings.HasPrefix(normalized, "spec.") {
			return fmt.Errorf("TargetNamespaceSource.FieldPath must start with \".spec.\" to prevent reading user-controlled fields, got %q", fp)
		}
	}
	if t.WebhookProvisioning && t.TargetNamespaceSource != nil {
		return fmt.Errorf("WebhookProvisioning cannot be used with TargetNamespaceSource (webhook is same-namespace only)")
	}
	if t.NamespaceLabelTrigger != nil && t.TargetNamespaceSource != nil {
		return fmt.Errorf("NamespaceLabelTrigger cannot be used with TargetNamespaceSource (label trigger is same-namespace only)")
	}
	if t.NamespaceLabelTrigger != nil && (t.TargetSASource != nil || t.TargetSAFunc != nil) {
		return fmt.Errorf("NamespaceLabelTrigger cannot be used with TargetSASource or TargetSAFunc (label trigger fires from Namespace events, not CR events — SA cannot be resolved without a CR)")
	}
	if t.WebhookProvisioning && (t.TargetSASource != nil || t.TargetSAFunc != nil) {
		return fmt.Errorf("WebhookProvisioning cannot be used with TargetSASource or TargetSAFunc (webhook fires before CR exists — SA cannot be resolved without a CR)")
	}
	return nil
}

func filterCleanupTargets(targets []ScopingTarget) []ScopingTarget {
	var result []ScopingTarget
	for _, t := range targets {
		if t.TargetNamespaceSource != nil || t.WebhookProvisioning {
			result = append(result, t)
		}
	}
	return result
}

func namespaceToRequests(c client.Client, target ScopingTarget) handler.MapFunc {
	return func(ctx context.Context, obj client.Object) []ctrl.Request {
		crList := &unstructured.UnstructuredList{}
		listGVK := target.WatchGVK.GroupVersion().WithKind(target.WatchGVK.Kind + "List")
		crList.SetGroupVersionKind(listGVK)
		if err := c.List(ctx, crList); err != nil {
			return nil
		}

		var requests []ctrl.Request
		for _, cr := range crList.Items {
			requests = append(requests, ctrl.Request{
				NamespacedName: client.ObjectKeyFromObject(&cr),
			})
		}
		return requests
	}
}

// isCRDAvailable checks whether the API server knows about the given GVK
// by querying the discovery cache (RESTMapper).
func isCRDAvailable(mgr ctrl.Manager, gvk schema.GroupVersionKind) bool {
	_, err := mgr.GetRESTMapper().RESTMapping(gvk.GroupKind(), gvk.Version)
	return err == nil
}

// targetSALogValue returns a human-readable SA descriptor for logging. For
// static TargetSA targets it returns "namespace/name"; for dynamic options it
// returns a descriptive placeholder.
func targetSALogValue(t ScopingTarget) string {
	if t.TargetSA.Name != "" {
		return fmt.Sprintf("%s/%s", t.TargetSA.Namespace, t.TargetSA.Name)
	}
	if t.TargetSASource != nil {
		return fmt.Sprintf("<field:%s>", t.TargetSASource.NameFieldPath)
	}
	return "<func>"
}
