package scoper

import (
	"context"
	"fmt"
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
			"targetSA", fmt.Sprintf("%s/%s", target.TargetSA.Namespace, target.TargetSA.Name),
			"clusterRole", target.ClusterRoleName)
	}

	cleanupInterval := 5 * time.Minute
	if cfg.CleanupInterval.Duration > 0 {
		cleanupInterval = cfg.CleanupInterval.Duration
	}
	crossNsTargets := filterCrossNamespaceTargets(cfg.Targets)
	if len(crossNsTargets) > 0 {
		cleanup := &CleanupReconciler{
			Client:   mgr.GetClient(),
			Targets:  crossNsTargets,
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
	if t.TargetSA.Name == "" || t.TargetSA.Namespace == "" {
		return fmt.Errorf("TargetSA name and namespace are required")
	}
	if t.ClusterRoleName == "" {
		return fmt.Errorf("ClusterRoleName is required")
	}
	if t.ManagedRoleBindingName == "" {
		return fmt.Errorf("ManagedRoleBindingName is required")
	}
	return nil
}

func filterCrossNamespaceTargets(targets []ScopingTarget) []ScopingTarget {
	var result []ScopingTarget
	for _, t := range targets {
		if t.TargetNamespaceSource != nil {
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
