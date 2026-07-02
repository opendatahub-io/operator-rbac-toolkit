package scoper

import (
	"context"
	"time"

	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

type CleanupReconciler struct {
	client.Client
	Targets  []ScopingTarget
	DenyList DenyListConfig
	Interval time.Duration
}

func (r *CleanupReconciler) Start(ctx context.Context) error {
	logger := log.Log.WithName("scoper-cleanup")
	logger.Info("starting cross-namespace cleanup reconciler", "interval", r.Interval)

	r.runCleanup(ctx)

	ticker := time.NewTicker(r.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			r.runCleanup(ctx)
		}
	}
}

func (r *CleanupReconciler) NeedLeaderElection() bool {
	return true
}

func (r *CleanupReconciler) runCleanup(ctx context.Context) {
	logger := log.Log.WithName("scoper-cleanup")

	for _, target := range r.Targets {
		// No field indexer is registered for RoleBindings, so always use
		// client-side filtering to avoid silent failures.
		if err := r.listAndCleanup(ctx, target); err != nil {
			logger.Error(err, "cleanup failed for target", "roleBinding", target.ManagedRoleBindingName)
		}
	}
}

func (r *CleanupReconciler) listAndCleanup(ctx context.Context, target ScopingTarget) error {
	rbList := &rbacv1.RoleBindingList{}
	if err := r.List(ctx, rbList); err != nil {
		return err
	}
	for _, rb := range rbList.Items {
		if rb.Name == target.ManagedRoleBindingName {
			r.cleanupRoleBinding(ctx, &rb, target)
		}
	}
	return nil
}

func (r *CleanupReconciler) cleanupRoleBinding(ctx context.Context, rb *rbacv1.RoleBinding, target ScopingTarget) {
	logger := log.Log.WithName("scoper-cleanup")

	annotation := rb.Annotations[OwnerAnnotationKey]
	if annotation == "" {
		return
	}

	entries := ParseOwnerAnnotation(annotation)
	var validEntries []OwnerEntry

	for _, entry := range entries {
		if r.isOwnerValid(ctx, entry, target, rb.Namespace) {
			validEntries = append(validEntries, entry)
		} else {
			logger.Info("removing stale owner entry",
				"roleBinding", rb.Namespace+"/"+rb.Name,
				"owner", entry.Namespace+"/"+entry.Name)
		}
	}

	if len(validEntries) == len(entries) {
		return
	}

	if len(validEntries) == 0 {
		logger.Info("deleting orphan RoleBinding", "namespace", rb.Namespace, "name", rb.Name)
		if err := r.Delete(ctx, rb); err != nil && !apierrors.IsNotFound(err) {
			logger.Error(err, "failed to delete orphan RoleBinding")
		}
		return
	}

	rb.Annotations[OwnerAnnotationKey] = FormatOwnerAnnotation(validEntries)
	if err := r.Update(ctx, rb); err != nil {
		logger.Error(err, "failed to update RoleBinding annotations")
	}
}

func (r *CleanupReconciler) isOwnerValid(ctx context.Context, entry OwnerEntry, target ScopingTarget, rbNamespace string) bool {
	logger := log.Log.WithName("scoper-cleanup")

	cr := &unstructured.Unstructured{}
	cr.SetGroupVersionKind(target.WatchGVK)
	err := r.Get(ctx, types.NamespacedName{Namespace: entry.Namespace, Name: entry.Name}, cr)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return false
		}
		// On transient errors (network, timeout), assume valid to avoid premature cleanup
		logger.V(1).Info("transient error checking owner, assuming valid",
			"owner", entry.Namespace+"/"+entry.Name, "error", err)
		return true
	}
	if cr.GetUID() != entry.UID {
		return false
	}

	if target.TargetNamespaceSource != nil {
		resolvedNs, err := extractFieldValue(cr, target.TargetNamespaceSource.FieldPath)
		if err != nil || resolvedNs != rbNamespace {
			return false
		}
	}

	return true
}
