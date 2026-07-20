package scoper

import (
	"context"
	"fmt"
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

	totalOrphans := 0
	for _, target := range r.Targets {
		// No field indexer is registered for RoleBindings, so always use
		// client-side filtering to avoid silent failures.
		count, err := r.listAndCleanup(ctx, target)
		if err != nil {
			logger.Error(err, "cleanup failed for target", "roleBinding", target.ManagedRoleBindingName)
		}
		totalOrphans += count
	}
	orphanRoleBindings.Set(float64(totalOrphans))
}

func (r *CleanupReconciler) listAndCleanup(ctx context.Context, target ScopingTarget) (int, error) {
	rbList := &rbacv1.RoleBindingList{}
	if err := r.List(ctx, rbList, client.MatchingLabels{ManagedLabelKey: ManagedLabelValue}); err != nil {
		return 0, err
	}
	orphanCount := 0
	for _, rb := range rbList.Items {
		if rb.Name == target.ManagedRoleBindingName {
			isOrphan := r.cleanupRoleBinding(ctx, &rb, target)
			if isOrphan {
				orphanCount++
			}
		}
	}
	return orphanCount, nil
}

func (r *CleanupReconciler) cleanupRoleBinding(ctx context.Context, rb *rbacv1.RoleBinding, target ScopingTarget) bool {
	logger := log.Log.WithName("scoper-cleanup")

	// Handle RoleBindings with pending-owner annotation (webhook-created, never backfilled)
	if pendingAnnotation, hasPending := rb.Annotations[PendingOwnerAnnotationKey]; hasPending {
		return r.cleanupPendingOwner(ctx, rb, target, pendingAnnotation)
	}

	annotation := rb.Annotations[OwnerAnnotationKey]
	if annotation == "" {
		return false
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
		return false
	}

	if len(validEntries) == 0 {
		logger.Info("deleting orphan RoleBinding", "namespace", rb.Namespace, "name", rb.Name)
		if err := r.Delete(ctx, rb); err != nil && !apierrors.IsNotFound(err) {
			logger.Error(err, "failed to delete orphan RoleBinding")
			return false
		}
		roleBindingDeletedTotal.WithLabelValues(
			fmt.Sprintf("%s/%s", target.TargetSA.Namespace, target.TargetSA.Name),
			rb.Namespace,
		).Inc()
		return true
	}

	rb.Annotations[OwnerAnnotationKey] = FormatOwnerAnnotation(validEntries)
	if err := r.Update(ctx, rb); err != nil {
		logger.Error(err, "failed to update RoleBinding annotations")
	}
	return false
}

// cleanupPendingOwner handles cleanup for RoleBindings that still have a pending-owner
// annotation (created by webhook, never backfilled by the reconciler). If the referenced
// CR no longer exists and the pending-owner TTL (30s) has expired, the RoleBinding is deleted.
func (r *CleanupReconciler) cleanupPendingOwner(ctx context.Context, rb *rbacv1.RoleBinding, target ScopingTarget, pendingAnnotation string) bool {
	logger := log.Log.WithName("scoper-cleanup")

	namespace, name, timestamp, err := parsePendingOwner(pendingAnnotation)
	if err != nil {
		logger.Error(err, "failed to parse pending-owner annotation, skipping",
			"roleBinding", rb.Namespace+"/"+rb.Name, "annotation", pendingAnnotation)
		return false
	}

	const pendingOwnerTTL = 30 * time.Second
	if time.Since(timestamp) <= pendingOwnerTTL {
		// Still within TTL, don't clean up yet
		return false
	}

	// Check if the referenced CR still exists
	cr := &unstructured.Unstructured{}
	cr.SetGroupVersionKind(target.WatchGVK)
	err = r.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, cr)
	if err == nil {
		// CR still exists, not an orphan
		return false
	}
	if !apierrors.IsNotFound(err) {
		// Transient error, assume valid to avoid premature cleanup
		logger.V(1).Info("transient error checking pending-owner CR, assuming valid",
			"owner", namespace+"/"+name, "error", err)
		return false
	}

	// CR is gone and TTL has expired, delete the RoleBinding
	logger.Info("deleting orphan RoleBinding with expired pending-owner",
		"namespace", rb.Namespace, "name", rb.Name,
		"pendingOwner", namespace+"/"+name)
	if err := r.Delete(ctx, rb); err != nil && !apierrors.IsNotFound(err) {
		logger.Error(err, "failed to delete orphan pending-owner RoleBinding")
		return false
	}
	roleBindingDeletedTotal.WithLabelValues(
		fmt.Sprintf("%s/%s", target.TargetSA.Namespace, target.TargetSA.Name),
		rb.Namespace,
	).Inc()
	return true
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
