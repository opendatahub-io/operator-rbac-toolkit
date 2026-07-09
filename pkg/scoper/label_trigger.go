package scoper

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// LabelTriggerReconciler watches Namespace resources and pre-provisions RoleBindings
// when namespaces match the configured label selector.
type LabelTriggerReconciler struct {
	Client   client.Client
	Target   ScopingTarget
	DenyList DenyListConfig
	Selector labels.Selector
}

// NewLabelTriggerReconciler creates a reconciler for namespace label-based RoleBinding provisioning.
func NewLabelTriggerReconciler(c client.Client, target ScopingTarget, denyList DenyListConfig) (*LabelTriggerReconciler, error) {
	if target.NamespaceLabelTrigger == nil {
		return nil, fmt.Errorf("NamespaceLabelTrigger is nil")
	}

	selector, err := metav1.LabelSelectorAsSelector(target.NamespaceLabelTrigger)
	if err != nil {
		return nil, fmt.Errorf("invalid NamespaceLabelTrigger: %w", err)
	}

	return &LabelTriggerReconciler{
		Client:   c,
		Target:   target,
		DenyList: denyList,
		Selector: selector,
	}, nil
}

// Reconcile processes a Namespace event and creates or deletes RoleBindings based on label matching.
func (r *LabelTriggerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx).WithValues("namespace", req.Name)

	// Get the namespace
	ns := &corev1.Namespace{}
	if err := r.Client.Get(ctx, req.NamespacedName, ns); err != nil {
		if apierrors.IsNotFound(err) {
			// Namespace deleted, nothing to clean up (RoleBindings cascade delete)
			logger.V(1).Info("namespace not found, skipping")
			return ctrl.Result{}, nil
		}
		logger.Error(err, "failed to get namespace")
		labelTriggerEvaluationsTotal.WithLabelValues("error").Inc()
		return ctrl.Result{}, err
	}

	// Check deny list
	if IsDenied(ns.Name, r.DenyList) {
		logger.V(1).Info("namespace is denied, checking for orphan RoleBindings")
		if err := r.deleteRoleBinding(ctx, ns.Name); err != nil {
			logger.Error(err, "failed to delete orphan RoleBinding in denied namespace")
			labelTriggerEvaluationsTotal.WithLabelValues("error").Inc()
			return ctrl.Result{}, err
		}
		labelTriggerEvaluationsTotal.WithLabelValues("denied").Inc()
		return ctrl.Result{}, nil
	}

	// Check if namespace matches the label selector
	matches := r.Selector.Matches(labels.Set(ns.Labels))

	if matches {
		// Create RoleBinding
		if err := r.ensureRoleBinding(ctx, ns.Name); err != nil {
			logger.Error(err, "failed to ensure RoleBinding")
			labelTriggerEvaluationsTotal.WithLabelValues("error").Inc()
			return ctrl.Result{}, err
		}
		labelTriggerEvaluationsTotal.WithLabelValues("created").Inc()
		logger.Info("RoleBinding ensured for matching namespace")
	} else {
		// Delete RoleBinding if it exists
		if err := r.deleteRoleBinding(ctx, ns.Name); err != nil {
			logger.Error(err, "failed to delete RoleBinding")
			labelTriggerEvaluationsTotal.WithLabelValues("error").Inc()
			return ctrl.Result{}, err
		}
		labelTriggerEvaluationsTotal.WithLabelValues("removed").Inc()
		logger.V(1).Info("namespace does not match label selector, RoleBinding removed if it existed")
	}

	return ctrl.Result{}, nil
}

// ensureRoleBinding creates a RoleBinding in the namespace if it doesn't exist.
func (r *LabelTriggerReconciler) ensureRoleBinding(ctx context.Context, namespace string) error {
	rb := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      r.Target.ManagedRoleBindingName,
			Namespace: namespace,
			Labels: map[string]string{
				ManagedLabelKey: ManagedLabelValue,
			},
			Annotations: map[string]string{
				CreatedByAnnotationKey: CreatedByLabelTrigger,
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "ClusterRole",
			Name:     r.Target.ClusterRoleName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      r.Target.TargetSA.Name,
				Namespace: r.Target.TargetSA.Namespace,
			},
		},
	}

	if err := r.Client.Create(ctx, rb); err != nil {
		if apierrors.IsAlreadyExists(err) {
			// Another controller or concurrent reconcile created it, success
			return nil
		}
		return fmt.Errorf("creating RoleBinding: %w", err)
	}

	return nil
}

// deleteRoleBinding removes a label-trigger-created RoleBinding from the namespace.
func (r *LabelTriggerReconciler) deleteRoleBinding(ctx context.Context, namespace string) error {
	rb := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      r.Target.ManagedRoleBindingName,
			Namespace: namespace,
		},
	}

	// Get the RoleBinding to check if it was created by label trigger
	if err := r.Client.Get(ctx, client.ObjectKeyFromObject(rb), rb); err != nil {
		if apierrors.IsNotFound(err) {
			// RoleBinding doesn't exist, nothing to delete
			return nil
		}
		return fmt.Errorf("getting RoleBinding: %w", err)
	}

	// Only delete if it was created by label trigger
	if rb.Annotations[CreatedByAnnotationKey] != CreatedByLabelTrigger {
		// Not created by label trigger, don't touch it
		return nil
	}

	// Delete the RoleBinding
	if err := r.Client.Delete(ctx, rb); err != nil {
		if apierrors.IsNotFound(err) {
			// Already deleted, success
			return nil
		}
		return fmt.Errorf("deleting RoleBinding: %w", err)
	}

	return nil
}
