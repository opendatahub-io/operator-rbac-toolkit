package scoper

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

type ScopingReconciler struct {
	client.Client
	Target   ScopingTarget
	DenyList DenyListConfig
	selector labels.Selector
	recorder record.EventRecorder
}

func NewScopingReconciler(c client.Client, target ScopingTarget, denyList DenyListConfig, recorder record.EventRecorder) (*ScopingReconciler, error) {
	var selector labels.Selector
	if target.NamespaceSelector != nil {
		var err error
		selector, err = metav1.LabelSelectorAsSelector(target.NamespaceSelector)
		if err != nil {
			return nil, fmt.Errorf("invalid namespace selector: %w", err)
		}
	}
	return &ScopingReconciler{
		Client:   c,
		Target:   target,
		DenyList: denyList,
		selector: selector,
		recorder: recorder,
	}, nil
}

func (r *ScopingReconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	logger := log.FromContext(ctx)

	cr := &unstructured.Unstructured{}
	cr.SetGroupVersionKind(r.Target.WatchGVK)
	if err := r.Get(ctx, req.NamespacedName, cr); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	targetNamespace := cr.GetNamespace()
	if r.Target.TargetNamespaceSource != nil {
		ns, err := extractFieldValue(cr, r.Target.TargetNamespaceSource.FieldPath)
		if err != nil {
			logger.Error(err, "failed to extract target namespace from CR")
			return ctrl.Result{}, nil
		}
		targetNamespace = ns
	}

	if !r.isNamespaceAllowed(ctx, targetNamespace) {
		logger.V(1).Info("namespace not allowed", "namespace", targetNamespace)
		return ctrl.Result{}, nil
	}

	if err := ValidateClusterRole(ctx, r.Client, r.Target.ClusterRoleName); err != nil {
		logger.Error(err, "ClusterRole validation failed, requeueing")
		r.recorder.Eventf(cr, corev1.EventTypeWarning, "ClusterRoleValidationFailed",
			"ClusterRole %q validation failed: %v", r.Target.ClusterRoleName, err)
		return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
	}

	return ctrl.Result{}, r.ensureRoleBinding(ctx, cr, targetNamespace)
}

func (r *ScopingReconciler) isNamespaceAllowed(ctx context.Context, namespace string) bool {
	if IsDenied(namespace, r.DenyList) {
		return false
	}
	if r.selector == nil {
		return true
	}
	ns := &corev1.Namespace{}
	if err := r.Get(ctx, types.NamespacedName{Name: namespace}, ns); err != nil {
		return false
	}
	return r.selector.Matches(labels.Set(ns.Labels))
}

func (r *ScopingReconciler) ensureRoleBinding(ctx context.Context, cr *unstructured.Unstructured, targetNamespace string) error {
	logger := log.FromContext(ctx)
	rbName := types.NamespacedName{
		Name:      r.Target.ManagedRoleBindingName,
		Namespace: targetNamespace,
	}

	existing := &rbacv1.RoleBinding{}
	err := r.Get(ctx, rbName, existing)
	if apierrors.IsNotFound(err) {
		return r.createRoleBinding(ctx, cr, targetNamespace)
	}
	if err != nil {
		return err
	}

	// MAJOR 2: drift detection for RoleRef and Subjects
	if err := r.ensureRoleBindingSpec(ctx, existing, targetNamespace); err != nil {
		return err
	}

	if r.isSameNamespace(cr, targetNamespace) {
		return r.ensureOwnerReference(ctx, cr, existing)
	}

	// CRITICAL 1: wrap annotation update in retry-on-conflict
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		current := &rbacv1.RoleBinding{}
		if err := r.Get(ctx, rbName, current); err != nil {
			return err
		}

		entries := ParseOwnerAnnotation(current.Annotations[OwnerAnnotationKey])
		entry := OwnerEntry{
			Namespace: cr.GetNamespace(),
			Name:      cr.GetName(),
			UID:       cr.GetUID(),
		}
		updated := AddOwnerEntry(entries, entry)
		if len(updated) == len(entries) {
			return nil
		}

		logger.Info("adding cross-namespace owner", "rolebinding", rbName, "owner", fmt.Sprintf("%s/%s", cr.GetNamespace(), cr.GetName()))
		if current.Annotations == nil {
			current.Annotations = make(map[string]string)
		}
		current.Annotations[OwnerAnnotationKey] = FormatOwnerAnnotation(updated)
		return r.Update(ctx, current)
	})
}

// ensureRoleBindingSpec detects drift in RoleRef and Subjects and corrects it.
// RoleRef is immutable in Kubernetes, so if it differs we must delete and recreate.
func (r *ScopingReconciler) ensureRoleBindingSpec(ctx context.Context, existing *rbacv1.RoleBinding, targetNamespace string) error {
	logger := log.FromContext(ctx)
	expectedRoleRef := rbacv1.RoleRef{
		APIGroup: rbacv1.GroupName,
		Kind:     "ClusterRole",
		Name:     r.Target.ClusterRoleName,
	}
	expectedSubjects := []rbacv1.Subject{
		{
			Kind:      rbacv1.ServiceAccountKind,
			Name:      r.Target.TargetSA.Name,
			Namespace: r.Target.TargetSA.Namespace,
		},
	}

	roleRefDrifted := existing.RoleRef != expectedRoleRef
	subjectsDrifted := !reflect.DeepEqual(existing.Subjects, expectedSubjects)

	if !roleRefDrifted && !subjectsDrifted {
		return nil
	}

	if roleRefDrifted {
		// RoleRef is immutable, must delete and recreate
		logger.Info("RoleRef drift detected, deleting RoleBinding for recreation",
			"namespace", targetNamespace, "name", existing.Name,
			"expected", expectedRoleRef, "actual", existing.RoleRef)
		if err := r.Delete(ctx, existing); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("deleting drifted RoleBinding: %w", err)
		}
		// Recreate with correct spec (preserving annotations/owner references)
		recreated := &rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:            existing.Name,
				Namespace:       existing.Namespace,
				Annotations:     existing.Annotations,
				OwnerReferences: existing.OwnerReferences,
			},
			RoleRef:  expectedRoleRef,
			Subjects: expectedSubjects,
		}
		return r.Create(ctx, recreated)
	}

	// Only Subjects drifted, can update in place
	logger.Info("Subjects drift detected, updating RoleBinding",
		"namespace", targetNamespace, "name", existing.Name)
	existing.Subjects = expectedSubjects
	return r.Update(ctx, existing)
}

func (r *ScopingReconciler) createRoleBinding(ctx context.Context, cr *unstructured.Unstructured, targetNamespace string) error {
	logger := log.FromContext(ctx)
	rb := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      r.Target.ManagedRoleBindingName,
			Namespace: targetNamespace,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "ClusterRole",
			Name:     r.Target.ClusterRoleName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      rbacv1.ServiceAccountKind,
				Name:      r.Target.TargetSA.Name,
				Namespace: r.Target.TargetSA.Namespace,
			},
		},
	}

	if r.isSameNamespace(cr, targetNamespace) {
		if err := controllerutil.SetOwnerReference(cr, rb, r.Scheme()); err != nil {
			return fmt.Errorf("setting owner reference: %w", err)
		}
	} else {
		entry := OwnerEntry{
			Namespace: cr.GetNamespace(),
			Name:      cr.GetName(),
			UID:       cr.GetUID(),
		}
		rb.Annotations = map[string]string{
			OwnerAnnotationKey: FormatOwnerAnnotation([]OwnerEntry{entry}),
		}
	}

	logger.Info("creating RoleBinding", "namespace", targetNamespace, "name", r.Target.ManagedRoleBindingName)
	return r.Create(ctx, rb)
}

func (r *ScopingReconciler) ensureOwnerReference(ctx context.Context, cr *unstructured.Unstructured, rb *rbacv1.RoleBinding) error {
	for _, ref := range rb.OwnerReferences {
		if ref.UID == cr.GetUID() {
			return nil
		}
	}

	logger := log.FromContext(ctx)
	logger.Info("adding owner reference", "rolebinding", rb.Name, "owner", cr.GetName())
	patch := client.MergeFrom(rb.DeepCopy())
	if err := controllerutil.SetOwnerReference(cr, rb, r.Scheme()); err != nil {
		return err
	}
	return r.Patch(ctx, rb, patch)
}

func (r *ScopingReconciler) isSameNamespace(cr *unstructured.Unstructured, targetNamespace string) bool {
	return r.Target.TargetNamespaceSource == nil && cr.GetNamespace() == targetNamespace
}

func extractFieldValue(obj *unstructured.Unstructured, fieldPath string) (string, error) {
	path := strings.TrimPrefix(fieldPath, ".")
	parts := strings.Split(path, ".")

	val, found, err := unstructured.NestedString(obj.Object, parts...)
	if err != nil {
		return "", fmt.Errorf("reading field %s: %w", fieldPath, err)
	}
	if !found || val == "" {
		return "", fmt.Errorf("field %s not found or empty", fieldPath)
	}
	return val, nil
}
