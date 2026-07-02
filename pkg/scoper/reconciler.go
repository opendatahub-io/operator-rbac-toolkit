package scoper

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
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
}

func NewScopingReconciler(c client.Client, target ScopingTarget, denyList DenyListConfig) (*ScopingReconciler, error) {
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
		return ctrl.Result{RequeueAfter: 30_000_000_000}, nil
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

	if r.isSameNamespace(cr, targetNamespace) {
		return r.ensureOwnerReference(ctx, cr, existing)
	}

	entries := ParseOwnerAnnotation(existing.Annotations[OwnerAnnotationKey])
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
	if existing.Annotations == nil {
		existing.Annotations = make(map[string]string)
	}
	existing.Annotations[OwnerAnnotationKey] = FormatOwnerAnnotation(updated)
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
	if err := controllerutil.SetOwnerReference(cr, rb, r.Scheme()); err != nil {
		return err
	}
	return r.Update(ctx, rb)
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
