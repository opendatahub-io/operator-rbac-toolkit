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
	start := time.Now()
	defer func() {
		reconcileDuration.Observe(time.Since(start).Seconds())
	}()

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
		clusterRoleMissing.WithLabelValues(r.Target.ClusterRoleName).Set(1)
		return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
	}
	clusterRoleMissing.WithLabelValues(r.Target.ClusterRoleName).Set(0)

	if err := r.ensureRoleBinding(ctx, cr, targetNamespace); err != nil {
		reconcileErrorsTotal.WithLabelValues("rolebinding").Inc()
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
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

// resolveTargetSA returns the SA for the given CR using whichever resolution
// strategy is configured on the target (static, field path, or callback).
// Returns an error only for TargetSASource when a required field is missing.
func (r *ScopingReconciler) resolveTargetSA(cr *unstructured.Unstructured) (types.NamespacedName, error) {
	if r.Target.TargetSAFunc != nil {
		return r.Target.TargetSAFunc(cr), nil
	}
	if r.Target.TargetSASource != nil {
		name, err := extractFieldValue(cr, r.Target.TargetSASource.NameFieldPath)
		if err != nil {
			return types.NamespacedName{}, fmt.Errorf("resolving SA name from %s: %w", r.Target.TargetSASource.NameFieldPath, err)
		}
		ns := cr.GetNamespace()
		if r.Target.TargetSASource.NamespaceFieldPath != "" {
			ns, err = extractFieldValue(cr, r.Target.TargetSASource.NamespaceFieldPath)
			if err != nil {
				return types.NamespacedName{}, fmt.Errorf("resolving SA namespace from %s: %w", r.Target.TargetSASource.NamespaceFieldPath, err)
			}
		}
		return types.NamespacedName{Name: name, Namespace: ns}, nil
	}
	return r.Target.TargetSA, nil
}

// resolveRoleBindingName returns the RoleBinding name to use for the given CR.
func (r *ScopingReconciler) resolveRoleBindingName(cr *unstructured.Unstructured) string {
	if r.Target.ManagedRoleBindingNameFunc != nil {
		return r.Target.ManagedRoleBindingNameFunc(cr)
	}
	return r.Target.ManagedRoleBindingName
}

func (r *ScopingReconciler) ensureRoleBinding(ctx context.Context, cr *unstructured.Unstructured, targetNamespace string) error {
	logger := log.FromContext(ctx)
	rbName := types.NamespacedName{
		Name:      r.resolveRoleBindingName(cr),
		Namespace: targetNamespace,
	}

	targetSA, err := r.resolveTargetSA(cr)
	if err != nil {
		logger.Error(err, "failed to resolve target SA from CR")
		return err
	}

	existing := &rbacv1.RoleBinding{}
	err = r.Get(ctx, rbName, existing)
	if apierrors.IsNotFound(err) {
		return r.createRoleBinding(ctx, cr, targetNamespace, targetSA)
	}
	if err != nil {
		return err
	}

	if err := r.ensureRoleBindingSpec(ctx, existing, targetNamespace, targetSA); err != nil {
		return err
	}

	// Backfill pending-owner annotation to OwnerReference
	if err := r.backfillPendingOwner(ctx, cr, targetNamespace); err != nil {
		return err
	}

	if r.isSameNamespace(cr, targetNamespace) {
		return retry.RetryOnConflict(retry.DefaultRetry, func() error {
			// Re-fetch after drift correction since ensureRoleBindingSpec may have
			// deleted and recreated the RoleBinding (RoleRef is immutable).
			fresh := &rbacv1.RoleBinding{}
			if err := r.Get(ctx, rbName, fresh); err != nil {
				return err
			}
			return r.ensureOwnerReference(ctx, cr, fresh)
		})
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
func (r *ScopingReconciler) ensureRoleBindingSpec(ctx context.Context, existing *rbacv1.RoleBinding, targetNamespace string, targetSA types.NamespacedName) error {
	logger := log.FromContext(ctx)
	expectedRoleRef := rbacv1.RoleRef{
		APIGroup: rbacv1.GroupName,
		Kind:     "ClusterRole",
		Name:     r.Target.ClusterRoleName,
	}
	expectedSubjects := []rbacv1.Subject{
		{
			Kind:      rbacv1.ServiceAccountKind,
			Name:      targetSA.Name,
			Namespace: targetSA.Namespace,
		},
	}

	roleRefDrifted := existing.RoleRef != expectedRoleRef
	subjectsDrifted := !reflect.DeepEqual(existing.Subjects, expectedSubjects)

	if !roleRefDrifted && !subjectsDrifted {
		return nil
	}

	if roleRefDrifted {
		// RoleRef is immutable, must delete and recreate.
		// Re-fetch to get the latest annotations before delete to minimize
		// the window for losing concurrent owner annotation updates.
		fresh := &rbacv1.RoleBinding{}
		if fetchErr := r.Get(ctx, client.ObjectKeyFromObject(existing), fresh); fetchErr != nil {
			if !apierrors.IsNotFound(fetchErr) {
				return fmt.Errorf("re-fetching RoleBinding for drift correction: %w", fetchErr)
			}
		} else {
			existing = fresh
		}

		logger.Info("RoleRef drift detected, deleting RoleBinding for recreation",
			"namespace", targetNamespace, "name", existing.Name,
			"expected", expectedRoleRef, "actual", existing.RoleRef)
		if err := r.Delete(ctx, existing); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("deleting drifted RoleBinding: %w", err)
		}
		recreatedAnnotations := map[string]string{
			CreatedByAnnotationKey: CreatedByScoper,
		}
		if ownerAnno, ok := existing.Annotations[OwnerAnnotationKey]; ok {
			recreatedAnnotations[OwnerAnnotationKey] = ownerAnno
		}
		recreated := &rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      existing.Name,
				Namespace: existing.Namespace,
				Labels: map[string]string{
					ManagedLabelKey: ManagedLabelValue,
				},
				Annotations:     recreatedAnnotations,
				OwnerReferences: existing.OwnerReferences,
			},
			RoleRef:  expectedRoleRef,
			Subjects: expectedSubjects,
		}
		if err := r.Create(ctx, recreated); err != nil {
			if apierrors.IsAlreadyExists(err) {
				return nil
			}
			return err
		}
		return nil
	}

	// Only Subjects drifted, can update in place
	logger.Info("Subjects drift detected, updating RoleBinding",
		"namespace", targetNamespace, "name", existing.Name)
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		fresh := &rbacv1.RoleBinding{}
		if err := r.Get(ctx, types.NamespacedName{Name: existing.Name, Namespace: existing.Namespace}, fresh); err != nil {
			return err
		}
		fresh.Subjects = expectedSubjects
		return r.Update(ctx, fresh)
	})
}

func (r *ScopingReconciler) createRoleBinding(ctx context.Context, cr *unstructured.Unstructured, targetNamespace string, targetSA types.NamespacedName) error {
	logger := log.FromContext(ctx)
	rbName := r.resolveRoleBindingName(cr)
	rb := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      rbName,
			Namespace: targetNamespace,
			Labels: map[string]string{
				ManagedLabelKey: ManagedLabelValue,
			},
			Annotations: map[string]string{
				CreatedByAnnotationKey: CreatedByScoper,
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "ClusterRole",
			Name:     r.Target.ClusterRoleName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      rbacv1.ServiceAccountKind,
				Name:      targetSA.Name,
				Namespace: targetSA.Namespace,
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
		rb.Annotations[OwnerAnnotationKey] = FormatOwnerAnnotation([]OwnerEntry{entry})
	}

	logger.Info("creating RoleBinding", "namespace", targetNamespace, "name", rbName)
	if err := r.Create(ctx, rb); err != nil {
		if apierrors.IsAlreadyExists(err) {
			// Another controller or concurrent reconcile created it, treat as success
			return nil
		}
		return err
	}
	source := "reconciler"
	if r.isSameNamespace(cr, targetNamespace) {
		source = "reconciler-owner-ref"
	} else {
		source = "reconciler-annotation"
	}
	roleBindingCreatedTotal.WithLabelValues(
		fmt.Sprintf("%s/%s", targetSA.Namespace, targetSA.Name),
		targetNamespace,
		source,
	).Inc()
	return nil
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

// parsePendingOwner parses the pending-owner annotation format:
// namespace/name/group/version/kind/RFC3339-timestamp
func parsePendingOwner(annotation string) (namespace, name string, timestamp time.Time, err error) {
	parts := strings.Split(annotation, "/")
	if len(parts) < 6 {
		return "", "", time.Time{}, fmt.Errorf("invalid pending-owner format: expected at least 6 parts, got %d", len(parts))
	}

	namespace = parts[0]
	name = parts[1]
	// parts[2] = group, parts[3] = version, parts[4] = kind (not needed for matching)
	timestampStr := parts[5]

	timestamp, err = time.Parse(time.RFC3339, timestampStr)
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("invalid timestamp in pending-owner: %w", err)
	}

	return namespace, name, timestamp, nil
}

// backfillPendingOwner checks if a RoleBinding has a pending-owner annotation
// and backfills it to an OwnerReference if it references the current CR.
func (r *ScopingReconciler) backfillPendingOwner(ctx context.Context, cr *unstructured.Unstructured, targetNamespace string) error {
	logger := log.FromContext(ctx)
	rbName := types.NamespacedName{
		Name:      r.resolveRoleBindingName(cr),
		Namespace: targetNamespace,
	}

	// Only backfill for same-namespace scenarios
	if !r.isSameNamespace(cr, targetNamespace) {
		return nil
	}

	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		rb := &rbacv1.RoleBinding{}
		if err := r.Get(ctx, rbName, rb); err != nil {
			return err
		}

		pendingOwnerAnnotation, hasPendingOwner := rb.Annotations[PendingOwnerAnnotationKey]
		if !hasPendingOwner {
			return nil
		}

		// Parse the pending-owner annotation
		pendingNS, pendingName, timestamp, err := parsePendingOwner(pendingOwnerAnnotation)
		if err != nil {
			logger.Error(err, "failed to parse pending-owner annotation", "annotation", pendingOwnerAnnotation)
			return nil
		}

		// Check if the pending-owner references this CR
		if pendingNS != cr.GetNamespace() || pendingName != cr.GetName() {
			// Not for this CR. Skip backfill and defer to periodic cleanup.
			// Returning nil avoids unnecessary requeues for CRs that don't own
			// this RoleBinding.
			_ = timestamp // timestamp used by cleanup, not needed here
			logger.V(1).Info("pending-owner doesn't match CR, skipping backfill",
				"rolebinding", rbName, "pending", fmt.Sprintf("%s/%s", pendingNS, pendingName))
			return nil
		}

		// CR exists and has UID, backfill
		if cr.GetUID() == "" {
			logger.V(1).Info("CR has no UID yet, skipping backfill", "rolebinding", rbName)
			return nil
		}

		// Set OwnerReference and remove pending-owner annotation
		logger.Info("backfilling pending-owner to OwnerReference", "rolebinding", rbName, "owner", fmt.Sprintf("%s/%s", cr.GetNamespace(), cr.GetName()))
		if err := controllerutil.SetOwnerReference(cr, rb, r.Scheme()); err != nil {
			return fmt.Errorf("setting owner reference: %w", err)
		}
		delete(rb.Annotations, PendingOwnerAnnotationKey)

		return r.Update(ctx, rb)
	})
}
