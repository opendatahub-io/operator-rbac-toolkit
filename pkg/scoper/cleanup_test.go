package scoper

import (
	"context"
	"fmt"
	"testing"
	"time"

	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// ---------------------------------------------------------------------------
// cleanupPendingOwner tests
// ---------------------------------------------------------------------------

func TestCleanupPendingOwner_WithinTTL_NoDelete(t *testing.T) {
	scheme := testScheme()
	gvk := schema.GroupVersionKind{Group: "test.io", Version: "v1", Kind: "MyResource"}
	scheme.AddKnownTypeWithName(gvk, &unstructured.Unstructured{})

	freshTimestamp := time.Now().UTC().Format(time.RFC3339)
	rb := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "managed-rb",
			Namespace: "test-ns",
			Labels:    map[string]string{ManagedLabelKey: ManagedLabelValue},
			Annotations: map[string]string{
				PendingOwnerAnnotationKey: fmt.Sprintf("test-ns/my-cr/test.io/v1/MyResource/%s", freshTimestamp),
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "ClusterRole",
			Name:     "role",
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(rb).Build()
	target := ScopingTarget{
		WatchGVK:              gvk,
		TargetSA:              types.NamespacedName{Name: "sa", Namespace: "ns"},
		ClusterRoleName:       "role",
		ManagedRoleBindingName: "managed-rb",
	}

	reconciler := &CleanupReconciler{
		Client:  c,
		Targets: []ScopingTarget{target},
	}

	isOrphan := reconciler.cleanupPendingOwner(context.Background(), rb, target, rb.Annotations[PendingOwnerAnnotationKey])
	if isOrphan {
		t.Error("expected not orphan when within TTL")
	}

	// Verify RoleBinding still exists
	existing := &rbacv1.RoleBinding{}
	if err := c.Get(context.Background(), types.NamespacedName{Name: "managed-rb", Namespace: "test-ns"}, existing); err != nil {
		t.Fatalf("RoleBinding should still exist: %v", err)
	}
}

func TestCleanupPendingOwner_PastTTL_CRExists_NoDelete(t *testing.T) {
	scheme := testScheme()
	gvk := schema.GroupVersionKind{Group: "test.io", Version: "v1", Kind: "MyResource"}
	scheme.AddKnownTypeWithName(gvk, &unstructured.Unstructured{})

	pastTimestamp := time.Now().Add(-5 * time.Minute).UTC().Format(time.RFC3339)
	rb := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "managed-rb",
			Namespace: "test-ns",
			Labels:    map[string]string{ManagedLabelKey: ManagedLabelValue},
			Annotations: map[string]string{
				PendingOwnerAnnotationKey: fmt.Sprintf("test-ns/my-cr/test.io/v1/MyResource/%s", pastTimestamp),
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "ClusterRole",
			Name:     "role",
		},
	}

	// Create the CR so it still exists
	cr := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "test.io/v1",
			"kind":       "MyResource",
			"metadata": map[string]interface{}{
				"name":      "my-cr",
				"namespace": "test-ns",
			},
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(rb, cr).Build()
	target := ScopingTarget{
		WatchGVK:              gvk,
		TargetSA:              types.NamespacedName{Name: "sa", Namespace: "ns"},
		ClusterRoleName:       "role",
		ManagedRoleBindingName: "managed-rb",
	}

	reconciler := &CleanupReconciler{
		Client:  c,
		Targets: []ScopingTarget{target},
	}

	isOrphan := reconciler.cleanupPendingOwner(context.Background(), rb, target, rb.Annotations[PendingOwnerAnnotationKey])
	if isOrphan {
		t.Error("expected not orphan when CR still exists")
	}

	// Verify RoleBinding still exists
	existing := &rbacv1.RoleBinding{}
	if err := c.Get(context.Background(), types.NamespacedName{Name: "managed-rb", Namespace: "test-ns"}, existing); err != nil {
		t.Fatalf("RoleBinding should still exist: %v", err)
	}
}

func TestCleanupPendingOwner_PastTTL_CRGone_Deletes(t *testing.T) {
	scheme := testScheme()
	gvk := schema.GroupVersionKind{Group: "test.io", Version: "v1", Kind: "MyResource"}
	scheme.AddKnownTypeWithName(gvk, &unstructured.Unstructured{})

	pastTimestamp := time.Now().Add(-5 * time.Minute).UTC().Format(time.RFC3339)
	rb := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "managed-rb",
			Namespace: "test-ns",
			Labels:    map[string]string{ManagedLabelKey: ManagedLabelValue},
			Annotations: map[string]string{
				PendingOwnerAnnotationKey: fmt.Sprintf("test-ns/my-cr/test.io/v1/MyResource/%s", pastTimestamp),
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "ClusterRole",
			Name:     "role",
		},
	}

	// No CR exists
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(rb).Build()
	target := ScopingTarget{
		WatchGVK:              gvk,
		TargetSA:              types.NamespacedName{Name: "sa", Namespace: "ns"},
		ClusterRoleName:       "role",
		ManagedRoleBindingName: "managed-rb",
	}

	reconciler := &CleanupReconciler{
		Client:  c,
		Targets: []ScopingTarget{target},
	}

	isOrphan := reconciler.cleanupPendingOwner(context.Background(), rb, target, rb.Annotations[PendingOwnerAnnotationKey])
	if !isOrphan {
		t.Error("expected orphan when CR is gone and TTL expired")
	}

	// Verify RoleBinding was deleted
	existing := &rbacv1.RoleBinding{}
	err := c.Get(context.Background(), types.NamespacedName{Name: "managed-rb", Namespace: "test-ns"}, existing)
	if !apierrors.IsNotFound(err) {
		t.Errorf("expected RoleBinding to be deleted, got: %v", err)
	}
}

func TestCleanupPendingOwner_MalformedAnnotation_NoDelete(t *testing.T) {
	scheme := testScheme()
	gvk := schema.GroupVersionKind{Group: "test.io", Version: "v1", Kind: "MyResource"}
	scheme.AddKnownTypeWithName(gvk, &unstructured.Unstructured{})

	rb := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "managed-rb",
			Namespace: "test-ns",
			Labels:    map[string]string{ManagedLabelKey: ManagedLabelValue},
			Annotations: map[string]string{
				PendingOwnerAnnotationKey: "malformed-annotation",
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "ClusterRole",
			Name:     "role",
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(rb).Build()
	target := ScopingTarget{
		WatchGVK:              gvk,
		TargetSA:              types.NamespacedName{Name: "sa", Namespace: "ns"},
		ClusterRoleName:       "role",
		ManagedRoleBindingName: "managed-rb",
	}

	reconciler := &CleanupReconciler{
		Client:  c,
		Targets: []ScopingTarget{target},
	}

	isOrphan := reconciler.cleanupPendingOwner(context.Background(), rb, target, "malformed-annotation")
	if isOrphan {
		t.Error("expected not orphan for malformed annotation")
	}

	// Verify RoleBinding still exists
	existing := &rbacv1.RoleBinding{}
	if err := c.Get(context.Background(), types.NamespacedName{Name: "managed-rb", Namespace: "test-ns"}, existing); err != nil {
		t.Fatalf("RoleBinding should still exist after malformed annotation: %v", err)
	}
}

// ---------------------------------------------------------------------------
// cleanupRoleBinding tests
// ---------------------------------------------------------------------------

func TestCleanupRoleBinding_WithOwnerAnnotation_ValidEntries(t *testing.T) {
	scheme := testScheme()
	gvk := schema.GroupVersionKind{Group: "test.io", Version: "v1", Kind: "MyResource"}
	scheme.AddKnownTypeWithName(gvk, &unstructured.Unstructured{})

	cr := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "test.io/v1",
			"kind":       "MyResource",
			"metadata": map[string]interface{}{
				"name":      "my-cr",
				"namespace": "owner-ns",
				"uid":       "uid-123",
			},
		},
	}

	rb := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "managed-rb",
			Namespace: "target-ns",
			Labels:    map[string]string{ManagedLabelKey: ManagedLabelValue},
			Annotations: map[string]string{
				OwnerAnnotationKey: "owner-ns/my-cr/uid-123",
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "ClusterRole",
			Name:     "role",
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(rb, cr).Build()
	target := ScopingTarget{
		WatchGVK:              gvk,
		TargetSA:              types.NamespacedName{Name: "sa", Namespace: "ns"},
		ClusterRoleName:       "role",
		ManagedRoleBindingName: "managed-rb",
	}

	reconciler := &CleanupReconciler{
		Client:  c,
		Targets: []ScopingTarget{target},
	}

	isOrphan := reconciler.cleanupRoleBinding(context.Background(), rb, target)
	if isOrphan {
		t.Error("expected not orphan when owner CR exists with matching UID")
	}

	existing := &rbacv1.RoleBinding{}
	if err := c.Get(context.Background(), types.NamespacedName{Name: "managed-rb", Namespace: "target-ns"}, existing); err != nil {
		t.Fatalf("RoleBinding should still exist: %v", err)
	}
}

func TestCleanupRoleBinding_WithPendingOwner(t *testing.T) {
	scheme := testScheme()
	gvk := schema.GroupVersionKind{Group: "test.io", Version: "v1", Kind: "MyResource"}
	scheme.AddKnownTypeWithName(gvk, &unstructured.Unstructured{})

	// Pending owner with expired timestamp and no CR
	pastTimestamp := time.Now().Add(-5 * time.Minute).UTC().Format(time.RFC3339)
	rb := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "managed-rb",
			Namespace: "test-ns",
			Labels:    map[string]string{ManagedLabelKey: ManagedLabelValue},
			Annotations: map[string]string{
				PendingOwnerAnnotationKey: fmt.Sprintf("test-ns/gone-cr/test.io/v1/MyResource/%s", pastTimestamp),
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "ClusterRole",
			Name:     "role",
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(rb).Build()
	target := ScopingTarget{
		WatchGVK:              gvk,
		TargetSA:              types.NamespacedName{Name: "sa", Namespace: "ns"},
		ClusterRoleName:       "role",
		ManagedRoleBindingName: "managed-rb",
	}

	reconciler := &CleanupReconciler{
		Client:  c,
		Targets: []ScopingTarget{target},
	}

	isOrphan := reconciler.cleanupRoleBinding(context.Background(), rb, target)
	if !isOrphan {
		t.Error("expected orphan when pending-owner CR is gone and TTL expired")
	}
}

func TestCleanupRoleBinding_OwnerDeleted_IsOrphan(t *testing.T) {
	scheme := testScheme()
	gvk := schema.GroupVersionKind{Group: "test.io", Version: "v1", Kind: "MyResource"}
	scheme.AddKnownTypeWithName(gvk, &unstructured.Unstructured{})

	rb := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "managed-rb",
			Namespace: "target-ns",
			Labels:    map[string]string{ManagedLabelKey: ManagedLabelValue},
			Annotations: map[string]string{
				OwnerAnnotationKey: "owner-ns/deleted-cr/uid-gone",
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "ClusterRole",
			Name:     "role",
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(rb).Build()
	target := ScopingTarget{
		WatchGVK:              gvk,
		TargetSA:              types.NamespacedName{Name: "sa", Namespace: "ns"},
		ClusterRoleName:       "role",
		ManagedRoleBindingName: "managed-rb",
	}

	reconciler := &CleanupReconciler{Client: c, Targets: []ScopingTarget{target}}
	isOrphan := reconciler.cleanupRoleBinding(context.Background(), rb, target)
	if !isOrphan {
		t.Error("expected orphan when owner CR is deleted")
	}
}

func TestCleanupRoleBinding_OwnerReplacedWithDifferentUID_IsOrphan(t *testing.T) {
	scheme := testScheme()
	gvk := schema.GroupVersionKind{Group: "test.io", Version: "v1", Kind: "MyResource"}
	scheme.AddKnownTypeWithName(gvk, &unstructured.Unstructured{})

	cr := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "test.io/v1",
			"kind":       "MyResource",
			"metadata": map[string]interface{}{
				"name":      "my-cr",
				"namespace": "owner-ns",
				"uid":       "uid-new-456",
			},
		},
	}

	rb := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "managed-rb",
			Namespace: "target-ns",
			Labels:    map[string]string{ManagedLabelKey: ManagedLabelValue},
			Annotations: map[string]string{
				OwnerAnnotationKey: "owner-ns/my-cr/uid-old-123",
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "ClusterRole",
			Name:     "role",
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(rb, cr).Build()
	target := ScopingTarget{
		WatchGVK:              gvk,
		TargetSA:              types.NamespacedName{Name: "sa", Namespace: "ns"},
		ClusterRoleName:       "role",
		ManagedRoleBindingName: "managed-rb",
	}

	reconciler := &CleanupReconciler{Client: c, Targets: []ScopingTarget{target}}
	isOrphan := reconciler.cleanupRoleBinding(context.Background(), rb, target)
	if !isOrphan {
		t.Error("expected orphan when owner CR has different UID (replaced)")
	}
}

func TestCleanupRoleBinding_CrossNamespace_WrongResolvedNamespace(t *testing.T) {
	scheme := testScheme()
	gvk := schema.GroupVersionKind{Group: "test.io", Version: "v1", Kind: "MyResource"}
	scheme.AddKnownTypeWithName(gvk, &unstructured.Unstructured{})

	cr := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "test.io/v1",
			"kind":       "MyResource",
			"metadata": map[string]interface{}{
				"name":      "my-cr",
				"namespace": "owner-ns",
				"uid":       "uid-123",
			},
			"spec": map[string]interface{}{
				"targetNamespace": "new-target-ns",
			},
		},
	}

	rb := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "managed-rb",
			Namespace: "old-target-ns",
			Labels:    map[string]string{ManagedLabelKey: ManagedLabelValue},
			Annotations: map[string]string{
				OwnerAnnotationKey: "owner-ns/my-cr/uid-123",
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "ClusterRole",
			Name:     "role",
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(rb, cr).Build()
	target := ScopingTarget{
		WatchGVK:              gvk,
		TargetSA:              types.NamespacedName{Name: "sa", Namespace: "ns"},
		ClusterRoleName:       "role",
		ManagedRoleBindingName: "managed-rb",
		TargetNamespaceSource: &NamespaceSource{FieldPath: ".spec.targetNamespace"},
	}

	reconciler := &CleanupReconciler{Client: c, Targets: []ScopingTarget{target}}
	isOrphan := reconciler.cleanupRoleBinding(context.Background(), rb, target)
	if !isOrphan {
		t.Error("expected orphan when CR's resolved namespace doesn't match RoleBinding namespace")
	}
}

func TestCleanupRoleBinding_EmptyAnnotation_NotOrphan(t *testing.T) {
	scheme := testScheme()
	gvk := schema.GroupVersionKind{Group: "test.io", Version: "v1", Kind: "MyResource"}
	scheme.AddKnownTypeWithName(gvk, &unstructured.Unstructured{})

	rb := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "managed-rb",
			Namespace: "test-ns",
			Labels:    map[string]string{ManagedLabelKey: ManagedLabelValue},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "ClusterRole",
			Name:     "role",
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(rb).Build()
	target := ScopingTarget{
		WatchGVK:              gvk,
		TargetSA:              types.NamespacedName{Name: "sa", Namespace: "ns"},
		ClusterRoleName:       "role",
		ManagedRoleBindingName: "managed-rb",
	}

	reconciler := &CleanupReconciler{
		Client:  c,
		Targets: []ScopingTarget{target},
	}

	isOrphan := reconciler.cleanupRoleBinding(context.Background(), rb, target)
	if isOrphan {
		t.Error("expected not orphan when no owner annotation is set")
	}

	existing := &rbacv1.RoleBinding{}
	if err := c.Get(context.Background(), types.NamespacedName{Name: "managed-rb", Namespace: "test-ns"}, existing); err != nil {
		t.Fatalf("RoleBinding should still exist: %v", err)
	}
}
