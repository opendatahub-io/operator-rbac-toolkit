package scoper

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestNewLabelTriggerReconciler(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(testScheme()).Build()

	t.Run("valid label selector", func(t *testing.T) {
		target := ScopingTarget{
			WatchGVK:               testGVK(),
			TargetSA:               types.NamespacedName{Name: "sa", Namespace: "default"},
			ClusterRoleName:        "role",
			ManagedRoleBindingName: "binding",
			NamespaceLabelTrigger: &metav1.LabelSelector{
				MatchLabels: map[string]string{"foo": "bar"},
			},
		}

		rec, err := NewLabelTriggerReconciler(c, target, DenyListConfig{})
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if rec == nil {
			t.Fatal("expected reconciler, got nil")
		}
	})

	t.Run("nil label selector", func(t *testing.T) {
		target := ScopingTarget{
			WatchGVK:               testGVK(),
			TargetSA:               types.NamespacedName{Name: "sa", Namespace: "default"},
			ClusterRoleName:        "role",
			ManagedRoleBindingName: "binding",
			NamespaceLabelTrigger:  nil,
		}

		_, err := NewLabelTriggerReconciler(c, target, DenyListConfig{})
		if err == nil {
			t.Fatal("expected error for nil NamespaceLabelTrigger")
		}
	})

	t.Run("invalid label selector", func(t *testing.T) {
		target := ScopingTarget{
			WatchGVK:               testGVK(),
			TargetSA:               types.NamespacedName{Name: "sa", Namespace: "default"},
			ClusterRoleName:        "role",
			ManagedRoleBindingName: "binding",
			NamespaceLabelTrigger: &metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{
						Key:      "foo",
						Operator: "InvalidOperator",
						Values:   []string{"bar"},
					},
				},
			},
		}

		_, err := NewLabelTriggerReconciler(c, target, DenyListConfig{})
		if err == nil {
			t.Fatal("expected error for invalid label selector")
		}
	})
}

func TestLabelTriggerReconciler_MatchingNamespace(t *testing.T) {
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "test-ns",
			Labels: map[string]string{"team": "ml"},
		},
	}

	c := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(ns).Build()

	target := ScopingTarget{
		WatchGVK:               testGVK(),
		TargetSA:               types.NamespacedName{Name: "sa", Namespace: "default"},
		ClusterRoleName:        "role",
		ManagedRoleBindingName: "scoped-binding",
		NamespaceLabelTrigger: &metav1.LabelSelector{
			MatchLabels: map[string]string{"team": "ml"},
		},
	}

	rec, err := NewLabelTriggerReconciler(c, target, DenyListConfig{})
	if err != nil {
		t.Fatalf("failed to create reconciler: %v", err)
	}

	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: "test-ns"}}
	_, err = rec.Reconcile(context.Background(), req)
	if err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}

	// Verify RoleBinding was created
	rb := &rbacv1.RoleBinding{}
	err = c.Get(context.Background(), types.NamespacedName{Name: "scoped-binding", Namespace: "test-ns"}, rb)
	if err != nil {
		t.Fatalf("RoleBinding not created: %v", err)
	}

	// Verify annotations and labels
	if rb.Labels[ManagedLabelKey] != ManagedLabelValue {
		t.Errorf("expected ManagedLabel, got %v", rb.Labels)
	}
	if rb.Annotations[CreatedByAnnotationKey] != CreatedByLabelTrigger {
		t.Errorf("expected created-by: label-trigger, got %v", rb.Annotations[CreatedByAnnotationKey])
	}

	// Verify no OwnerReference
	if len(rb.OwnerReferences) > 0 {
		t.Errorf("expected no OwnerReference, got %v", rb.OwnerReferences)
	}

	// Verify no pending-owner annotation
	if rb.Annotations[PendingOwnerAnnotationKey] != "" {
		t.Errorf("expected no pending-owner, got %v", rb.Annotations[PendingOwnerAnnotationKey])
	}

	// Verify RoleRef and Subjects
	if rb.RoleRef.Name != "role" {
		t.Errorf("expected ClusterRole 'role', got %v", rb.RoleRef.Name)
	}
	if len(rb.Subjects) != 1 || rb.Subjects[0].Name != "sa" || rb.Subjects[0].Namespace != "default" {
		t.Errorf("expected ServiceAccount default/sa, got %v", rb.Subjects)
	}
}

func TestLabelTriggerReconciler_NonMatchingNamespace(t *testing.T) {
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "test-ns",
			Labels: map[string]string{"team": "backend"},
		},
	}

	c := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(ns).Build()

	target := ScopingTarget{
		WatchGVK:               testGVK(),
		TargetSA:               types.NamespacedName{Name: "sa", Namespace: "default"},
		ClusterRoleName:        "role",
		ManagedRoleBindingName: "scoped-binding",
		NamespaceLabelTrigger: &metav1.LabelSelector{
			MatchLabels: map[string]string{"team": "ml"},
		},
	}

	rec, err := NewLabelTriggerReconciler(c, target, DenyListConfig{})
	if err != nil {
		t.Fatalf("failed to create reconciler: %v", err)
	}

	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: "test-ns"}}
	_, err = rec.Reconcile(context.Background(), req)
	if err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}

	// Verify RoleBinding was NOT created
	rb := &rbacv1.RoleBinding{}
	err = c.Get(context.Background(), types.NamespacedName{Name: "scoped-binding", Namespace: "test-ns"}, rb)
	if !apierrors.IsNotFound(err) {
		t.Errorf("expected RoleBinding to not exist, but it does: %v", rb)
	}
}

func TestLabelTriggerReconciler_LabelRemoved(t *testing.T) {
	// Start with matching namespace and existing RoleBinding
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "test-ns",
			Labels: map[string]string{"team": "ml"},
		},
	}

	rb := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "scoped-binding",
			Namespace: "test-ns",
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
			Name:     "role",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      "sa",
				Namespace: "default",
			},
		},
	}

	c := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(ns, rb).Build()

	target := ScopingTarget{
		WatchGVK:               testGVK(),
		TargetSA:               types.NamespacedName{Name: "sa", Namespace: "default"},
		ClusterRoleName:        "role",
		ManagedRoleBindingName: "scoped-binding",
		NamespaceLabelTrigger: &metav1.LabelSelector{
			MatchLabels: map[string]string{"team": "ml"},
		},
	}

	rec, err := NewLabelTriggerReconciler(c, target, DenyListConfig{})
	if err != nil {
		t.Fatalf("failed to create reconciler: %v", err)
	}

	// Remove the matching label
	ns.Labels = map[string]string{"team": "backend"}
	if err := c.Update(context.Background(), ns); err != nil {
		t.Fatalf("failed to update namespace: %v", err)
	}

	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: "test-ns"}}
	_, err = rec.Reconcile(context.Background(), req)
	if err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}

	// Verify RoleBinding was deleted
	deletedRB := &rbacv1.RoleBinding{}
	err = c.Get(context.Background(), types.NamespacedName{Name: "scoped-binding", Namespace: "test-ns"}, deletedRB)
	if !apierrors.IsNotFound(err) {
		t.Errorf("expected RoleBinding to be deleted, but it still exists")
	}
}

func TestLabelTriggerReconciler_DeniedNamespace(t *testing.T) {
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "kube-system",
			Labels: map[string]string{"team": "ml"},
		},
	}

	c := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(ns).Build()

	target := ScopingTarget{
		WatchGVK:               testGVK(),
		TargetSA:               types.NamespacedName{Name: "sa", Namespace: "default"},
		ClusterRoleName:        "role",
		ManagedRoleBindingName: "scoped-binding",
		NamespaceLabelTrigger: &metav1.LabelSelector{
			MatchLabels: map[string]string{"team": "ml"},
		},
	}

	denyList := DenyListConfig{
		Namespaces: []string{"kube-system"},
	}

	rec, err := NewLabelTriggerReconciler(c, target, denyList)
	if err != nil {
		t.Fatalf("failed to create reconciler: %v", err)
	}

	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: "kube-system"}}
	_, err = rec.Reconcile(context.Background(), req)
	if err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}

	// Verify RoleBinding was NOT created
	rb := &rbacv1.RoleBinding{}
	err = c.Get(context.Background(), types.NamespacedName{Name: "scoped-binding", Namespace: "kube-system"}, rb)
	if !apierrors.IsNotFound(err) {
		t.Errorf("expected RoleBinding to not exist in denied namespace, but it does: %v", rb)
	}
}

func TestLabelTriggerReconciler_AlreadyExists(t *testing.T) {
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "test-ns",
			Labels: map[string]string{"team": "ml"},
		},
	}

	// Pre-existing RoleBinding (e.g., created by another reconcile)
	rb := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "scoped-binding",
			Namespace: "test-ns",
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
			Name:     "role",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      "sa",
				Namespace: "default",
			},
		},
	}

	c := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(ns, rb).Build()

	target := ScopingTarget{
		WatchGVK:               testGVK(),
		TargetSA:               types.NamespacedName{Name: "sa", Namespace: "default"},
		ClusterRoleName:        "role",
		ManagedRoleBindingName: "scoped-binding",
		NamespaceLabelTrigger: &metav1.LabelSelector{
			MatchLabels: map[string]string{"team": "ml"},
		},
	}

	rec, err := NewLabelTriggerReconciler(c, target, DenyListConfig{})
	if err != nil {
		t.Fatalf("failed to create reconciler: %v", err)
	}

	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: "test-ns"}}
	_, err = rec.Reconcile(context.Background(), req)
	if err != nil {
		t.Fatalf("reconcile failed on AlreadyExists: %v", err)
	}

	// Verify RoleBinding still exists (not an error)
	existingRB := &rbacv1.RoleBinding{}
	err = c.Get(context.Background(), types.NamespacedName{Name: "scoped-binding", Namespace: "test-ns"}, existingRB)
	if err != nil {
		t.Fatalf("RoleBinding should still exist: %v", err)
	}
}

func TestLabelTriggerReconciler_DoesNotDeleteNonLabelTriggerRoleBinding(t *testing.T) {
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "test-ns",
			Labels: map[string]string{"team": "backend"},
		},
	}

	// RoleBinding created by scoper (not label-trigger)
	rb := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "scoped-binding",
			Namespace: "test-ns",
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
			Name:     "role",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      "sa",
				Namespace: "default",
			},
		},
	}

	c := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(ns, rb).Build()

	target := ScopingTarget{
		WatchGVK:               testGVK(),
		TargetSA:               types.NamespacedName{Name: "sa", Namespace: "default"},
		ClusterRoleName:        "role",
		ManagedRoleBindingName: "scoped-binding",
		NamespaceLabelTrigger: &metav1.LabelSelector{
			MatchLabels: map[string]string{"team": "ml"},
		},
	}

	rec, err := NewLabelTriggerReconciler(c, target, DenyListConfig{})
	if err != nil {
		t.Fatalf("failed to create reconciler: %v", err)
	}

	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: "test-ns"}}
	_, err = rec.Reconcile(context.Background(), req)
	if err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}

	// Verify RoleBinding still exists (not deleted because it's not created by label-trigger)
	existingRB := &rbacv1.RoleBinding{}
	err = c.Get(context.Background(), types.NamespacedName{Name: "scoped-binding", Namespace: "test-ns"}, existingRB)
	if err != nil {
		t.Fatalf("RoleBinding should not be deleted when created by different component: %v", err)
	}
	if existingRB.Annotations[CreatedByAnnotationKey] != CreatedByScoper {
		t.Errorf("RoleBinding annotation should remain unchanged")
	}
}

func TestLabelTriggerReconciler_NamespaceNotFound(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(testScheme()).Build()

	target := ScopingTarget{
		WatchGVK:               testGVK(),
		TargetSA:               types.NamespacedName{Name: "sa", Namespace: "default"},
		ClusterRoleName:        "role",
		ManagedRoleBindingName: "scoped-binding",
		NamespaceLabelTrigger: &metav1.LabelSelector{
			MatchLabels: map[string]string{"team": "ml"},
		},
	}

	rec, err := NewLabelTriggerReconciler(c, target, DenyListConfig{})
	if err != nil {
		t.Fatalf("failed to create reconciler: %v", err)
	}

	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: "deleted-ns"}}
	_, err = rec.Reconcile(context.Background(), req)
	if err != nil {
		t.Fatalf("reconcile should handle NotFound gracefully: %v", err)
	}
}

// testGVK returns a test GVK for use in tests
func testGVK() schema.GroupVersionKind {
	return schema.GroupVersionKind{
		Group:   "apps",
		Version: "v1",
		Kind:    "Deployment",
	}
}
