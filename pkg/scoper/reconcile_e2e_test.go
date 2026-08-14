package scoper

import (
	"context"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// e2eGVK is the GVK used in end-to-end reconcile tests.
// Uses a distinct group/kind from the testGVK() in label_trigger_test.go.
var e2eGVK = schema.GroupVersionKind{Group: "e2e.test.io", Version: "v1", Kind: "Widget"}

// makeSchemeWithGVK builds a scheme with rbacv1, corev1, and e2eGVK registered.
func makeSchemeWithGVK() *runtime.Scheme {
	s := testScheme()
	s.AddKnownTypeWithName(e2eGVK, &unstructured.Unstructured{})
	return s
}

// makeTestCR builds an unstructured CR with e2eGVK and optional spec fields.
func makeTestCR(namespace, name string, spec map[string]interface{}) *unstructured.Unstructured {
	obj := map[string]interface{}{
		"apiVersion": "e2e.test.io/v1",
		"kind":       "Widget",
		"metadata": map[string]interface{}{
			"name":      name,
			"namespace": namespace,
			"uid":       "uid-" + name,
		},
	}
	if spec != nil {
		obj["spec"] = spec
	}
	return &unstructured.Unstructured{Object: obj}
}

// makeClusterRole returns a minimal ClusterRole with the given name.
func makeClusterRole(name string) *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Rules: []rbacv1.PolicyRule{
			{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}},
		},
	}
}

// ---------------------------------------------------------------------------
// Option A end-to-end: static TargetSA
// ---------------------------------------------------------------------------

func TestE2E_OptionA_StaticSA_CreatesRoleBinding(t *testing.T) {
	s := makeSchemeWithGVK()
	cr := makeTestCR("app-ns", "my-cr", nil)
	clusterRole := makeClusterRole("my-clusterrole")

	c := fake.NewClientBuilder().WithScheme(s).WithObjects(cr, clusterRole).Build()

	target := ScopingTarget{
		WatchGVK:               e2eGVK,
		ClusterRoleName:        "my-clusterrole",
		ManagedRoleBindingName: "managed-rb",
		TargetSA:               types.NamespacedName{Name: "operator-sa", Namespace: "operator-ns"},
	}
	rec, err := NewScopingReconciler(c, target, DenyListConfig{}, record.NewFakeRecorder(10))
	if err != nil {
		t.Fatalf("NewScopingReconciler: %v", err)
	}

	_, err = rec.Reconcile(context.Background(), reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "my-cr", Namespace: "app-ns"},
	})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	rb := &rbacv1.RoleBinding{}
	if err := c.Get(context.Background(), types.NamespacedName{Name: "managed-rb", Namespace: "app-ns"}, rb); err != nil {
		t.Fatalf("expected RoleBinding to exist: %v", err)
	}
	if rb.RoleRef.Name != "my-clusterrole" {
		t.Errorf("RoleRef: got %q, want %q", rb.RoleRef.Name, "my-clusterrole")
	}
	if len(rb.Subjects) != 1 || rb.Subjects[0].Name != "operator-sa" || rb.Subjects[0].Namespace != "operator-ns" {
		t.Errorf("Subjects: got %+v, want [{operator-sa operator-ns}]", rb.Subjects)
	}
}

// ---------------------------------------------------------------------------
// Option B end-to-end: TargetSASource (dynamic from CR spec fields)
// ---------------------------------------------------------------------------

func TestE2E_OptionB_SASource_NameOnly_UsesFieldAndCRNamespace(t *testing.T) {
	s := makeSchemeWithGVK()
	cr := makeTestCR("app-ns", "my-cr", map[string]interface{}{
		"serviceAccountName": "tenant-sa",
	})
	clusterRole := makeClusterRole("my-clusterrole")

	c := fake.NewClientBuilder().WithScheme(s).WithObjects(cr, clusterRole).Build()

	target := ScopingTarget{
		WatchGVK:               e2eGVK,
		ClusterRoleName:        "my-clusterrole",
		ManagedRoleBindingName: "managed-rb",
		TargetSASource: &SASource{
			NameFieldPath: ".spec.serviceAccountName",
		},
	}
	rec, err := NewScopingReconciler(c, target, DenyListConfig{}, record.NewFakeRecorder(10))
	if err != nil {
		t.Fatalf("NewScopingReconciler: %v", err)
	}

	_, err = rec.Reconcile(context.Background(), reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "my-cr", Namespace: "app-ns"},
	})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	rb := &rbacv1.RoleBinding{}
	if err := c.Get(context.Background(), types.NamespacedName{Name: "managed-rb", Namespace: "app-ns"}, rb); err != nil {
		t.Fatalf("expected RoleBinding to exist: %v", err)
	}
	if len(rb.Subjects) != 1 {
		t.Fatalf("expected 1 subject, got %d", len(rb.Subjects))
	}
	// SA name comes from spec; namespace falls back to CR's own namespace
	if rb.Subjects[0].Name != "tenant-sa" {
		t.Errorf("SA name: got %q, want %q", rb.Subjects[0].Name, "tenant-sa")
	}
	if rb.Subjects[0].Namespace != "app-ns" {
		t.Errorf("SA namespace: got %q, want %q (CR namespace fallback)", rb.Subjects[0].Namespace, "app-ns")
	}
}

func TestE2E_OptionB_SASource_NameAndNamespace_BothFromSpec(t *testing.T) {
	s := makeSchemeWithGVK()
	cr := makeTestCR("app-ns", "my-cr", map[string]interface{}{
		"serviceAccountName":      "tenant-sa",
		"serviceAccountNamespace": "tenant-ops",
	})
	clusterRole := makeClusterRole("my-clusterrole")

	c := fake.NewClientBuilder().WithScheme(s).WithObjects(cr, clusterRole).Build()

	target := ScopingTarget{
		WatchGVK:               e2eGVK,
		ClusterRoleName:        "my-clusterrole",
		ManagedRoleBindingName: "managed-rb",
		TargetSASource: &SASource{
			NameFieldPath:      ".spec.serviceAccountName",
			NamespaceFieldPath: ".spec.serviceAccountNamespace",
		},
	}
	rec, err := NewScopingReconciler(c, target, DenyListConfig{}, record.NewFakeRecorder(10))
	if err != nil {
		t.Fatalf("NewScopingReconciler: %v", err)
	}

	_, err = rec.Reconcile(context.Background(), reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "my-cr", Namespace: "app-ns"},
	})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	rb := &rbacv1.RoleBinding{}
	if err := c.Get(context.Background(), types.NamespacedName{Name: "managed-rb", Namespace: "app-ns"}, rb); err != nil {
		t.Fatalf("expected RoleBinding to exist: %v", err)
	}
	if len(rb.Subjects) != 1 {
		t.Fatalf("expected 1 subject, got %d", len(rb.Subjects))
	}
	if rb.Subjects[0].Name != "tenant-sa" || rb.Subjects[0].Namespace != "tenant-ops" {
		t.Errorf("Subjects: got %+v, want [{tenant-sa tenant-ops}]", rb.Subjects)
	}
}

func TestE2E_OptionB_SASource_MissingNameField_ReturnsError(t *testing.T) {
	s := makeSchemeWithGVK()
	// CR has no spec.serviceAccountName
	cr := makeTestCR("app-ns", "my-cr", nil)
	clusterRole := makeClusterRole("my-clusterrole")

	c := fake.NewClientBuilder().WithScheme(s).WithObjects(cr, clusterRole).Build()

	target := ScopingTarget{
		WatchGVK:               e2eGVK,
		ClusterRoleName:        "my-clusterrole",
		ManagedRoleBindingName: "managed-rb",
		TargetSASource: &SASource{
			NameFieldPath: ".spec.serviceAccountName",
		},
	}
	rec, err := NewScopingReconciler(c, target, DenyListConfig{}, record.NewFakeRecorder(10))
	if err != nil {
		t.Fatalf("NewScopingReconciler: %v", err)
	}

	_, err = rec.Reconcile(context.Background(), reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "my-cr", Namespace: "app-ns"},
	})
	if err == nil {
		t.Fatal("expected error when SA name field is missing from CR, got nil")
	}

	// No RoleBinding should have been created
	rb := &rbacv1.RoleBinding{}
	getErr := c.Get(context.Background(), types.NamespacedName{Name: "managed-rb", Namespace: "app-ns"}, rb)
	if getErr == nil {
		t.Error("expected no RoleBinding to be created when SA resolution fails")
	}
}

func TestE2E_OptionB_SASource_MissingNamespaceField_ReturnsError(t *testing.T) {
	s := makeSchemeWithGVK()
	// spec has SA name but not the namespace field
	cr := makeTestCR("app-ns", "my-cr", map[string]interface{}{
		"serviceAccountName": "tenant-sa",
		// serviceAccountNamespace intentionally absent
	})
	clusterRole := makeClusterRole("my-clusterrole")

	c := fake.NewClientBuilder().WithScheme(s).WithObjects(cr, clusterRole).Build()

	target := ScopingTarget{
		WatchGVK:               e2eGVK,
		ClusterRoleName:        "my-clusterrole",
		ManagedRoleBindingName: "managed-rb",
		TargetSASource: &SASource{
			NameFieldPath:      ".spec.serviceAccountName",
			NamespaceFieldPath: ".spec.serviceAccountNamespace", // required but absent
		},
	}
	rec, err := NewScopingReconciler(c, target, DenyListConfig{}, record.NewFakeRecorder(10))
	if err != nil {
		t.Fatalf("NewScopingReconciler: %v", err)
	}

	_, err = rec.Reconcile(context.Background(), reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "my-cr", Namespace: "app-ns"},
	})
	if err == nil {
		t.Fatal("expected error when namespace field is absent from CR, got nil")
	}
}

// ---------------------------------------------------------------------------
// Option C end-to-end: TargetSAFunc (callback closure)
// ---------------------------------------------------------------------------

func TestE2E_OptionC_SAFunc_CreatesRoleBindingWithReturnedSA(t *testing.T) {
	s := makeSchemeWithGVK()
	cr := makeTestCR("app-ns", "my-cr", map[string]interface{}{
		"tenantID": "acme",
	})
	clusterRole := makeClusterRole("my-clusterrole")

	c := fake.NewClientBuilder().WithScheme(s).WithObjects(cr, clusterRole).Build()

	target := ScopingTarget{
		WatchGVK:               e2eGVK,
		ClusterRoleName:        "my-clusterrole",
		ManagedRoleBindingName: "managed-rb",
		TargetSAFunc: func(cr *unstructured.Unstructured) types.NamespacedName {
			tenantID, _, _ := unstructured.NestedString(cr.Object, "spec", "tenantID")
			return types.NamespacedName{
				Name:      "sa-" + tenantID,
				Namespace: cr.GetNamespace() + "-ops",
			}
		},
	}
	rec, err := NewScopingReconciler(c, target, DenyListConfig{}, record.NewFakeRecorder(10))
	if err != nil {
		t.Fatalf("NewScopingReconciler: %v", err)
	}

	_, err = rec.Reconcile(context.Background(), reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "my-cr", Namespace: "app-ns"},
	})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	rb := &rbacv1.RoleBinding{}
	if err := c.Get(context.Background(), types.NamespacedName{Name: "managed-rb", Namespace: "app-ns"}, rb); err != nil {
		t.Fatalf("expected RoleBinding to exist: %v", err)
	}
	if len(rb.Subjects) != 1 {
		t.Fatalf("expected 1 subject, got %d", len(rb.Subjects))
	}
	if rb.Subjects[0].Name != "sa-acme" || rb.Subjects[0].Namespace != "app-ns-ops" {
		t.Errorf("Subjects: got %+v, want [{sa-acme app-ns-ops}]", rb.Subjects)
	}
}

func TestE2E_OptionC_SAFunc_EmptyReturn_CreatesRBWithEmptySubject(t *testing.T) {
	// TargetSAFunc returning an empty NamespacedName is valid from the library's
	// perspective — the caller's func is responsible for correctness. The RoleBinding
	// should still be created with whatever the func returns.
	s := makeSchemeWithGVK()
	cr := makeTestCR("app-ns", "my-cr", nil)
	clusterRole := makeClusterRole("my-clusterrole")

	c := fake.NewClientBuilder().WithScheme(s).WithObjects(cr, clusterRole).Build()

	target := ScopingTarget{
		WatchGVK:               e2eGVK,
		ClusterRoleName:        "my-clusterrole",
		ManagedRoleBindingName: "managed-rb",
		TargetSAFunc:           func(_ *unstructured.Unstructured) types.NamespacedName { return types.NamespacedName{} },
	}
	rec, err := NewScopingReconciler(c, target, DenyListConfig{}, record.NewFakeRecorder(10))
	if err != nil {
		t.Fatalf("NewScopingReconciler: %v", err)
	}

	_, err = rec.Reconcile(context.Background(), reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "my-cr", Namespace: "app-ns"},
	})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	rb := &rbacv1.RoleBinding{}
	if err := c.Get(context.Background(), types.NamespacedName{Name: "managed-rb", Namespace: "app-ns"}, rb); err != nil {
		t.Fatalf("expected RoleBinding to exist: %v", err)
	}
	// Subject exists but with empty name/namespace — the func chose to return empty
	if len(rb.Subjects) != 1 {
		t.Fatalf("expected 1 subject, got %d", len(rb.Subjects))
	}
	if rb.Subjects[0].Name != "" || rb.Subjects[0].Namespace != "" {
		t.Errorf("expected empty subject, got %+v", rb.Subjects[0])
	}
}

// ---------------------------------------------------------------------------
// ManagedRoleBindingNameFunc: multiple CRs in same namespace
// ---------------------------------------------------------------------------

func TestE2E_ManagedRoleBindingNameFunc_TwoCRsSameNamespace_SeparateRoleBindings(t *testing.T) {
	s := makeSchemeWithGVK()
	cr1 := makeTestCR("app-ns", "tenant-a", map[string]interface{}{
		"serviceAccountName": "sa-a",
	})
	cr2 := makeTestCR("app-ns", "tenant-b", map[string]interface{}{
		"serviceAccountName": "sa-b",
	})
	clusterRole := makeClusterRole("my-clusterrole")

	c := fake.NewClientBuilder().WithScheme(s).WithObjects(cr1, cr2, clusterRole).Build()

	target := ScopingTarget{
		WatchGVK:        e2eGVK,
		ClusterRoleName: "my-clusterrole",
		TargetSASource: &SASource{
			NameFieldPath: ".spec.serviceAccountName",
		},
		ManagedRoleBindingNameFunc: func(cr *unstructured.Unstructured) string {
			return "rb-" + cr.GetName()
		},
	}
	rec, err := NewScopingReconciler(c, target, DenyListConfig{}, record.NewFakeRecorder(10))
	if err != nil {
		t.Fatalf("NewScopingReconciler: %v", err)
	}

	for _, crName := range []string{"tenant-a", "tenant-b"} {
		_, err = rec.Reconcile(context.Background(), reconcile.Request{
			NamespacedName: types.NamespacedName{Name: crName, Namespace: "app-ns"},
		})
		if err != nil {
			t.Fatalf("Reconcile(%s): %v", crName, err)
		}
	}

	// Each CR should have its own RoleBinding with its own SA as subject
	for _, tt := range []struct {
		rbName string
		saName string
	}{
		{"rb-tenant-a", "sa-a"},
		{"rb-tenant-b", "sa-b"},
	} {
		rb := &rbacv1.RoleBinding{}
		if err := c.Get(context.Background(), types.NamespacedName{Name: tt.rbName, Namespace: "app-ns"}, rb); err != nil {
			t.Fatalf("expected RoleBinding %q to exist: %v", tt.rbName, err)
		}
		if len(rb.Subjects) != 1 || rb.Subjects[0].Name != tt.saName {
			t.Errorf("RoleBinding %q: expected SA %q, got %+v", tt.rbName, tt.saName, rb.Subjects)
		}
	}
}

func TestE2E_ManagedRoleBindingNameFunc_WithStaticSA_TwoCRs(t *testing.T) {
	// Even with Option A (static SA), multiple CRs in the same namespace
	// can coexist if ManagedRoleBindingNameFunc gives them different RB names.
	s := makeSchemeWithGVK()
	cr1 := makeTestCR("app-ns", "cr-1", nil)
	cr2 := makeTestCR("app-ns", "cr-2", nil)
	clusterRole := makeClusterRole("my-clusterrole")

	c := fake.NewClientBuilder().WithScheme(s).WithObjects(cr1, cr2, clusterRole).Build()

	target := ScopingTarget{
		WatchGVK:        e2eGVK,
		ClusterRoleName: "my-clusterrole",
		TargetSA:        types.NamespacedName{Name: "operator-sa", Namespace: "operator-ns"},
		ManagedRoleBindingNameFunc: func(cr *unstructured.Unstructured) string {
			return "rb-" + cr.GetName()
		},
	}
	rec, err := NewScopingReconciler(c, target, DenyListConfig{}, record.NewFakeRecorder(10))
	if err != nil {
		t.Fatalf("NewScopingReconciler: %v", err)
	}

	for _, crName := range []string{"cr-1", "cr-2"} {
		_, err = rec.Reconcile(context.Background(), reconcile.Request{
			NamespacedName: types.NamespacedName{Name: crName, Namespace: "app-ns"},
		})
		if err != nil {
			t.Fatalf("Reconcile(%s): %v", crName, err)
		}
	}

	for _, rbName := range []string{"rb-cr-1", "rb-cr-2"} {
		rb := &rbacv1.RoleBinding{}
		if err := c.Get(context.Background(), types.NamespacedName{Name: rbName, Namespace: "app-ns"}, rb); err != nil {
			t.Fatalf("expected RoleBinding %q to exist: %v", rbName, err)
		}
		if len(rb.Subjects) != 1 || rb.Subjects[0].Name != "operator-sa" {
			t.Errorf("RoleBinding %q: unexpected subjects %+v", rbName, rb.Subjects)
		}
	}
}

// ---------------------------------------------------------------------------
// Drift correction with Options B and C
// ---------------------------------------------------------------------------

func TestE2E_OptionB_Drift_SAChanges_SubjectUpdated(t *testing.T) {
	// First reconcile: SA is "old-sa". Second reconcile: SA changes to "new-sa".
	// Verify the subjects on the RoleBinding are corrected.
	s := makeSchemeWithGVK()
	cr := makeTestCR("app-ns", "my-cr", map[string]interface{}{
		"serviceAccountName": "old-sa",
	})
	clusterRole := makeClusterRole("my-clusterrole")

	c := fake.NewClientBuilder().WithScheme(s).WithObjects(cr, clusterRole).Build()

	target := ScopingTarget{
		WatchGVK:               e2eGVK,
		ClusterRoleName:        "my-clusterrole",
		ManagedRoleBindingName: "managed-rb",
		TargetSASource: &SASource{
			NameFieldPath: ".spec.serviceAccountName",
		},
	}
	rec, err := NewScopingReconciler(c, target, DenyListConfig{}, record.NewFakeRecorder(10))
	if err != nil {
		t.Fatalf("NewScopingReconciler: %v", err)
	}

	// First reconcile: RoleBinding created with old-sa
	if _, err = rec.Reconcile(context.Background(), reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "my-cr", Namespace: "app-ns"},
	}); err != nil {
		t.Fatalf("first Reconcile: %v", err)
	}

	// Update the CR to use new-sa
	updated := cr.DeepCopy()
	updated.Object["spec"] = map[string]interface{}{"serviceAccountName": "new-sa"}
	if err := c.Update(context.Background(), updated); err != nil {
		t.Fatalf("updating CR: %v", err)
	}

	// Second reconcile: subjects should be updated to new-sa
	if _, err = rec.Reconcile(context.Background(), reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "my-cr", Namespace: "app-ns"},
	}); err != nil {
		t.Fatalf("second Reconcile: %v", err)
	}

	rb := &rbacv1.RoleBinding{}
	if err := c.Get(context.Background(), types.NamespacedName{Name: "managed-rb", Namespace: "app-ns"}, rb); err != nil {
		t.Fatalf("expected RoleBinding to exist: %v", err)
	}
	if len(rb.Subjects) != 1 || rb.Subjects[0].Name != "new-sa" {
		t.Errorf("expected subject new-sa, got %+v", rb.Subjects)
	}
}

func TestE2E_OptionC_Drift_FuncReturnChanges_SubjectUpdated(t *testing.T) {
	s := makeSchemeWithGVK()
	cr := makeTestCR("app-ns", "my-cr", nil)
	clusterRole := makeClusterRole("my-clusterrole")
	c := fake.NewClientBuilder().WithScheme(s).WithObjects(cr, clusterRole).Build()

	// Func starts returning sa-v1, then we swap it to sa-v2 for the second reconcile.
	returnedSA := types.NamespacedName{Name: "sa-v1", Namespace: "operator-ns"}
	target := ScopingTarget{
		WatchGVK:               e2eGVK,
		ClusterRoleName:        "my-clusterrole",
		ManagedRoleBindingName: "managed-rb",
		TargetSAFunc:           func(_ *unstructured.Unstructured) types.NamespacedName { return returnedSA },
	}
	rec, err := NewScopingReconciler(c, target, DenyListConfig{}, record.NewFakeRecorder(10))
	if err != nil {
		t.Fatalf("NewScopingReconciler: %v", err)
	}

	if _, err = rec.Reconcile(context.Background(), reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "my-cr", Namespace: "app-ns"},
	}); err != nil {
		t.Fatalf("first Reconcile: %v", err)
	}

	// Simulate the func returning a different SA on next reconcile
	returnedSA = types.NamespacedName{Name: "sa-v2", Namespace: "operator-ns"}
	rec.Target.TargetSAFunc = func(_ *unstructured.Unstructured) types.NamespacedName { return returnedSA }

	if _, err = rec.Reconcile(context.Background(), reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "my-cr", Namespace: "app-ns"},
	}); err != nil {
		t.Fatalf("second Reconcile: %v", err)
	}

	rb := &rbacv1.RoleBinding{}
	if err := c.Get(context.Background(), types.NamespacedName{Name: "managed-rb", Namespace: "app-ns"}, rb); err != nil {
		t.Fatalf("expected RoleBinding to exist: %v", err)
	}
	if len(rb.Subjects) != 1 || rb.Subjects[0].Name != "sa-v2" {
		t.Errorf("expected subject sa-v2, got %+v", rb.Subjects)
	}
}

// ---------------------------------------------------------------------------
// Mutual exclusivity validation
// ---------------------------------------------------------------------------

func TestValidateTarget_AllThreeSAOptions_RejectsMultiple(t *testing.T) {
	tests := []struct {
		name   string
		target ScopingTarget
	}{
		{
			name: "A+B",
			target: ScopingTarget{
				WatchGVK: e2eGVK, ClusterRoleName: "role", ManagedRoleBindingName: "rb",
				TargetSA:       types.NamespacedName{Name: "sa", Namespace: "ns"},
				TargetSASource: &SASource{NameFieldPath: ".spec.sa"},
			},
		},
		{
			name: "A+C",
			target: ScopingTarget{
				WatchGVK: e2eGVK, ClusterRoleName: "role", ManagedRoleBindingName: "rb",
				TargetSA:     types.NamespacedName{Name: "sa", Namespace: "ns"},
				TargetSAFunc: func(*unstructured.Unstructured) types.NamespacedName { return types.NamespacedName{} },
			},
		},
		{
			name: "B+C",
			target: ScopingTarget{
				WatchGVK: e2eGVK, ClusterRoleName: "role", ManagedRoleBindingName: "rb",
				TargetSASource: &SASource{NameFieldPath: ".spec.sa"},
				TargetSAFunc:   func(*unstructured.Unstructured) types.NamespacedName { return types.NamespacedName{} },
			},
		},
		{
			name: "A+B+C",
			target: ScopingTarget{
				WatchGVK: e2eGVK, ClusterRoleName: "role", ManagedRoleBindingName: "rb",
				TargetSA:       types.NamespacedName{Name: "sa", Namespace: "ns"},
				TargetSASource: &SASource{NameFieldPath: ".spec.sa"},
				TargetSAFunc:   func(*unstructured.Unstructured) types.NamespacedName { return types.NamespacedName{} },
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateTarget(tt.target); err == nil {
				t.Fatalf("expected validation error for %s, got nil", tt.name)
			}
		})
	}
}

func TestValidateTarget_EachOptionAlone_Accepted(t *testing.T) {
	tests := []struct {
		name   string
		target ScopingTarget
	}{
		{
			name: "A only",
			target: ScopingTarget{
				WatchGVK: e2eGVK, ClusterRoleName: "role", ManagedRoleBindingName: "rb",
				TargetSA: types.NamespacedName{Name: "sa", Namespace: "ns"},
			},
		},
		{
			name: "B only",
			target: ScopingTarget{
				WatchGVK: e2eGVK, ClusterRoleName: "role", ManagedRoleBindingName: "rb",
				TargetSASource: &SASource{NameFieldPath: ".spec.sa"},
			},
		},
		{
			name: "C only",
			target: ScopingTarget{
				WatchGVK: e2eGVK, ClusterRoleName: "role", ManagedRoleBindingName: "rb",
				TargetSAFunc: func(*unstructured.Unstructured) types.NamespacedName { return types.NamespacedName{} },
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateTarget(tt.target); err != nil {
				t.Fatalf("%s: unexpected validation error: %v", tt.name, err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Option B idempotency: reconciling twice doesn't duplicate subjects
// ---------------------------------------------------------------------------

func TestE2E_OptionB_Idempotent_SecondReconcileNoop(t *testing.T) {
	s := makeSchemeWithGVK()
	cr := makeTestCR("app-ns", "my-cr", map[string]interface{}{
		"serviceAccountName": "my-sa",
	})
	clusterRole := makeClusterRole("my-clusterrole")

	c := fake.NewClientBuilder().WithScheme(s).WithObjects(cr, clusterRole).Build()

	target := ScopingTarget{
		WatchGVK:               e2eGVK,
		ClusterRoleName:        "my-clusterrole",
		ManagedRoleBindingName: "managed-rb",
		TargetSASource:         &SASource{NameFieldPath: ".spec.serviceAccountName"},
	}
	rec, err := NewScopingReconciler(c, target, DenyListConfig{}, record.NewFakeRecorder(10))
	if err != nil {
		t.Fatalf("NewScopingReconciler: %v", err)
	}

	req := reconcile.Request{NamespacedName: types.NamespacedName{Name: "my-cr", Namespace: "app-ns"}}
	for i := 0; i < 3; i++ {
		if _, err = rec.Reconcile(context.Background(), req); err != nil {
			t.Fatalf("Reconcile iteration %d: %v", i, err)
		}
	}

	rb := &rbacv1.RoleBinding{}
	if err := c.Get(context.Background(), types.NamespacedName{Name: "managed-rb", Namespace: "app-ns"}, rb); err != nil {
		t.Fatalf("expected RoleBinding: %v", err)
	}
	if len(rb.Subjects) != 1 {
		t.Errorf("expected exactly 1 subject after 3 reconciles, got %d: %+v", len(rb.Subjects), rb.Subjects)
	}
}

func TestE2E_OptionC_Idempotent_SecondReconcileNoop(t *testing.T) {
	s := makeSchemeWithGVK()
	cr := makeTestCR("app-ns", "my-cr", nil)
	clusterRole := makeClusterRole("my-clusterrole")

	c := fake.NewClientBuilder().WithScheme(s).WithObjects(cr, clusterRole).Build()

	target := ScopingTarget{
		WatchGVK:               e2eGVK,
		ClusterRoleName:        "my-clusterrole",
		ManagedRoleBindingName: "managed-rb",
		TargetSAFunc: func(cr *unstructured.Unstructured) types.NamespacedName {
			return types.NamespacedName{Name: "computed-sa", Namespace: "ops-ns"}
		},
	}
	rec, err := NewScopingReconciler(c, target, DenyListConfig{}, record.NewFakeRecorder(10))
	if err != nil {
		t.Fatalf("NewScopingReconciler: %v", err)
	}

	req := reconcile.Request{NamespacedName: types.NamespacedName{Name: "my-cr", Namespace: "app-ns"}}
	for i := 0; i < 3; i++ {
		if _, err = rec.Reconcile(context.Background(), req); err != nil {
			t.Fatalf("Reconcile iteration %d: %v", i, err)
		}
	}

	rb := &rbacv1.RoleBinding{}
	if err := c.Get(context.Background(), types.NamespacedName{Name: "managed-rb", Namespace: "app-ns"}, rb); err != nil {
		t.Fatalf("expected RoleBinding: %v", err)
	}
	if len(rb.Subjects) != 1 || rb.Subjects[0].Name != "computed-sa" {
		t.Errorf("expected [{computed-sa ops-ns}], got %+v", rb.Subjects)
	}
}
