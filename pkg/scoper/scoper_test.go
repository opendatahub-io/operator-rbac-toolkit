package scoper

import (
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func testScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	_ = rbacv1.AddToScheme(s)
	_ = corev1.AddToScheme(s)
	return s
}

// ---------------------------------------------------------------------------
// IsDenied tests
// ---------------------------------------------------------------------------

func TestIsDenied(t *testing.T) {
	denyList := DenyListConfig{
		Namespaces: []string{"kube-system", "kube-public", "default"},
		Prefixes:   []string{"openshift-", "test-"},
	}

	tests := []struct {
		name      string
		namespace string
		want      bool
	}{
		{"exact match kube-system", "kube-system", true},
		{"exact match default", "default", true},
		{"exact match kube-public", "kube-public", true},
		{"prefix match openshift-monitoring", "openshift-monitoring", true},
		{"prefix match openshift-", "openshift-", true},
		{"prefix match test-ns", "test-ns", true},
		{"allowed namespace", "my-app", false},
		{"partial overlap not denied", "kube-systemx", false},
		{"prefix substring not denied", "notest-ns", false},
		{"empty namespace", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsDenied(tt.namespace, denyList)
			if got != tt.want {
				t.Errorf("IsDenied(%q) = %v, want %v", tt.namespace, got, tt.want)
			}
		})
	}
}

func TestIsDenied_EmptyDenyList(t *testing.T) {
	dl := DenyListConfig{}
	if IsDenied("anything", dl) {
		t.Error("empty deny list should deny nothing")
	}
}

// ---------------------------------------------------------------------------
// ValidateClusterRole tests
// ---------------------------------------------------------------------------

func TestValidateClusterRole_Valid(t *testing.T) {
	cr := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "my-role"},
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{""},
			Resources: []string{"pods"},
			Verbs:     []string{"get", "list"},
		}},
	}
	c := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(cr).Build()

	if err := ValidateClusterRole(context.Background(), c, "my-role"); err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestValidateClusterRole_NotFound(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(testScheme()).Build()

	err := ValidateClusterRole(context.Background(), c, "missing-role")
	if err == nil {
		t.Fatal("expected error for missing ClusterRole")
	}
}

func TestValidateClusterRole_WithAggregationRule(t *testing.T) {
	cr := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "agg-role"},
		AggregationRule: &rbacv1.AggregationRule{
			ClusterRoleSelectors: []metav1.LabelSelector{
				{MatchLabels: map[string]string{"app": "test"}},
			},
		},
	}
	c := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(cr).Build()

	err := ValidateClusterRole(context.Background(), c, "agg-role")
	if err == nil {
		t.Fatal("expected error for ClusterRole with aggregationRule")
	}
}

// ---------------------------------------------------------------------------
// extractFieldValue tests
// ---------------------------------------------------------------------------

func TestExtractFieldValue(t *testing.T) {
	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "v1",
			"kind":       "TestKind",
			"metadata": map[string]interface{}{
				"name":      "test-obj",
				"namespace": "test-ns",
			},
			"spec": map[string]interface{}{
				"targetNamespace": "target-ns",
				"nested": map[string]interface{}{
					"deep": "deep-value",
				},
			},
		},
	}

	tests := []struct {
		name      string
		fieldPath string
		want      string
		wantErr   bool
	}{
		{"top-level spec field", ".spec.targetNamespace", "target-ns", false},
		{"without leading dot", "spec.targetNamespace", "target-ns", false},
		{"nested field", ".spec.nested.deep", "deep-value", false},
		{"missing field", ".spec.nonexistent", "", true},
		{"metadata name", ".metadata.name", "test-obj", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := extractFieldValue(obj, tt.fieldPath)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// isNamespaceAllowed tests
// ---------------------------------------------------------------------------

func TestIsNamespaceAllowed(t *testing.T) {
	scheme := testScheme()

	labeledNs := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "labeled-ns",
			Labels: map[string]string{"env": "prod"},
		},
	}
	unlabeledNs := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "unlabeled-ns",
			Labels: map[string]string{"env": "dev"},
		},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(labeledNs, unlabeledNs).Build()

	t.Run("denied by deny list", func(t *testing.T) {
		rec, _ := NewScopingReconciler(c, ScopingTarget{
			WatchGVK:              schema.GroupVersionKind{Group: "test", Version: "v1", Kind: "Thing"},
			TargetSA:              types.NamespacedName{Name: "sa", Namespace: "ns"},
			ClusterRoleName:       "role",
			ManagedRoleBindingName: "rb",
		}, DenyListConfig{Namespaces: []string{"kube-system"}}, record.NewFakeRecorder(10))

		if rec.isNamespaceAllowed(context.Background(), "kube-system") {
			t.Error("kube-system should be denied")
		}
	})

	t.Run("allowed without selector", func(t *testing.T) {
		rec, _ := NewScopingReconciler(c, ScopingTarget{
			WatchGVK:              schema.GroupVersionKind{Group: "test", Version: "v1", Kind: "Thing"},
			TargetSA:              types.NamespacedName{Name: "sa", Namespace: "ns"},
			ClusterRoleName:       "role",
			ManagedRoleBindingName: "rb",
		}, DenyListConfig{}, record.NewFakeRecorder(10))

		if !rec.isNamespaceAllowed(context.Background(), "labeled-ns") {
			t.Error("labeled-ns should be allowed with no selector")
		}
	})

	t.Run("allowed by selector match", func(t *testing.T) {
		rec, _ := NewScopingReconciler(c, ScopingTarget{
			WatchGVK:              schema.GroupVersionKind{Group: "test", Version: "v1", Kind: "Thing"},
			TargetSA:              types.NamespacedName{Name: "sa", Namespace: "ns"},
			ClusterRoleName:       "role",
			ManagedRoleBindingName: "rb",
			NamespaceSelector:     &metav1.LabelSelector{MatchLabels: map[string]string{"env": "prod"}},
		}, DenyListConfig{}, record.NewFakeRecorder(10))

		if !rec.isNamespaceAllowed(context.Background(), "labeled-ns") {
			t.Error("labeled-ns should match selector env=prod")
		}
	})

	t.Run("denied by selector mismatch", func(t *testing.T) {
		rec, _ := NewScopingReconciler(c, ScopingTarget{
			WatchGVK:              schema.GroupVersionKind{Group: "test", Version: "v1", Kind: "Thing"},
			TargetSA:              types.NamespacedName{Name: "sa", Namespace: "ns"},
			ClusterRoleName:       "role",
			ManagedRoleBindingName: "rb",
			NamespaceSelector:     &metav1.LabelSelector{MatchLabels: map[string]string{"env": "prod"}},
		}, DenyListConfig{}, record.NewFakeRecorder(10))

		if rec.isNamespaceAllowed(context.Background(), "unlabeled-ns") {
			t.Error("unlabeled-ns should not match selector env=prod")
		}
	})

	t.Run("denied when namespace not found", func(t *testing.T) {
		rec, _ := NewScopingReconciler(c, ScopingTarget{
			WatchGVK:              schema.GroupVersionKind{Group: "test", Version: "v1", Kind: "Thing"},
			TargetSA:              types.NamespacedName{Name: "sa", Namespace: "ns"},
			ClusterRoleName:       "role",
			ManagedRoleBindingName: "rb",
			NamespaceSelector:     &metav1.LabelSelector{MatchLabels: map[string]string{"env": "prod"}},
		}, DenyListConfig{}, record.NewFakeRecorder(10))

		if rec.isNamespaceAllowed(context.Background(), "nonexistent-ns") {
			t.Error("nonexistent namespace should not be allowed")
		}
	})
}

// ---------------------------------------------------------------------------
// Drift detection tests (ensureRoleBindingSpec)
// ---------------------------------------------------------------------------

func TestDriftDetection_RoleRefDrift(t *testing.T) {
	scheme := testScheme()
	target := ScopingTarget{
		WatchGVK:              schema.GroupVersionKind{Group: "test.io", Version: "v1", Kind: "MyResource"},
		TargetSA:              types.NamespacedName{Name: "controller-sa", Namespace: "operator-ns"},
		ClusterRoleName:       "correct-role",
		ManagedRoleBindingName: "managed-rb",
	}

	// Existing RoleBinding with wrong RoleRef
	existingRB := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "managed-rb",
			Namespace: "target-ns",
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "ClusterRole",
			Name:     "wrong-role",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      rbacv1.ServiceAccountKind,
				Name:      "controller-sa",
				Namespace: "operator-ns",
			},
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(existingRB).Build()
	rec, _ := NewScopingReconciler(c, target, DenyListConfig{}, record.NewFakeRecorder(10))

	err := rec.ensureRoleBindingSpec(context.Background(), existingRB, "target-ns")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify the old RB was deleted and a new one was created with correct RoleRef
	recreated := &rbacv1.RoleBinding{}
	if err := c.Get(context.Background(), types.NamespacedName{Name: "managed-rb", Namespace: "target-ns"}, recreated); err != nil {
		t.Fatalf("expected recreated RoleBinding to exist: %v", err)
	}
	if recreated.RoleRef.Name != "correct-role" {
		t.Errorf("expected RoleRef name %q, got %q", "correct-role", recreated.RoleRef.Name)
	}
}

func TestDriftDetection_SubjectsDrift(t *testing.T) {
	scheme := testScheme()
	target := ScopingTarget{
		WatchGVK:              schema.GroupVersionKind{Group: "test.io", Version: "v1", Kind: "MyResource"},
		TargetSA:              types.NamespacedName{Name: "correct-sa", Namespace: "operator-ns"},
		ClusterRoleName:       "my-role",
		ManagedRoleBindingName: "managed-rb",
	}

	existingRB := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "managed-rb",
			Namespace: "target-ns",
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "ClusterRole",
			Name:     "my-role",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      rbacv1.ServiceAccountKind,
				Name:      "wrong-sa",
				Namespace: "wrong-ns",
			},
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(existingRB).Build()
	rec, _ := NewScopingReconciler(c, target, DenyListConfig{}, record.NewFakeRecorder(10))

	err := rec.ensureRoleBindingSpec(context.Background(), existingRB, "target-ns")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify subjects were updated (not deleted/recreated since RoleRef is fine)
	updated := &rbacv1.RoleBinding{}
	if err := c.Get(context.Background(), types.NamespacedName{Name: "managed-rb", Namespace: "target-ns"}, updated); err != nil {
		t.Fatalf("expected RoleBinding to exist: %v", err)
	}

	expectedSubjects := []rbacv1.Subject{
		{
			Kind:      rbacv1.ServiceAccountKind,
			Name:      "correct-sa",
			Namespace: "operator-ns",
		},
	}
	if !reflect.DeepEqual(updated.Subjects, expectedSubjects) {
		t.Errorf("expected subjects %+v, got %+v", expectedSubjects, updated.Subjects)
	}
}

func TestDriftDetection_NoDrift(t *testing.T) {
	scheme := testScheme()
	target := ScopingTarget{
		WatchGVK:              schema.GroupVersionKind{Group: "test.io", Version: "v1", Kind: "MyResource"},
		TargetSA:              types.NamespacedName{Name: "controller-sa", Namespace: "operator-ns"},
		ClusterRoleName:       "my-role",
		ManagedRoleBindingName: "managed-rb",
	}

	existingRB := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "managed-rb",
			Namespace: "target-ns",
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "ClusterRole",
			Name:     "my-role",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      rbacv1.ServiceAccountKind,
				Name:      "controller-sa",
				Namespace: "operator-ns",
			},
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(existingRB).Build()
	rec, _ := NewScopingReconciler(c, target, DenyListConfig{}, record.NewFakeRecorder(10))

	err := rec.ensureRoleBindingSpec(context.Background(), existingRB, "target-ns")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// ensureOwnerReference patch test (MAJOR 3)
// ---------------------------------------------------------------------------

func TestEnsureOwnerReference_UsesPatch(t *testing.T) {
	scheme := testScheme()

	// Register the GVK for the unstructured object so SetOwnerReference works
	scheme.AddKnownTypeWithName(
		schema.GroupVersionKind{Group: "test.io", Version: "v1", Kind: "MyResource"},
		&unstructured.Unstructured{},
	)

	rb := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "managed-rb",
			Namespace: "test-ns",
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "ClusterRole",
			Name:     "role",
		},
	}

	cr := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "test.io/v1",
			"kind":       "MyResource",
			"metadata": map[string]interface{}{
				"name":      "my-cr",
				"namespace": "test-ns",
				"uid":       "cr-uid-123",
			},
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(rb).Build()
	target := ScopingTarget{
		WatchGVK:              schema.GroupVersionKind{Group: "test.io", Version: "v1", Kind: "MyResource"},
		TargetSA:              types.NamespacedName{Name: "sa", Namespace: "ns"},
		ClusterRoleName:       "role",
		ManagedRoleBindingName: "managed-rb",
	}
	rec, _ := NewScopingReconciler(c, target, DenyListConfig{}, record.NewFakeRecorder(10))

	err := rec.ensureOwnerReference(context.Background(), cr, rb)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify the owner reference was added
	updated := &rbacv1.RoleBinding{}
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(rb), updated); err != nil {
		t.Fatalf("failed to get updated RoleBinding: %v", err)
	}

	found := false
	for _, ref := range updated.OwnerReferences {
		if ref.UID == "cr-uid-123" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected owner reference with UID cr-uid-123 to be added")
	}
}

// ---------------------------------------------------------------------------
// DefaultDenyList test
// ---------------------------------------------------------------------------

func TestDefaultDenyList(t *testing.T) {
	dl := DefaultDenyList("my-operator-ns")

	expectedNamespaces := []string{"kube-system", "kube-public", "kube-node-lease", "default", "my-operator-ns"}
	if !reflect.DeepEqual(dl.Namespaces, expectedNamespaces) {
		t.Errorf("expected namespaces %v, got %v", expectedNamespaces, dl.Namespaces)
	}

	if len(dl.Prefixes) != 1 || dl.Prefixes[0] != "openshift-" {
		t.Errorf("expected prefixes [openshift-], got %v", dl.Prefixes)
	}
}

func TestDefaultDenyList_EmptyControllerNamespace(t *testing.T) {
	dl := DefaultDenyList("")

	expectedNamespaces := []string{"kube-system", "kube-public", "kube-node-lease", "default"}
	if !reflect.DeepEqual(dl.Namespaces, expectedNamespaces) {
		t.Errorf("expected namespaces %v, got %v", expectedNamespaces, dl.Namespaces)
	}
}

// ---------------------------------------------------------------------------
// validateTarget tests for new WebhookProvisioning field
// ---------------------------------------------------------------------------

func TestValidateTarget_RejectsWebhookWithTargetNamespaceSource(t *testing.T) {
	target := ScopingTarget{
		WatchGVK:            schema.GroupVersionKind{Kind: "Foo"},
		TargetSA:            types.NamespacedName{Name: "sa", Namespace: "ns"},
		ClusterRoleName:     "role",
		ManagedRoleBindingName: "binding",
		WebhookProvisioning: true,
		TargetNamespaceSource: &NamespaceSource{FieldPath: ".spec.namespace"},
	}
	err := validateTarget(target)
	if err == nil {
		t.Fatal("expected error for WebhookProvisioning + TargetNamespaceSource")
	}
}

func TestValidateTarget_RejectsLabelTriggerWithTargetNamespaceSource(t *testing.T) {
	target := ScopingTarget{
		WatchGVK:            schema.GroupVersionKind{Kind: "Foo"},
		TargetSA:            types.NamespacedName{Name: "sa", Namespace: "ns"},
		ClusterRoleName:     "role",
		ManagedRoleBindingName: "binding",
		NamespaceLabelTrigger: &metav1.LabelSelector{MatchLabels: map[string]string{"env": "prod"}},
		TargetNamespaceSource: &NamespaceSource{FieldPath: ".spec.namespace"},
	}
	err := validateTarget(target)
	if err == nil {
		t.Fatal("expected error for NamespaceLabelTrigger + TargetNamespaceSource")
	}
}

// ---------------------------------------------------------------------------
// parsePendingOwner tests
// ---------------------------------------------------------------------------

func TestParsePendingOwner(t *testing.T) {
	tests := []struct {
		name        string
		annotation  string
		wantNS      string
		wantName    string
		wantErr     bool
	}{
		{
			name:        "valid annotation",
			annotation:  "test-ns/my-cr/test.io/v1/MyKind/2026-07-09T10:00:00Z",
			wantNS:      "test-ns",
			wantName:    "my-cr",
			wantErr:     false,
		},
		{
			name:        "valid annotation with empty group",
			annotation:  "default/my-cr//v1/Pod/2026-07-09T10:00:00Z",
			wantNS:      "default",
			wantName:    "my-cr",
			wantErr:     false,
		},
		{
			name:        "invalid format - too few parts",
			annotation:  "test-ns/my-cr/test.io",
			wantErr:     true,
		},
		{
			name:        "invalid timestamp",
			annotation:  "test-ns/my-cr/test.io/v1/MyKind/not-a-timestamp",
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotNS, gotName, _, err := parsePendingOwner(tt.annotation)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if gotNS != tt.wantNS {
				t.Errorf("namespace: got %q, want %q", gotNS, tt.wantNS)
			}
			if gotName != tt.wantName {
				t.Errorf("name: got %q, want %q", gotName, tt.wantName)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// backfillPendingOwner tests
// ---------------------------------------------------------------------------

func TestBackfillPendingOwner_MatchingCR(t *testing.T) {
	scheme := testScheme()
	scheme.AddKnownTypeWithName(
		schema.GroupVersionKind{Group: "test.io", Version: "v1", Kind: "MyResource"},
		&unstructured.Unstructured{},
	)

	cr := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "test.io/v1",
			"kind":       "MyResource",
			"metadata": map[string]interface{}{
				"name":      "my-cr",
				"namespace": "test-ns",
				"uid":       "cr-uid-123",
			},
		},
	}

	rb := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "managed-rb",
			Namespace: "test-ns",
			Annotations: map[string]string{
				PendingOwnerAnnotationKey: fmt.Sprintf("test-ns/my-cr/test.io/v1/MyResource/%s",
					time.Now().UTC().Format(time.RFC3339)),
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "ClusterRole",
			Name:     "test-role",
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(rb).Build()
	target := ScopingTarget{
		WatchGVK:              schema.GroupVersionKind{Group: "test.io", Version: "v1", Kind: "MyResource"},
		TargetSA:              types.NamespacedName{Name: "sa", Namespace: "operator-ns"},
		ClusterRoleName:       "test-role",
		ManagedRoleBindingName: "managed-rb",
	}
	rec, _ := NewScopingReconciler(c, target, DenyListConfig{}, record.NewFakeRecorder(10))

	err := rec.backfillPendingOwner(context.Background(), cr, "test-ns")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify OwnerReference was set and pending-owner annotation was removed
	updated := &rbacv1.RoleBinding{}
	if err := c.Get(context.Background(), types.NamespacedName{Name: "managed-rb", Namespace: "test-ns"}, updated); err != nil {
		t.Fatalf("failed to get updated RoleBinding: %v", err)
	}

	// Check OwnerReference
	found := false
	for _, ref := range updated.OwnerReferences {
		if ref.UID == "cr-uid-123" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected OwnerReference with UID cr-uid-123 to be set")
	}

	// Check annotation removed
	if _, exists := updated.Annotations[PendingOwnerAnnotationKey]; exists {
		t.Error("expected pending-owner annotation to be removed")
	}
}

func TestBackfillPendingOwner_NonMatchingCR(t *testing.T) {
	scheme := testScheme()
	scheme.AddKnownTypeWithName(
		schema.GroupVersionKind{Group: "test.io", Version: "v1", Kind: "MyResource"},
		&unstructured.Unstructured{},
	)

	cr := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "test.io/v1",
			"kind":       "MyResource",
			"metadata": map[string]interface{}{
				"name":      "my-cr",
				"namespace": "test-ns",
				"uid":       "cr-uid-123",
			},
		},
	}

	// RoleBinding has pending-owner pointing to a different CR
	rb := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "managed-rb",
			Namespace: "test-ns",
			Annotations: map[string]string{
				PendingOwnerAnnotationKey: fmt.Sprintf("test-ns/other-cr/test.io/v1/MyResource/%s",
					time.Now().UTC().Format(time.RFC3339)),
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "ClusterRole",
			Name:     "test-role",
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(rb).Build()
	target := ScopingTarget{
		WatchGVK:              schema.GroupVersionKind{Group: "test.io", Version: "v1", Kind: "MyResource"},
		TargetSA:              types.NamespacedName{Name: "sa", Namespace: "operator-ns"},
		ClusterRoleName:       "test-role",
		ManagedRoleBindingName: "managed-rb",
	}
	rec, _ := NewScopingReconciler(c, target, DenyListConfig{}, record.NewFakeRecorder(10))

	err := rec.backfillPendingOwner(context.Background(), cr, "test-ns")
	// Should return nil (non-matching CRs skip backfill without requeueing)
	if err != nil {
		t.Errorf("expected nil for non-matching CR, got %v", err)
	}

	// Verify nothing changed
	updated := &rbacv1.RoleBinding{}
	if err := c.Get(context.Background(), types.NamespacedName{Name: "managed-rb", Namespace: "test-ns"}, updated); err != nil {
		t.Fatalf("failed to get RoleBinding: %v", err)
	}

	if len(updated.OwnerReferences) > 0 {
		t.Error("expected no OwnerReference to be set for non-matching CR")
	}

	if _, exists := updated.Annotations[PendingOwnerAnnotationKey]; !exists {
		t.Error("expected pending-owner annotation to remain")
	}
}

func TestBackfillPendingOwner_PastTTL_NoRequeue(t *testing.T) {
	scheme := testScheme()
	scheme.AddKnownTypeWithName(
		schema.GroupVersionKind{Group: "test.io", Version: "v1", Kind: "MyResource"},
		&unstructured.Unstructured{},
	)

	cr := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "test.io/v1",
			"kind":       "MyResource",
			"metadata": map[string]interface{}{
				"name":      "my-cr",
				"namespace": "test-ns",
				"uid":       "cr-uid-123",
			},
		},
	}

	// RoleBinding has pending-owner pointing to a different CR, with timestamp past TTL
	pastTimestamp := time.Now().Add(-5 * time.Minute).UTC().Format(time.RFC3339)
	rb := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "managed-rb",
			Namespace: "test-ns",
			Annotations: map[string]string{
				PendingOwnerAnnotationKey: fmt.Sprintf("test-ns/other-cr/test.io/v1/MyResource/%s", pastTimestamp),
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "ClusterRole",
			Name:     "test-role",
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(rb).Build()
	target := ScopingTarget{
		WatchGVK:              schema.GroupVersionKind{Group: "test.io", Version: "v1", Kind: "MyResource"},
		TargetSA:              types.NamespacedName{Name: "sa", Namespace: "operator-ns"},
		ClusterRoleName:       "test-role",
		ManagedRoleBindingName: "managed-rb",
	}
	rec, _ := NewScopingReconciler(c, target, DenyListConfig{}, record.NewFakeRecorder(10))

	err := rec.backfillPendingOwner(context.Background(), cr, "test-ns")
	// Should NOT return error (stops requeueing since TTL expired)
	if err != nil {
		t.Errorf("expected no error for pending-owner past TTL, got %v", err)
	}

	// Verify nothing changed (no OwnerReference set, annotation still present)
	updated := &rbacv1.RoleBinding{}
	if err := c.Get(context.Background(), types.NamespacedName{Name: "managed-rb", Namespace: "test-ns"}, updated); err != nil {
		t.Fatalf("failed to get RoleBinding: %v", err)
	}
	if len(updated.OwnerReferences) > 0 {
		t.Error("expected no OwnerReference for non-matching CR past TTL")
	}
	if _, exists := updated.Annotations[PendingOwnerAnnotationKey]; !exists {
		t.Error("expected pending-owner annotation to remain")
	}
}

func TestBackfillPendingOwner_CRWithEmptyUID(t *testing.T) {
	scheme := testScheme()
	scheme.AddKnownTypeWithName(
		schema.GroupVersionKind{Group: "test.io", Version: "v1", Kind: "MyResource"},
		&unstructured.Unstructured{},
	)

	// CR with empty UID (e.g., just created, not yet persisted)
	cr := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "test.io/v1",
			"kind":       "MyResource",
			"metadata": map[string]interface{}{
				"name":      "my-cr",
				"namespace": "test-ns",
				"uid":       "", // empty UID
			},
		},
	}

	rb := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "managed-rb",
			Namespace: "test-ns",
			Annotations: map[string]string{
				PendingOwnerAnnotationKey: fmt.Sprintf("test-ns/my-cr/test.io/v1/MyResource/%s",
					time.Now().UTC().Format(time.RFC3339)),
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "ClusterRole",
			Name:     "test-role",
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(rb).Build()
	target := ScopingTarget{
		WatchGVK:              schema.GroupVersionKind{Group: "test.io", Version: "v1", Kind: "MyResource"},
		TargetSA:              types.NamespacedName{Name: "sa", Namespace: "operator-ns"},
		ClusterRoleName:       "test-role",
		ManagedRoleBindingName: "managed-rb",
	}
	rec, _ := NewScopingReconciler(c, target, DenyListConfig{}, record.NewFakeRecorder(10))

	err := rec.backfillPendingOwner(context.Background(), cr, "test-ns")
	// Should return nil (skips backfill when UID is empty)
	if err != nil {
		t.Errorf("expected no error for CR with empty UID, got %v", err)
	}

	// Verify no OwnerReference was set
	updated := &rbacv1.RoleBinding{}
	if err := c.Get(context.Background(), types.NamespacedName{Name: "managed-rb", Namespace: "test-ns"}, updated); err != nil {
		t.Fatalf("failed to get RoleBinding: %v", err)
	}
	if len(updated.OwnerReferences) > 0 {
		t.Error("expected no OwnerReference when CR has empty UID")
	}

	// Pending-owner annotation should still be present (not removed since UID is empty)
	if _, exists := updated.Annotations[PendingOwnerAnnotationKey]; !exists {
		t.Error("expected pending-owner annotation to remain when CR has empty UID")
	}
}

func TestBackfillPendingOwner_NoPendingOwner(t *testing.T) {
	scheme := testScheme()
	scheme.AddKnownTypeWithName(
		schema.GroupVersionKind{Group: "test.io", Version: "v1", Kind: "MyResource"},
		&unstructured.Unstructured{},
	)

	cr := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "test.io/v1",
			"kind":       "MyResource",
			"metadata": map[string]interface{}{
				"name":      "my-cr",
				"namespace": "test-ns",
				"uid":       "cr-uid-123",
			},
		},
	}

	// RoleBinding without pending-owner annotation
	rb := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "managed-rb",
			Namespace: "test-ns",
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "ClusterRole",
			Name:     "test-role",
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(rb).Build()
	target := ScopingTarget{
		WatchGVK:              schema.GroupVersionKind{Group: "test.io", Version: "v1", Kind: "MyResource"},
		TargetSA:              types.NamespacedName{Name: "sa", Namespace: "operator-ns"},
		ClusterRoleName:       "test-role",
		ManagedRoleBindingName: "managed-rb",
	}
	rec, _ := NewScopingReconciler(c, target, DenyListConfig{}, record.NewFakeRecorder(10))

	err := rec.backfillPendingOwner(context.Background(), cr, "test-ns")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify nothing changed (no error, no changes)
	updated := &rbacv1.RoleBinding{}
	if err := c.Get(context.Background(), types.NamespacedName{Name: "managed-rb", Namespace: "test-ns"}, updated); err != nil {
		t.Fatalf("failed to get RoleBinding: %v", err)
	}

	if len(updated.OwnerReferences) > 0 {
		t.Error("expected no OwnerReference to be set when no pending-owner annotation exists")
	}
}
