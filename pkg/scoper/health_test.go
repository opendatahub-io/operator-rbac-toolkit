package scoper

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// ---------------------------------------------------------------------------
// RBACHealthHandler tests
// ---------------------------------------------------------------------------

func TestRBACHealthHandler_ReturnsJSON(t *testing.T) {
	scheme := testScheme()

	// Create a ClusterRole for target1
	cr1 := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "test-role-1"},
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{""},
			Resources: []string{"pods"},
			Verbs:     []string{"get", "list"},
		}},
	}

	// Create managed RoleBindings for target1
	rb1 := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "managed-rb-1",
			Namespace: "ns1",
			Labels: map[string]string{
				ManagedLabelKey: ManagedLabelValue,
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "ClusterRole",
			Name:     "test-role-1",
		},
	}

	rb2 := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "managed-rb-1",
			Namespace: "ns2",
			Labels: map[string]string{
				ManagedLabelKey: ManagedLabelValue,
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "ClusterRole",
			Name:     "test-role-1",
		},
	}

	// Create managed RoleBinding for target2 (different name)
	rb3 := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "managed-rb-2",
			Namespace: "ns3",
			Labels: map[string]string{
				ManagedLabelKey: ManagedLabelValue,
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "ClusterRole",
			Name:     "test-role-2",
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cr1, rb1, rb2, rb3).Build()

	cfg := Config{
		Targets: []ScopingTarget{
			{
				WatchGVK:              schema.GroupVersionKind{Group: "test", Version: "v1", Kind: "Thing"},
				TargetSA:              types.NamespacedName{Name: "sa1", Namespace: "ns1"},
				ClusterRoleName:       "test-role-1",
				ManagedRoleBindingName: "managed-rb-1",
				WebhookProvisioning:   true,
			},
			{
				WatchGVK:              schema.GroupVersionKind{Group: "test", Version: "v1", Kind: "Thing2"},
				TargetSA:              types.NamespacedName{Name: "sa2", Namespace: "ns2"},
				ClusterRoleName:       "test-role-2",
				ManagedRoleBindingName: "managed-rb-2",
				WebhookProvisioning:   false,
			},
		},
	}

	handler := RBACHealthHandler(cfg, c)

	req := httptest.NewRequest(http.MethodGet, "/debug/rbac-health", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}

	contentType := w.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("expected Content-Type application/json, got %q", contentType)
	}

	var response RBACHealthResponse
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(response.Targets) != 2 {
		t.Fatalf("expected 2 targets, got %d", len(response.Targets))
	}

	// Check target1
	target1 := response.Targets[0]
	if target1.Name != "managed-rb-1" {
		t.Errorf("target1 name: got %q, want %q", target1.Name, "managed-rb-1")
	}
	if !target1.ClusterRoleExists {
		t.Error("target1 ClusterRoleExists should be true")
	}
	if target1.ManagedRoleBindings != 2 {
		t.Errorf("target1 ManagedRoleBindings: got %d, want 2", target1.ManagedRoleBindings)
	}
	if target1.OrphanRoleBindings != 0 {
		t.Errorf("target1 OrphanRoleBindings: got %d, want 0", target1.OrphanRoleBindings)
	}
	if !target1.WebhookProvisioning {
		t.Error("target1 WebhookProvisioning should be true")
	}

	// Check target2
	target2 := response.Targets[1]
	if target2.Name != "managed-rb-2" {
		t.Errorf("target2 name: got %q, want %q", target2.Name, "managed-rb-2")
	}
	if target2.ClusterRoleExists {
		t.Error("target2 ClusterRoleExists should be false (missing)")
	}
	if target2.ManagedRoleBindings != 1 {
		t.Errorf("target2 ManagedRoleBindings: got %d, want 1", target2.ManagedRoleBindings)
	}
	if target2.WebhookProvisioning {
		t.Error("target2 WebhookProvisioning should be false")
	}

	// Overall health should be false because target2 is missing its ClusterRole
	if response.Healthy {
		t.Error("expected Healthy to be false when a ClusterRole is missing")
	}

	// Check new response-level fields
	if response.WebhookRegistered {
		t.Error("expected WebhookRegistered to be false (placeholder)")
	}
}

func TestRBACHealthHandler_HealthyWhenAllClusterRolesExist(t *testing.T) {
	scheme := testScheme()

	cr1 := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "role-1"},
		Rules:      []rbacv1.PolicyRule{{Verbs: []string{"get"}}},
	}
	cr2 := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "role-2"},
		Rules:      []rbacv1.PolicyRule{{Verbs: []string{"list"}}},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cr1, cr2).Build()

	cfg := Config{
		Targets: []ScopingTarget{
			{
				WatchGVK:              schema.GroupVersionKind{Group: "test", Version: "v1", Kind: "Thing"},
				TargetSA:              types.NamespacedName{Name: "sa1", Namespace: "ns1"},
				ClusterRoleName:       "role-1",
				ManagedRoleBindingName: "rb-1",
			},
			{
				WatchGVK:              schema.GroupVersionKind{Group: "test", Version: "v1", Kind: "Thing2"},
				TargetSA:              types.NamespacedName{Name: "sa2", Namespace: "ns2"},
				ClusterRoleName:       "role-2",
				ManagedRoleBindingName: "rb-2",
			},
		},
	}

	handler := RBACHealthHandler(cfg, c)
	req := httptest.NewRequest(http.MethodGet, "/debug/rbac-health", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	var response RBACHealthResponse
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if !response.Healthy {
		t.Error("expected Healthy to be true when all ClusterRoles exist")
	}

	for _, target := range response.Targets {
		if !target.ClusterRoleExists {
			t.Errorf("target %q ClusterRoleExists should be true", target.Name)
		}
	}
}

func TestRBACHealthHandler_UnhealthyWhenClusterRoleMissing(t *testing.T) {
	scheme := testScheme()

	cr1 := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "role-1"},
		Rules:      []rbacv1.PolicyRule{{Verbs: []string{"get"}}},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cr1).Build()

	cfg := Config{
		Targets: []ScopingTarget{
			{
				WatchGVK:              schema.GroupVersionKind{Group: "test", Version: "v1", Kind: "Thing"},
				TargetSA:              types.NamespacedName{Name: "sa1", Namespace: "ns1"},
				ClusterRoleName:       "role-1",
				ManagedRoleBindingName: "rb-1",
			},
			{
				WatchGVK:              schema.GroupVersionKind{Group: "test", Version: "v1", Kind: "Thing2"},
				TargetSA:              types.NamespacedName{Name: "sa2", Namespace: "ns2"},
				ClusterRoleName:       "missing-role",
				ManagedRoleBindingName: "rb-2",
			},
		},
	}

	handler := RBACHealthHandler(cfg, c)
	req := httptest.NewRequest(http.MethodGet, "/debug/rbac-health", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	var response RBACHealthResponse
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if response.Healthy {
		t.Error("expected Healthy to be false when a ClusterRole is missing")
	}

	if !response.Targets[0].ClusterRoleExists {
		t.Error("target[0] should have ClusterRoleExists=true")
	}
	if response.Targets[1].ClusterRoleExists {
		t.Error("target[1] should have ClusterRoleExists=false")
	}
}

// ---------------------------------------------------------------------------
// RBACHealthzCheck tests
// ---------------------------------------------------------------------------

func TestRBACHealthzCheck_PassWhenAllClusterRolesExist(t *testing.T) {
	scheme := testScheme()

	cr1 := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "role-1"},
		Rules:      []rbacv1.PolicyRule{{Verbs: []string{"get"}}},
	}
	cr2 := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "role-2"},
		Rules:      []rbacv1.PolicyRule{{Verbs: []string{"list"}}},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cr1, cr2).Build()

	cfg := Config{
		Targets: []ScopingTarget{
			{
				WatchGVK:              schema.GroupVersionKind{Group: "test", Version: "v1", Kind: "Thing"},
				TargetSA:              types.NamespacedName{Name: "sa1", Namespace: "ns1"},
				ClusterRoleName:       "role-1",
				ManagedRoleBindingName: "rb-1",
			},
			{
				WatchGVK:              schema.GroupVersionKind{Group: "test", Version: "v1", Kind: "Thing2"},
				TargetSA:              types.NamespacedName{Name: "sa2", Namespace: "ns2"},
				ClusterRoleName:       "role-2",
				ManagedRoleBindingName: "rb-2",
			},
		},
	}

	checker := RBACHealthzCheck(cfg, c)
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)

	err := checker(req)
	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
}

func TestRBACHealthzCheck_FailWhenClusterRoleMissing(t *testing.T) {
	scheme := testScheme()

	cr1 := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "role-1"},
		Rules:      []rbacv1.PolicyRule{{Verbs: []string{"get"}}},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cr1).Build()

	cfg := Config{
		Targets: []ScopingTarget{
			{
				WatchGVK:              schema.GroupVersionKind{Group: "test", Version: "v1", Kind: "Thing"},
				TargetSA:              types.NamespacedName{Name: "sa1", Namespace: "ns1"},
				ClusterRoleName:       "role-1",
				ManagedRoleBindingName: "rb-1",
			},
			{
				WatchGVK:              schema.GroupVersionKind{Group: "test", Version: "v1", Kind: "Thing2"},
				TargetSA:              types.NamespacedName{Name: "sa2", Namespace: "ns2"},
				ClusterRoleName:       "missing-role",
				ManagedRoleBindingName: "rb-2",
			},
		},
	}

	checker := RBACHealthzCheck(cfg, c)
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)

	err := checker(req)
	if err == nil {
		t.Fatal("expected error when ClusterRole is missing")
	}

	// Error message should mention the missing role
	if err.Error() == "" {
		t.Error("expected non-empty error message")
	}
}

func TestRBACHealthzCheck_FailWhenMultipleClusterRolesMissing(t *testing.T) {
	scheme := testScheme()
	c := fake.NewClientBuilder().WithScheme(scheme).Build()

	cfg := Config{
		Targets: []ScopingTarget{
			{
				WatchGVK:              schema.GroupVersionKind{Group: "test", Version: "v1", Kind: "Thing"},
				TargetSA:              types.NamespacedName{Name: "sa1", Namespace: "ns1"},
				ClusterRoleName:       "missing-role-1",
				ManagedRoleBindingName: "rb-1",
			},
			{
				WatchGVK:              schema.GroupVersionKind{Group: "test", Version: "v1", Kind: "Thing2"},
				TargetSA:              types.NamespacedName{Name: "sa2", Namespace: "ns2"},
				ClusterRoleName:       "missing-role-2",
				ManagedRoleBindingName: "rb-2",
			},
		},
	}

	checker := RBACHealthzCheck(cfg, c)
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)

	err := checker(req)
	if err == nil {
		t.Fatal("expected error when multiple ClusterRoles are missing")
	}
}

// ---------------------------------------------------------------------------
// countManagedRoleBindings tests
// ---------------------------------------------------------------------------

func TestCountManagedRoleBindings(t *testing.T) {
	scheme := testScheme()

	rb1 := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "managed-rb",
			Namespace: "ns1",
			Labels: map[string]string{
				ManagedLabelKey: ManagedLabelValue,
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "ClusterRole",
			Name:     "role",
		},
	}

	rb2 := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "managed-rb",
			Namespace: "ns2",
			Labels: map[string]string{
				ManagedLabelKey: ManagedLabelValue,
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "ClusterRole",
			Name:     "role",
		},
	}

	rb3 := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "other-rb",
			Namespace: "ns3",
			Labels: map[string]string{
				ManagedLabelKey: ManagedLabelValue,
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "ClusterRole",
			Name:     "role",
		},
	}

	rb4 := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "unmanaged-rb",
			Namespace: "ns4",
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "ClusterRole",
			Name:     "role",
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(rb1, rb2, rb3, rb4).Build()

	count, err := countManagedRoleBindings(context.Background(), c, "managed-rb")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if count != 2 {
		t.Errorf("expected count 2, got %d", count)
	}
}

func TestCountManagedRoleBindings_NoRoleBindings(t *testing.T) {
	scheme := testScheme()
	c := fake.NewClientBuilder().WithScheme(scheme).Build()

	count, err := countManagedRoleBindings(context.Background(), c, "managed-rb")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if count != 0 {
		t.Errorf("expected count 0, got %d", count)
	}
}

// ---------------------------------------------------------------------------
// OrphanRoleBindings and new fields tests
// ---------------------------------------------------------------------------

func TestRBACHealthHandler_OrphanRoleBindings(t *testing.T) {
	scheme := testScheme()

	cr1 := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "role-1"},
		Rules:      []rbacv1.PolicyRule{{Verbs: []string{"get"}}},
	}

	// Normal managed RoleBinding (no pending-owner)
	rb1 := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "managed-rb",
			Namespace: "ns1",
			Labels: map[string]string{
				ManagedLabelKey: ManagedLabelValue,
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "ClusterRole",
			Name:     "role-1",
		},
	}

	// Orphan RoleBinding with expired pending-owner (timestamp in the past)
	expiredTimestamp := time.Now().Add(-5 * time.Minute).UTC().Format(time.RFC3339)
	rb2 := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "managed-rb",
			Namespace: "ns2",
			Labels: map[string]string{
				ManagedLabelKey: ManagedLabelValue,
			},
			Annotations: map[string]string{
				PendingOwnerAnnotationKey: fmt.Sprintf("ns2/deleted-cr/test.io/v1/Thing/%s", expiredTimestamp),
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "ClusterRole",
			Name:     "role-1",
		},
	}

	// RoleBinding with non-expired pending-owner (should not count as orphan)
	freshTimestamp := time.Now().UTC().Format(time.RFC3339)
	rb3 := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "managed-rb",
			Namespace: "ns3",
			Labels: map[string]string{
				ManagedLabelKey: ManagedLabelValue,
			},
			Annotations: map[string]string{
				PendingOwnerAnnotationKey: fmt.Sprintf("ns3/new-cr/test.io/v1/Thing/%s", freshTimestamp),
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "ClusterRole",
			Name:     "role-1",
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cr1, rb1, rb2, rb3).Build()

	cfg := Config{
		Targets: []ScopingTarget{
			{
				WatchGVK:              schema.GroupVersionKind{Group: "test", Version: "v1", Kind: "Thing"},
				TargetSA:              types.NamespacedName{Name: "sa1", Namespace: "ns1"},
				ClusterRoleName:       "role-1",
				ManagedRoleBindingName: "managed-rb",
			},
		},
	}

	handler := RBACHealthHandler(cfg, c)
	req := httptest.NewRequest(http.MethodGet, "/debug/rbac-health", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	var response RBACHealthResponse
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(response.Targets) != 1 {
		t.Fatalf("expected 1 target, got %d", len(response.Targets))
	}

	target := response.Targets[0]
	if target.ManagedRoleBindings != 3 {
		t.Errorf("ManagedRoleBindings: got %d, want 3", target.ManagedRoleBindings)
	}
	if target.OrphanRoleBindings != 1 {
		t.Errorf("OrphanRoleBindings: got %d, want 1 (only expired pending-owner)", target.OrphanRoleBindings)
	}
}
