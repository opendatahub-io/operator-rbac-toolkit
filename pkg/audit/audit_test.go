package audit

import (
	"context"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func newScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	_ = rbacv1.AddToScheme(s)
	return s
}

func TestScanImpersonationGrants_ClusterRole(t *testing.T) {
	cr := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "dangerous-role"},
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{""},
			Resources: []string{"serviceaccounts"},
			Verbs:     []string{"impersonate"},
		}},
	}
	c := fake.NewClientBuilder().WithScheme(newScheme()).WithObjects(cr).Build()

	findings, err := scanImpersonationGrants(context.Background(), c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	assertFinding(t, findings[0], Critical, "impersonation-grants", "ClusterRole")
}

func TestScanImpersonationGrants_Role(t *testing.T) {
	r := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{Name: "ns-dangerous", Namespace: "default"},
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{""},
			Resources: []string{"serviceaccounts"},
			Verbs:     []string{"impersonate"},
		}},
	}
	c := fake.NewClientBuilder().WithScheme(newScheme()).WithObjects(r).Build()

	findings, err := scanImpersonationGrants(context.Background(), c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	assertFinding(t, findings[0], Critical, "impersonation-grants", "Role")
}

func TestScanImpersonationGrants_WildcardVerb(t *testing.T) {
	cr := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "wildcard-role"},
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{"*"},
			Resources: []string{"*"},
			Verbs:     []string{"*"},
		}},
	}
	c := fake.NewClientBuilder().WithScheme(newScheme()).WithObjects(cr).Build()

	findings, err := scanImpersonationGrants(context.Background(), c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for wildcard rule, got %d", len(findings))
	}
}

func TestScanImpersonationGrants_NoFindings(t *testing.T) {
	cr := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "safe-role"},
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{""},
			Resources: []string{"pods"},
			Verbs:     []string{"get", "list"},
		}},
	}
	c := fake.NewClientBuilder().WithScheme(newScheme()).WithObjects(cr).Build()

	findings, err := scanImpersonationGrants(context.Background(), c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(findings))
	}
}

func TestScanTokenRequestExposure_Positive(t *testing.T) {
	cr := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "token-minter"},
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{""},
			Resources: []string{"serviceaccounts/token"},
			Verbs:     []string{"create"},
		}},
	}
	c := fake.NewClientBuilder().WithScheme(newScheme()).WithObjects(cr).Build()

	findings, err := scanTokenRequestExposure(context.Background(), c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	assertFinding(t, findings[0], Critical, "tokenrequest-exposure", "ClusterRole")
}

func TestScanTokenRequestExposure_Role(t *testing.T) {
	r := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{Name: "ns-token-minter", Namespace: "test-ns"},
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{""},
			Resources: []string{"serviceaccounts/token"},
			Verbs:     []string{"create"},
		}},
	}
	c := fake.NewClientBuilder().WithScheme(newScheme()).WithObjects(r).Build()

	findings, err := scanTokenRequestExposure(context.Background(), c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	assertFinding(t, findings[0], Critical, "tokenrequest-exposure", "Role")
}

func TestScanTokenRequestExposure_NoFindings(t *testing.T) {
	cr := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "sa-reader"},
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{""},
			Resources: []string{"serviceaccounts"},
			Verbs:     []string{"get", "list"},
		}},
	}
	c := fake.NewClientBuilder().WithScheme(newScheme()).WithObjects(cr).Build()

	findings, err := scanTokenRequestExposure(context.Background(), c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(findings))
	}
}

func TestScanAggregateToEditStatus_HasImpersonate(t *testing.T) {
	cr := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "system:aggregate-to-edit"},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"pods"},
				Verbs:     []string{"get", "list"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"serviceaccounts"},
				Verbs:     []string{"impersonate"},
			},
		},
	}
	c := fake.NewClientBuilder().WithScheme(newScheme()).WithObjects(cr).Build()

	findings, err := scanAggregateToEditStatus(context.Background(), c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	assertFinding(t, findings[0], Warning, "aggregate-to-edit-impersonate", "ClusterRole")
}

func TestScanAggregateToEditStatus_NoImpersonate(t *testing.T) {
	cr := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "system:aggregate-to-edit"},
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{""},
			Resources: []string{"pods"},
			Verbs:     []string{"get", "list"},
		}},
	}
	c := fake.NewClientBuilder().WithScheme(newScheme()).WithObjects(cr).Build()

	findings, err := scanAggregateToEditStatus(context.Background(), c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(findings))
	}
}

func TestScanUnusedPermissions_DetectsUnused(t *testing.T) {
	cr := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "my-operator-role"},
		Rules: []rbacv1.PolicyRule{
			{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get", "list"}},
			{APIGroups: []string{""}, Resources: []string{"configmaps"}, Verbs: []string{"get"}},
			{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"delete"}},
		},
	}
	crb := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "my-operator-binding"},
		RoleRef:    rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "my-operator-role"},
		Subjects: []rbacv1.Subject{{
			Kind:      "ServiceAccount",
			Name:      "my-operator",
			Namespace: "my-ns",
		}},
	}
	c := fake.NewClientBuilder().WithScheme(newScheme()).WithObjects(cr, crb).Build()

	cfg := Config{
		ServiceAccount: types.NamespacedName{Name: "my-operator", Namespace: "my-ns"},
		ExpectedRules: []rbacv1.PolicyRule{
			{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get", "list"}},
			{APIGroups: []string{""}, Resources: []string{"configmaps"}, Verbs: []string{"get"}},
		},
	}

	findings, err := scanUnusedPermissions(context.Background(), c, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for unused pods/delete rule, got %d", len(findings))
	}
	assertFinding(t, findings[0], Info, "unused-permissions", "ClusterRole")
}

func TestScanUnusedPermissions_AllUsed(t *testing.T) {
	cr := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "my-operator-role"},
		Rules: []rbacv1.PolicyRule{
			{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get"}},
		},
	}
	crb := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "my-operator-binding"},
		RoleRef:    rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "my-operator-role"},
		Subjects: []rbacv1.Subject{{
			Kind:      "ServiceAccount",
			Name:      "my-operator",
			Namespace: "my-ns",
		}},
	}
	c := fake.NewClientBuilder().WithScheme(newScheme()).WithObjects(cr, crb).Build()

	cfg := Config{
		ServiceAccount: types.NamespacedName{Name: "my-operator", Namespace: "my-ns"},
		ExpectedRules: []rbacv1.PolicyRule{
			{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get"}},
		},
	}

	findings, err := scanUnusedPermissions(context.Background(), c, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(findings))
	}
}

func TestScanUnusedPermissions_NoBinding(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(newScheme()).Build()

	cfg := Config{
		ServiceAccount: types.NamespacedName{Name: "nonexistent", Namespace: "ns"},
		ExpectedRules: []rbacv1.PolicyRule{
			{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get"}},
		},
	}

	findings, err := scanUnusedPermissions(context.Background(), c, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings when no binding exists, got %d", len(findings))
	}
}

func TestScanAggregationRules_Positive(t *testing.T) {
	cr := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "aggregated-role"},
		AggregationRule: &rbacv1.AggregationRule{
			ClusterRoleSelectors: []metav1.LabelSelector{
				{MatchLabels: map[string]string{"aggregate": "true"}},
			},
		},
	}
	crb := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "agg-binding"},
		RoleRef:    rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "aggregated-role"},
		Subjects: []rbacv1.Subject{{
			Kind:      "ServiceAccount",
			Name:      "my-sa",
			Namespace: "my-ns",
		}},
	}
	c := fake.NewClientBuilder().WithScheme(newScheme()).WithObjects(cr, crb).Build()

	cfg := Config{
		ServiceAccount: types.NamespacedName{Name: "my-sa", Namespace: "my-ns"},
	}

	findings, err := scanAggregationRules(context.Background(), c, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	assertFinding(t, findings[0], Warning, "aggregation-rules", "ClusterRole")
}

func TestScanAggregationRules_NoAggregation(t *testing.T) {
	cr := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "plain-role"},
		Rules: []rbacv1.PolicyRule{
			{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}},
		},
	}
	crb := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "plain-binding"},
		RoleRef:    rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "plain-role"},
		Subjects: []rbacv1.Subject{{
			Kind:      "ServiceAccount",
			Name:      "my-sa",
			Namespace: "my-ns",
		}},
	}
	c := fake.NewClientBuilder().WithScheme(newScheme()).WithObjects(cr, crb).Build()

	cfg := Config{
		ServiceAccount: types.NamespacedName{Name: "my-sa", Namespace: "my-ns"},
	}

	findings, err := scanAggregationRules(context.Background(), c, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(findings))
	}
}

func TestScan_IntegrationAllScanners(t *testing.T) {
	impersonateRole := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "impersonate-role"},
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{""},
			Resources: []string{"serviceaccounts"},
			Verbs:     []string{"impersonate"},
		}},
	}
	tokenRole := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "token-role"},
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{""},
			Resources: []string{"serviceaccounts/token"},
			Verbs:     []string{"create"},
		}},
	}
	aggregateToEdit := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "system:aggregate-to-edit"},
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{""},
			Resources: []string{"serviceaccounts"},
			Verbs:     []string{"impersonate"},
		}},
	}
	saRole := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "sa-role"},
		AggregationRule: &rbacv1.AggregationRule{
			ClusterRoleSelectors: []metav1.LabelSelector{
				{MatchLabels: map[string]string{"inject": "true"}},
			},
		},
		Rules: []rbacv1.PolicyRule{
			{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get"}},
			{APIGroups: []string{""}, Resources: []string{"nodes"}, Verbs: []string{"list"}},
		},
	}
	saBinding := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "sa-binding"},
		RoleRef:    rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "sa-role"},
		Subjects: []rbacv1.Subject{{
			Kind:      "ServiceAccount",
			Name:      "test-sa",
			Namespace: "test-ns",
		}},
	}

	c := fake.NewClientBuilder().WithScheme(newScheme()).WithObjects(
		impersonateRole, tokenRole, aggregateToEdit, saRole, saBinding,
	).Build()

	cfg := Config{
		ServiceAccount: types.NamespacedName{Name: "test-sa", Namespace: "test-ns"},
		ExpectedRules: []rbacv1.PolicyRule{
			{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get"}},
		},
	}

	findings, err := Scan(context.Background(), c, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	categories := make(map[string]int)
	for _, f := range findings {
		categories[f.Category]++
	}

	// Only impersonate-role produces impersonation-grants findings;
	// system:aggregate-to-edit is excluded (has its own dedicated scanner).
	if categories["impersonation-grants"] != 1 {
		t.Errorf("expected 1 impersonation-grants finding, got %d", categories["impersonation-grants"])
	}
	if categories["tokenrequest-exposure"] != 1 {
		t.Errorf("expected 1 tokenrequest-exposure finding, got %d", categories["tokenrequest-exposure"])
	}
	if categories["aggregate-to-edit-impersonate"] != 1 {
		t.Errorf("expected 1 aggregate-to-edit-impersonate finding, got %d", categories["aggregate-to-edit-impersonate"])
	}
	if categories["unused-permissions"] != 1 {
		t.Errorf("expected 1 unused-permissions finding (nodes/list), got %d", categories["unused-permissions"])
	}
	if categories["aggregation-rules"] != 1 {
		t.Errorf("expected 1 aggregation-rules finding, got %d", categories["aggregation-rules"])
	}
}

func TestScan_CleanCluster(t *testing.T) {
	safeRole := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "safe-role"},
		Rules: []rbacv1.PolicyRule{
			{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}},
		},
	}
	aggregateToEdit := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "system:aggregate-to-edit"},
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{""},
			Resources: []string{"pods"},
			Verbs:     []string{"get", "list"},
		}},
	}

	c := fake.NewClientBuilder().WithScheme(newScheme()).WithObjects(safeRole, aggregateToEdit).Build()

	cfg := Config{
		ServiceAccount: types.NamespacedName{Name: "safe-sa", Namespace: "safe-ns"},
	}

	findings, err := Scan(context.Background(), c, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings on clean cluster, got %d: %+v", len(findings), findings)
	}
}

func assertFinding(t *testing.T, f Finding, severity Severity, category string, resourceKind string) {
	t.Helper()
	if f.Severity != severity {
		t.Errorf("expected severity %s, got %s", severity, f.Severity)
	}
	if f.Category != category {
		t.Errorf("expected category %q, got %q", category, f.Category)
	}
	if f.Resource == nil {
		t.Fatal("expected Resource to be non-nil")
	}
	if f.Resource.Kind != resourceKind {
		t.Errorf("expected resource kind %q, got %q", resourceKind, f.Resource.Kind)
	}
}
