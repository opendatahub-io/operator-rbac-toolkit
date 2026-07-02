package impersonation

import (
	"context"
	"testing"

	"github.com/go-logr/logr"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func newScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(s)
	return s
}

func componentClusterRole(name string, rules []rbacv1.PolicyRule) *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Labels: map[string]string{
				aggregateToEditLabel: "true",
			},
		},
		Rules: rules,
	}
}

func TestReconcile_StripsImpersonateVerb(t *testing.T) {
	cr := componentClusterRole("system:aggregate-to-edit-impersonate", []rbacv1.PolicyRule{
		{
			APIGroups: []string{""},
			Resources: []string{"serviceaccounts"},
			Verbs:     []string{"impersonate"},
		},
	})

	c := fake.NewClientBuilder().WithScheme(newScheme()).WithObjects(cr).Build()
	g := NewGuard(c, logr.Discard(), DefaultGuardConfig())

	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: cr.Name}}
	_, err := g.Reconcile(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var updated rbacv1.ClusterRole
	if err := c.Get(context.Background(), types.NamespacedName{Name: cr.Name}, &updated); err != nil {
		t.Fatalf("getting updated ClusterRole: %v", err)
	}

	if hasImpersonateVerb(updated.Rules) {
		t.Error("impersonate verb should have been removed")
	}

	// The rule had only "impersonate", so the entire rule should be dropped.
	if len(updated.Rules) != 0 {
		t.Errorf("expected 0 rules (single-verb rule dropped), got %d", len(updated.Rules))
	}
}

func TestReconcile_PreservesOtherVerbs(t *testing.T) {
	cr := componentClusterRole("system:aggregate-to-edit-impersonate", []rbacv1.PolicyRule{
		{
			APIGroups: []string{""},
			Resources: []string{"serviceaccounts"},
			Verbs:     []string{"get", "impersonate", "list"},
		},
		{
			APIGroups: []string{""},
			Resources: []string{"configmaps"},
			Verbs:     []string{"get", "list"},
		},
	})

	c := fake.NewClientBuilder().WithScheme(newScheme()).WithObjects(cr).Build()
	g := NewGuard(c, logr.Discard(), DefaultGuardConfig())

	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: cr.Name}}
	_, err := g.Reconcile(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var updated rbacv1.ClusterRole
	if err := c.Get(context.Background(), types.NamespacedName{Name: cr.Name}, &updated); err != nil {
		t.Fatalf("getting updated ClusterRole: %v", err)
	}

	if hasImpersonateVerb(updated.Rules) {
		t.Error("impersonate verb should have been removed")
	}

	if len(updated.Rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(updated.Rules))
	}

	saRule := updated.Rules[0]
	expectedVerbs := map[string]bool{"get": true, "list": true}
	if len(saRule.Verbs) != 2 {
		t.Fatalf("expected 2 verbs on serviceaccounts rule, got %d: %v", len(saRule.Verbs), saRule.Verbs)
	}
	for _, v := range saRule.Verbs {
		if !expectedVerbs[v] {
			t.Errorf("unexpected verb %q in serviceaccounts rule", v)
		}
	}
}

func TestReconcile_NoImpersonateVerb_Noop(t *testing.T) {
	cr := componentClusterRole("system:aggregate-to-edit-something", []rbacv1.PolicyRule{
		{
			APIGroups: []string{""},
			Resources: []string{"serviceaccounts"},
			Verbs:     []string{"get", "list"},
		},
	})
	cr.Annotations = map[string]string{autoupdateAnnotation: "false"}

	c := fake.NewClientBuilder().WithScheme(newScheme()).WithObjects(cr).Build()
	g := NewGuard(c, logr.Discard(), DefaultGuardConfig())

	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: cr.Name}}
	_, err := g.Reconcile(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var updated rbacv1.ClusterRole
	if err := c.Get(context.Background(), types.NamespacedName{Name: cr.Name}, &updated); err != nil {
		t.Fatalf("getting updated ClusterRole: %v", err)
	}

	if len(updated.Rules) != 1 || len(updated.Rules[0].Verbs) != 2 {
		t.Error("rules should not have been modified")
	}
}

func TestReconcile_SetsAutoupdateAnnotation(t *testing.T) {
	cr := componentClusterRole("system:aggregate-to-edit-impersonate", []rbacv1.PolicyRule{
		{
			APIGroups: []string{""},
			Resources: []string{"serviceaccounts"},
			Verbs:     []string{"impersonate"},
		},
	})

	c := fake.NewClientBuilder().WithScheme(newScheme()).WithObjects(cr).Build()
	g := NewGuard(c, logr.Discard(), DefaultGuardConfig())

	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: cr.Name}}
	_, err := g.Reconcile(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var updated rbacv1.ClusterRole
	if err := c.Get(context.Background(), types.NamespacedName{Name: cr.Name}, &updated); err != nil {
		t.Fatalf("getting updated ClusterRole: %v", err)
	}

	val, ok := updated.Annotations[autoupdateAnnotation]
	if !ok || val != "false" {
		t.Errorf("expected autoupdate annotation to be 'false', got %q (present: %v)", val, ok)
	}
}

func TestReconcile_DriftRecovery(t *testing.T) {
	cr := componentClusterRole("system:aggregate-to-edit-impersonate", []rbacv1.PolicyRule{
		{
			APIGroups: []string{""},
			Resources: []string{"serviceaccounts"},
			Verbs:     []string{"impersonate"},
		},
	})

	c := fake.NewClientBuilder().WithScheme(newScheme()).WithObjects(cr).Build()
	g := NewGuard(c, logr.Discard(), DefaultGuardConfig())

	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: cr.Name}}

	// First reconcile: strip the verb.
	if _, err := g.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("first reconcile: %v", err)
	}

	// Simulate drift: re-add the impersonate verb externally.
	var drifted rbacv1.ClusterRole
	if err := c.Get(context.Background(), types.NamespacedName{Name: cr.Name}, &drifted); err != nil {
		t.Fatalf("getting ClusterRole: %v", err)
	}
	drifted.Rules = []rbacv1.PolicyRule{
		{
			APIGroups: []string{""},
			Resources: []string{"serviceaccounts"},
			Verbs:     []string{"impersonate"},
		},
	}
	if err := c.Update(context.Background(), &drifted); err != nil {
		t.Fatalf("simulating drift: %v", err)
	}

	// Second reconcile: should strip the verb again.
	if _, err := g.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("second reconcile: %v", err)
	}

	var after rbacv1.ClusterRole
	if err := c.Get(context.Background(), types.NamespacedName{Name: cr.Name}, &after); err != nil {
		t.Fatalf("getting ClusterRole after drift recovery: %v", err)
	}

	if hasImpersonateVerb(after.Rules) {
		t.Error("impersonate verb should have been removed after drift")
	}
}

func TestReconcile_SkipsNonAggregateLabel(t *testing.T) {
	cr := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "some-other-clusterrole",
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"serviceaccounts"},
				Verbs:     []string{"impersonate"},
			},
		},
	}

	c := fake.NewClientBuilder().WithScheme(newScheme()).WithObjects(cr).Build()
	g := NewGuard(c, logr.Discard(), DefaultGuardConfig())

	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: cr.Name}}
	_, err := g.Reconcile(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var unchanged rbacv1.ClusterRole
	if err := c.Get(context.Background(), types.NamespacedName{Name: cr.Name}, &unchanged); err != nil {
		t.Fatalf("getting ClusterRole: %v", err)
	}

	if !hasImpersonateVerb(unchanged.Rules) {
		t.Error("should not have modified a ClusterRole without the aggregate-to-edit label")
	}
}

func TestReconcile_WildcardVerbOnServiceAccounts(t *testing.T) {
	cr := componentClusterRole("system:aggregate-to-edit-wildcard-verb", []rbacv1.PolicyRule{
		{
			APIGroups: []string{""},
			Resources: []string{"serviceaccounts"},
			Verbs:     []string{"*"},
		},
	})

	c := fake.NewClientBuilder().WithScheme(newScheme()).WithObjects(cr).Build()
	g := NewGuard(c, logr.Discard(), DefaultGuardConfig())

	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: cr.Name}}
	_, err := g.Reconcile(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var updated rbacv1.ClusterRole
	if err := c.Get(context.Background(), types.NamespacedName{Name: cr.Name}, &updated); err != nil {
		t.Fatalf("getting updated ClusterRole: %v", err)
	}

	if hasImpersonateVerb(updated.Rules) {
		t.Error("wildcard verb should have been expanded and impersonate removed")
	}

	// The wildcard should be replaced with explicit standard verbs.
	if len(updated.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(updated.Rules))
	}

	expectedVerbs := map[string]bool{
		"get": true, "list": true, "watch": true,
		"create": true, "update": true, "patch": true, "delete": true,
	}
	if len(updated.Rules[0].Verbs) != len(expectedVerbs) {
		t.Fatalf("expected %d verbs, got %d: %v", len(expectedVerbs), len(updated.Rules[0].Verbs), updated.Rules[0].Verbs)
	}
	for _, v := range updated.Rules[0].Verbs {
		if !expectedVerbs[v] {
			t.Errorf("unexpected verb %q after wildcard expansion", v)
		}
	}

	// Annotation should also be set.
	val, ok := updated.Annotations[autoupdateAnnotation]
	if !ok || val != "false" {
		t.Errorf("expected autoupdate annotation to be 'false', got %q (present: %v)", val, ok)
	}
}

func TestReconcile_WildcardResourceWithImpersonate(t *testing.T) {
	cr := componentClusterRole("system:aggregate-to-edit-wildcard-resource", []rbacv1.PolicyRule{
		{
			APIGroups: []string{""},
			Resources: []string{"*"},
			Verbs:     []string{"get", "impersonate", "list"},
		},
	})

	c := fake.NewClientBuilder().WithScheme(newScheme()).WithObjects(cr).Build()
	g := NewGuard(c, logr.Discard(), DefaultGuardConfig())

	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: cr.Name}}
	_, err := g.Reconcile(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var updated rbacv1.ClusterRole
	if err := c.Get(context.Background(), types.NamespacedName{Name: cr.Name}, &updated); err != nil {
		t.Fatalf("getting updated ClusterRole: %v", err)
	}

	if hasImpersonateVerb(updated.Rules) {
		t.Error("impersonate verb should have been removed from wildcard resource rule")
	}

	if len(updated.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(updated.Rules))
	}

	expectedVerbs := map[string]bool{"get": true, "list": true}
	if len(updated.Rules[0].Verbs) != len(expectedVerbs) {
		t.Fatalf("expected %d verbs, got %d: %v", len(expectedVerbs), len(updated.Rules[0].Verbs), updated.Rules[0].Verbs)
	}
	for _, v := range updated.Rules[0].Verbs {
		if !expectedVerbs[v] {
			t.Errorf("unexpected verb %q in wildcard resource rule", v)
		}
	}
}

func TestReconcile_WildcardVerbAndWildcardResource(t *testing.T) {
	cr := componentClusterRole("system:aggregate-to-edit-double-wildcard", []rbacv1.PolicyRule{
		{
			APIGroups: []string{""},
			Resources: []string{"*"},
			Verbs:     []string{"*"},
		},
	})

	c := fake.NewClientBuilder().WithScheme(newScheme()).WithObjects(cr).Build()
	g := NewGuard(c, logr.Discard(), DefaultGuardConfig())

	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: cr.Name}}
	_, err := g.Reconcile(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var updated rbacv1.ClusterRole
	if err := c.Get(context.Background(), types.NamespacedName{Name: cr.Name}, &updated); err != nil {
		t.Fatalf("getting updated ClusterRole: %v", err)
	}

	if hasImpersonateVerb(updated.Rules) {
		t.Error("wildcard verb+resource should have been expanded and impersonate removed")
	}

	if len(updated.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(updated.Rules))
	}

	expectedVerbs := map[string]bool{
		"get": true, "list": true, "watch": true,
		"create": true, "update": true, "patch": true, "delete": true,
	}
	if len(updated.Rules[0].Verbs) != len(expectedVerbs) {
		t.Fatalf("expected %d verbs, got %d: %v", len(expectedVerbs), len(updated.Rules[0].Verbs), updated.Rules[0].Verbs)
	}
	for _, v := range updated.Rules[0].Verbs {
		if !expectedVerbs[v] {
			t.Errorf("unexpected verb %q after wildcard expansion", v)
		}
	}
}

func TestReconcile_NoAnnotationOnCleanClusterRole(t *testing.T) {
	// A ClusterRole without impersonate should not get the autoupdate annotation modified.
	cr := componentClusterRole("system:aggregate-to-edit-clean", []rbacv1.PolicyRule{
		{
			APIGroups: []string{""},
			Resources: []string{"serviceaccounts"},
			Verbs:     []string{"get", "list"},
		},
	})

	c := fake.NewClientBuilder().WithScheme(newScheme()).WithObjects(cr).Build()
	g := NewGuard(c, logr.Discard(), DefaultGuardConfig())

	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: cr.Name}}
	_, err := g.Reconcile(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var updated rbacv1.ClusterRole
	if err := c.Get(context.Background(), types.NamespacedName{Name: cr.Name}, &updated); err != nil {
		t.Fatalf("getting updated ClusterRole: %v", err)
	}

	if _, ok := updated.Annotations[autoupdateAnnotation]; ok {
		t.Error("autoupdate annotation should not be set on a ClusterRole that had no impersonate verb")
	}
}

func TestReconcile_RequeueAfterIsConfigurable(t *testing.T) {
	cr := componentClusterRole("test-cr", []rbacv1.PolicyRule{})
	cr.Annotations = map[string]string{autoupdateAnnotation: "false"}

	c := fake.NewClientBuilder().WithScheme(newScheme()).WithObjects(cr).Build()
	cfg := DefaultGuardConfig()
	cfg.RequeueAfter = 10 * DefaultRequeueAfter
	g := NewGuard(c, logr.Discard(), cfg)

	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: cr.Name}}
	result, err := g.Reconcile(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.RequeueAfter != cfg.RequeueAfter {
		t.Errorf("expected RequeueAfter=%v, got %v", cfg.RequeueAfter, result.RequeueAfter)
	}
}
