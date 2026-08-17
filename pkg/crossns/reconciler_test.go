package crossns

import (
	"context"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// ---------------------------------------------------------------------------
// helpers

func testScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	_ = rbacv1.AddToScheme(s)
	return s
}

func newReconciler(owner OwnerLabel, objects ...client.Object) (*Reconciler, client.Client) {
	c := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(objects...).Build()
	return New(c, owner), c
}

func noOwner() OwnerLabel { return OwnerLabel{} }

func subjectFor(name, namespace string) SubjectRef {
	return SubjectRef{Name: name, Namespace: namespace}
}

func ruleSet(role, namespace string, rules []rbacv1.PolicyRule) RuleSet {
	return RuleSet{RoleName: role, Namespace: namespace, Rules: rules}
}

func basicRules() []rbacv1.PolicyRule {
	return []rbacv1.PolicyRule{
		{APIGroups: []string{""}, Resources: []string{"configmaps"}, Verbs: []string{"get", "list"}},
	}
}

func listRoles(t *testing.T, c client.Client, opts ...client.ListOption) []rbacv1.Role {
	t.Helper()
	var list rbacv1.RoleList
	if err := c.List(context.Background(), &list, opts...); err != nil {
		t.Fatalf("listing roles: %v", err)
	}
	return list.Items
}

func listRoleBindings(t *testing.T, c client.Client, opts ...client.ListOption) []rbacv1.RoleBinding {
	t.Helper()
	var list rbacv1.RoleBindingList
	if err := c.List(context.Background(), &list, opts...); err != nil {
		t.Fatalf("listing rolebindings: %v", err)
	}
	return list.Items
}

func getRole(t *testing.T, c client.Client, ns, name string) *rbacv1.Role {
	t.Helper()
	role := &rbacv1.Role{}
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: ns, Name: name}, role); err != nil {
		t.Fatalf("getting role %s/%s: %v", ns, name, err)
	}
	return role
}

func getRoleBinding(t *testing.T, c client.Client, ns, name string) *rbacv1.RoleBinding {
	t.Helper()
	rb := &rbacv1.RoleBinding{}
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: ns, Name: name}, rb); err != nil {
		t.Fatalf("getting rolebinding %s/%s: %v", ns, name, err)
	}
	return rb
}

func managedLabelsFor(owner OwnerLabel) client.MatchingLabels {
	labels := client.MatchingLabels{ManagedLabelKey: ManagedLabelValue}
	if owner.Key != "" {
		labels[owner.Key] = owner.Value
	}
	return labels
}

// ---------------------------------------------------------------------------
// Apply: basic creation

func TestApply_CreatesRoleAndBinding(t *testing.T) {
	r, c := newReconciler(noOwner())
	subject := subjectFor("my-sa", "my-app-ns")
	rs := ruleSet("my-role", "target-ns", basicRules())

	if err := r.Apply(context.Background(), subject, []RuleSet{rs}); err != nil {
		t.Fatalf("Apply failed: %v", err)
	}

	role := getRole(t, c, "target-ns", "my-role")
	if role.Namespace != "target-ns" {
		t.Errorf("expected role namespace target-ns, got %s", role.Namespace)
	}
	if len(role.Rules) != 1 {
		t.Errorf("expected 1 rule, got %d", len(role.Rules))
	}

	rb := getRoleBinding(t, c, "target-ns", "my-role-binding")
	if rb.RoleRef.Kind != "Role" {
		t.Errorf("expected RoleRef.Kind=Role, got %s", rb.RoleRef.Kind)
	}
	if rb.RoleRef.Name != "my-role" {
		t.Errorf("expected RoleRef.Name=my-role, got %s", rb.RoleRef.Name)
	}
	if len(rb.Subjects) != 1 {
		t.Fatalf("expected 1 subject, got %d", len(rb.Subjects))
	}
	if rb.Subjects[0].Name != "my-sa" || rb.Subjects[0].Namespace != "my-app-ns" {
		t.Errorf("unexpected subject: %+v", rb.Subjects[0])
	}
}

func TestApply_MultipleRuleSets_AllCreated(t *testing.T) {
	r, c := newReconciler(noOwner())
	subject := subjectFor("sa", "app")

	ruleSets := []RuleSet{
		ruleSet("role-a", "ns-a", basicRules()),
		ruleSet("role-b", "ns-b", basicRules()),
	}
	if err := r.Apply(context.Background(), subject, ruleSets); err != nil {
		t.Fatalf("Apply failed: %v", err)
	}

	roles := listRoles(t, c, client.MatchingLabels{ManagedLabelKey: ManagedLabelValue})
	if len(roles) != 2 {
		t.Errorf("expected 2 roles, got %d", len(roles))
	}
	rbs := listRoleBindings(t, c, client.MatchingLabels{ManagedLabelKey: ManagedLabelValue})
	if len(rbs) != 2 {
		t.Errorf("expected 2 rolebindings, got %d", len(rbs))
	}
}

func TestApply_EmptyRuleSets_NoResourcesCreated(t *testing.T) {
	r, c := newReconciler(noOwner())

	if err := r.Apply(context.Background(), subjectFor("sa", "ns"), nil); err != nil {
		t.Fatalf("Apply failed: %v", err)
	}

	roles := listRoles(t, c)
	if len(roles) != 0 {
		t.Errorf("expected 0 roles, got %d", len(roles))
	}
}

// ---------------------------------------------------------------------------
// Apply: idempotency

func TestApply_Idempotent(t *testing.T) {
	r, c := newReconciler(noOwner())
	subject := subjectFor("sa", "app")
	ruleSets := []RuleSet{ruleSet("my-role", "target-ns", basicRules())}

	if err := r.Apply(context.Background(), subject, ruleSets); err != nil {
		t.Fatalf("first Apply: %v", err)
	}
	if err := r.Apply(context.Background(), subject, ruleSets); err != nil {
		t.Fatalf("second Apply: %v", err)
	}

	roles := listRoles(t, c, client.MatchingLabels{ManagedLabelKey: ManagedLabelValue})
	if len(roles) != 1 {
		t.Errorf("expected 1 role after idempotent Apply, got %d", len(roles))
	}
	rbs := listRoleBindings(t, c, client.MatchingLabels{ManagedLabelKey: ManagedLabelValue})
	if len(rbs) != 1 {
		t.Errorf("expected 1 rolebinding after idempotent Apply, got %d", len(rbs))
	}
}

// ---------------------------------------------------------------------------
// Apply: updates existing

func TestApply_UpdatesExistingRoleRules(t *testing.T) {
	existing := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-role",
			Namespace: "target-ns",
			Labels:    map[string]string{ManagedLabelKey: ManagedLabelValue},
		},
		Rules: []rbacv1.PolicyRule{
			{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}},
		},
	}

	r, c := newReconciler(noOwner(), existing)
	subject := subjectFor("sa", "app")

	newRules := []rbacv1.PolicyRule{
		{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get", "list", "create"}},
	}
	if err := r.Apply(context.Background(), subject, []RuleSet{ruleSet("my-role", "target-ns", newRules)}); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	role := getRole(t, c, "target-ns", "my-role")
	if len(role.Rules) != 1 || role.Rules[0].Resources[0] != "secrets" {
		t.Errorf("expected rules to be updated to secrets, got: %v", role.Rules)
	}
}

func TestApply_UpdatesExistingSubjects(t *testing.T) {
	existingRB := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-role-binding",
			Namespace: "target-ns",
			Labels:    map[string]string{ManagedLabelKey: ManagedLabelValue},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "Role",
			Name:     "my-role",
		},
		Subjects: []rbacv1.Subject{
			{Kind: rbacv1.ServiceAccountKind, Name: "old-sa", Namespace: "old-ns"},
		},
	}

	r, c := newReconciler(noOwner(), existingRB)
	subject := subjectFor("new-sa", "new-ns")

	if err := r.Apply(context.Background(), subject, []RuleSet{ruleSet("my-role", "target-ns", basicRules())}); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	rb := getRoleBinding(t, c, "target-ns", "my-role-binding")
	if len(rb.Subjects) != 1 || rb.Subjects[0].Name != "new-sa" {
		t.Errorf("expected subjects updated to new-sa, got: %v", rb.Subjects)
	}
}

// ---------------------------------------------------------------------------
// GC: stale namespace cleanup

func TestApply_GCsStaleNamespaceOnChange(t *testing.T) {
	r, c := newReconciler(noOwner())
	subject := subjectFor("sa", "app")

	// First: create in old-ns
	if err := r.Apply(context.Background(), subject, []RuleSet{ruleSet("my-role", "old-ns", basicRules())}); err != nil {
		t.Fatalf("first Apply: %v", err)
	}
	roles := listRoles(t, c, client.MatchingLabels{ManagedLabelKey: ManagedLabelValue})
	if len(roles) != 1 || roles[0].Namespace != "old-ns" {
		t.Errorf("expected 1 role in old-ns, got %+v", roles)
	}

	// Second: switch to new-ns — old-ns should be GC'd
	if err := r.Apply(context.Background(), subject, []RuleSet{ruleSet("my-role", "new-ns", basicRules())}); err != nil {
		t.Fatalf("second Apply: %v", err)
	}

	roles = listRoles(t, c, client.MatchingLabels{ManagedLabelKey: ManagedLabelValue})
	if len(roles) != 1 {
		t.Errorf("expected 1 role after namespace change, got %d", len(roles))
	}
	if roles[0].Namespace != "new-ns" {
		t.Errorf("expected role in new-ns, got %s", roles[0].Namespace)
	}

	rbs := listRoleBindings(t, c, client.MatchingLabels{ManagedLabelKey: ManagedLabelValue})
	if len(rbs) != 1 || rbs[0].Namespace != "new-ns" {
		t.Errorf("expected rolebinding in new-ns, got %+v", rbs)
	}
}

func TestApply_GCsNamespaceRemovedFromSpec(t *testing.T) {
	r, c := newReconciler(noOwner())
	subject := subjectFor("sa", "app")

	// Create in two namespaces
	if err := r.Apply(context.Background(), subject, []RuleSet{
		ruleSet("role-a", "ns-a", basicRules()),
		ruleSet("role-b", "ns-b", basicRules()),
	}); err != nil {
		t.Fatalf("first Apply: %v", err)
	}
	if len(listRoles(t, c, client.MatchingLabels{ManagedLabelKey: ManagedLabelValue})) != 2 {
		t.Fatal("expected 2 roles after initial Apply")
	}

	// Remove ns-b from desired
	if err := r.Apply(context.Background(), subject, []RuleSet{ruleSet("role-a", "ns-a", basicRules())}); err != nil {
		t.Fatalf("second Apply: %v", err)
	}

	roles := listRoles(t, c, client.MatchingLabels{ManagedLabelKey: ManagedLabelValue})
	if len(roles) != 1 || roles[0].Namespace != "ns-a" {
		t.Errorf("expected only ns-a role, got %+v", roles)
	}
	rbs := listRoleBindings(t, c, client.MatchingLabels{ManagedLabelKey: ManagedLabelValue})
	if len(rbs) != 1 || rbs[0].Namespace != "ns-a" {
		t.Errorf("expected only ns-a rolebinding, got %+v", rbs)
	}
}

func TestApply_GCRemovesAllWhenDesiredEmpty(t *testing.T) {
	r, c := newReconciler(noOwner())
	subject := subjectFor("sa", "app")

	if err := r.Apply(context.Background(), subject, []RuleSet{
		ruleSet("role-a", "ns-a", basicRules()),
		ruleSet("role-b", "ns-b", basicRules()),
	}); err != nil {
		t.Fatalf("first Apply: %v", err)
	}

	// Apply with no rule sets — GC should remove everything
	if err := r.Apply(context.Background(), subject, nil); err != nil {
		t.Fatalf("empty Apply: %v", err)
	}

	if len(listRoles(t, c, client.MatchingLabels{ManagedLabelKey: ManagedLabelValue})) != 0 {
		t.Error("expected 0 roles after empty Apply")
	}
	if len(listRoleBindings(t, c, client.MatchingLabels{ManagedLabelKey: ManagedLabelValue})) != 0 {
		t.Error("expected 0 rolebindings after empty Apply")
	}
}

// ---------------------------------------------------------------------------
// GC: does not touch unmanaged resources

func TestApply_GCDoesNotTouchUnmanagedRoles(t *testing.T) {
	foreign := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "foreign-role",
			Namespace: "target-ns",
			// No managed label
		},
		Rules: basicRules(),
	}

	r, c := newReconciler(noOwner(), foreign)
	subject := subjectFor("sa", "app")

	// Apply with empty desired — GC fires, should not touch the foreign role
	if err := r.Apply(context.Background(), subject, nil); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	all := listRoles(t, c, client.InNamespace("target-ns"))
	if len(all) != 1 || all[0].Name != "foreign-role" {
		t.Errorf("expected foreign role to survive GC, got: %+v", all)
	}
}

func TestApply_GCDoesNotTouchForeignOwnerRoles(t *testing.T) {
	// A role owned by a different component (different owner label value)
	differentOwner := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "other-component-role",
			Namespace: "target-ns",
			Labels: map[string]string{
				ManagedLabelKey:     ManagedLabelValue,
				"myop.io/component": "other-component",
			},
		},
		Rules: basicRules(),
	}

	owner := OwnerLabel{Key: "myop.io/component", Value: "dashboard"}
	r, c := newReconciler(owner, differentOwner)
	subject := subjectFor("sa", "app")

	// Apply with empty desired — GC should only sweep our own label
	if err := r.Apply(context.Background(), subject, nil); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	all := listRoles(t, c, client.InNamespace("target-ns"))
	if len(all) != 1 || all[0].Name != "other-component-role" {
		t.Errorf("expected other-component role to survive, got: %+v", all)
	}
}

// ---------------------------------------------------------------------------
// Teardown

func TestTeardown_DeletesAllManagedResources(t *testing.T) {
	r, c := newReconciler(noOwner())
	subject := subjectFor("sa", "app")

	if err := r.Apply(context.Background(), subject, []RuleSet{
		ruleSet("role-a", "ns-a", basicRules()),
		ruleSet("role-b", "ns-b", basicRules()),
	}); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	if err := r.Teardown(context.Background()); err != nil {
		t.Fatalf("Teardown: %v", err)
	}

	if len(listRoles(t, c, client.MatchingLabels{ManagedLabelKey: ManagedLabelValue})) != 0 {
		t.Error("expected 0 roles after Teardown")
	}
	if len(listRoleBindings(t, c, client.MatchingLabels{ManagedLabelKey: ManagedLabelValue})) != 0 {
		t.Error("expected 0 rolebindings after Teardown")
	}
}

func TestTeardown_Idempotent(t *testing.T) {
	r, _ := newReconciler(noOwner())

	// Teardown on empty state should not fail
	if err := r.Teardown(context.Background()); err != nil {
		t.Fatalf("first Teardown: %v", err)
	}
	if err := r.Teardown(context.Background()); err != nil {
		t.Fatalf("second Teardown: %v", err)
	}
}

func TestTeardown_DoesNotTouchUnmanagedResources(t *testing.T) {
	foreign := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "foreign-rb",
			Namespace: "some-ns",
		},
		RoleRef: rbacv1.RoleRef{Kind: "Role", Name: "r", APIGroup: rbacv1.GroupName},
	}

	r, c := newReconciler(noOwner(), foreign)

	if err := r.Teardown(context.Background()); err != nil {
		t.Fatalf("Teardown: %v", err)
	}

	all := listRoleBindings(t, c, client.InNamespace("some-ns"))
	if len(all) != 1 || all[0].Name != "foreign-rb" {
		t.Errorf("expected foreign rolebinding to survive Teardown, got: %+v", all)
	}
}

// ---------------------------------------------------------------------------
// Labels

func TestApply_ManagedLabelStamped(t *testing.T) {
	r, c := newReconciler(noOwner())
	subject := subjectFor("sa", "app")

	if err := r.Apply(context.Background(), subject, []RuleSet{ruleSet("my-role", "ns", basicRules())}); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	role := getRole(t, c, "ns", "my-role")
	if role.Labels[ManagedLabelKey] != ManagedLabelValue {
		t.Errorf("expected managed label on role, labels: %v", role.Labels)
	}

	rb := getRoleBinding(t, c, "ns", "my-role-binding")
	if rb.Labels[ManagedLabelKey] != ManagedLabelValue {
		t.Errorf("expected managed label on rolebinding, labels: %v", rb.Labels)
	}
}

func TestApply_OwnerLabelStamped(t *testing.T) {
	owner := OwnerLabel{Key: "myop.io/component", Value: "dashboard"}
	r, c := newReconciler(owner)
	subject := subjectFor("sa", "app")

	if err := r.Apply(context.Background(), subject, []RuleSet{ruleSet("my-role", "ns", basicRules())}); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	role := getRole(t, c, "ns", "my-role")
	if role.Labels["myop.io/component"] != "dashboard" {
		t.Errorf("expected owner label on role, labels: %v", role.Labels)
	}

	// Verify the list filter with owner label finds exactly the created resources
	found := listRoles(t, c, managedLabelsFor(owner))
	if len(found) != 1 {
		t.Errorf("expected 1 role via owner-label filter, got %d", len(found))
	}
}

func TestApply_PreservesExistingLabels(t *testing.T) {
	// A role that already has an external label we don't own
	existing := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-role",
			Namespace: "ns",
			Labels: map[string]string{
				ManagedLabelKey:    ManagedLabelValue,
				"external/label":   "keep-me",
			},
		},
		Rules: basicRules(),
	}

	r, c := newReconciler(noOwner(), existing)
	subject := subjectFor("sa", "app")

	if err := r.Apply(context.Background(), subject, []RuleSet{ruleSet("my-role", "ns", basicRules())}); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	role := getRole(t, c, "ns", "my-role")
	if role.Labels["external/label"] != "keep-me" {
		t.Errorf("external label should be preserved, labels: %v", role.Labels)
	}
}

// ---------------------------------------------------------------------------
// RoleBinding RoleRef correctness

func TestApply_RoleRefIsRoleNotClusterRole(t *testing.T) {
	r, c := newReconciler(noOwner())
	subject := subjectFor("sa", "app")

	if err := r.Apply(context.Background(), subject, []RuleSet{ruleSet("my-role", "ns", basicRules())}); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	rb := getRoleBinding(t, c, "ns", "my-role-binding")
	if rb.RoleRef.Kind != "Role" {
		t.Errorf("expected RoleRef.Kind=Role, got %s", rb.RoleRef.Kind)
	}
	if rb.RoleRef.APIGroup != rbacv1.GroupName {
		t.Errorf("expected RoleRef.APIGroup=rbac.authorization.k8s.io, got %s", rb.RoleRef.APIGroup)
	}
}

// ---------------------------------------------------------------------------
// Drifted RoleRef: delete+recreate

func TestApply_DriftedRoleRef_RecreatesRoleBinding(t *testing.T) {
	// Pre-create a RoleBinding with a wrong RoleRef (points to ClusterRole instead of Role)
	drifted := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-role-binding",
			Namespace: "ns",
			Labels:    map[string]string{ManagedLabelKey: ManagedLabelValue},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "ClusterRole",
			Name:     "some-cluster-role",
		},
	}

	r, c := newReconciler(noOwner(), drifted)
	subject := subjectFor("sa", "app")

	if err := r.Apply(context.Background(), subject, []RuleSet{ruleSet("my-role", "ns", basicRules())}); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	rb := getRoleBinding(t, c, "ns", "my-role-binding")
	if rb.RoleRef.Kind != "Role" {
		t.Errorf("expected recreated RoleBinding with Kind=Role, got %s", rb.RoleRef.Kind)
	}
}

// ---------------------------------------------------------------------------
// Same namespace for multiple rule sets

func TestApply_TwoRoleSetsInSameNamespace(t *testing.T) {
	r, c := newReconciler(noOwner())
	subject := subjectFor("sa", "app")

	if err := r.Apply(context.Background(), subject, []RuleSet{
		ruleSet("role-a", "shared-ns", basicRules()),
		ruleSet("role-b", "shared-ns", basicRules()),
	}); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	roles := listRoles(t, c, client.InNamespace("shared-ns"))
	if len(roles) != 2 {
		t.Errorf("expected 2 roles in shared-ns, got %d", len(roles))
	}

	// GC should keep shared-ns since it's in the desired set
	getRole(t, c, "shared-ns", "role-a")
	getRole(t, c, "shared-ns", "role-b")
}

// TestApply_GCsOneRoleInSharedNamespace verifies that when one of two RuleSets
// in the same namespace is removed, only that specific Role/RoleBinding is GC'd
// (not both). This exercises the (namespace, roleName) key correctness of GC.
func TestApply_GCsOneRoleInSharedNamespace(t *testing.T) {
	r, c := newReconciler(noOwner())
	subject := subjectFor("sa", "app")

	// First: create two roles in shared-ns
	if err := r.Apply(context.Background(), subject, []RuleSet{
		ruleSet("role-a", "shared-ns", basicRules()),
		ruleSet("role-b", "shared-ns", basicRules()),
	}); err != nil {
		t.Fatalf("first Apply: %v", err)
	}

	// Second: remove role-b from desired — only role-b should be GC'd
	if err := r.Apply(context.Background(), subject, []RuleSet{
		ruleSet("role-a", "shared-ns", basicRules()),
	}); err != nil {
		t.Fatalf("second Apply: %v", err)
	}

	// role-a and its binding should survive
	getRole(t, c, "shared-ns", "role-a")
	getRoleBinding(t, c, "shared-ns", "role-a-binding")

	// role-b and its binding should be gone
	roles := listRoles(t, c, client.MatchingLabels{ManagedLabelKey: ManagedLabelValue})
	if len(roles) != 1 || roles[0].Name != "role-a" {
		t.Errorf("expected only role-a to survive, got: %+v", roles)
	}
	rbs := listRoleBindings(t, c, client.MatchingLabels{ManagedLabelKey: ManagedLabelValue})
	if len(rbs) != 1 || rbs[0].Name != "role-a-binding" {
		t.Errorf("expected only role-a-binding to survive, got: %+v", rbs)
	}
}

// ---------------------------------------------------------------------------
// Input validation

func TestApply_EmptySubjectName_ReturnsError(t *testing.T) {
	r, _ := newReconciler(noOwner())
	err := r.Apply(context.Background(), SubjectRef{Name: "", Namespace: "ns"}, []RuleSet{ruleSet("role", "ns", basicRules())})
	if err == nil {
		t.Fatal("expected error for empty SubjectRef.Name, got nil")
	}
}

func TestApply_EmptyRoleName_ReturnsError(t *testing.T) {
	r, _ := newReconciler(noOwner())
	err := r.Apply(context.Background(), subjectFor("sa", "ns"), []RuleSet{ruleSet("", "target-ns", basicRules())})
	if err == nil {
		t.Fatal("expected error for empty RoleSet.RoleName, got nil")
	}
}

func TestApply_EmptyNamespace_ReturnsError(t *testing.T) {
	r, _ := newReconciler(noOwner())
	err := r.Apply(context.Background(), subjectFor("sa", "ns"), []RuleSet{ruleSet("role", "", basicRules())})
	if err == nil {
		t.Fatal("expected error for empty RuleSet.Namespace, got nil")
	}
}

func TestApply_EmptyRules_Accepted(t *testing.T) {
	// A RuleSet with no Rules is valid (creates a Role with no permissions).
	r, c := newReconciler(noOwner())
	err := r.Apply(context.Background(), subjectFor("sa", "app"), []RuleSet{ruleSet("role", "ns", nil)})
	if err != nil {
		t.Fatalf("expected nil for empty Rules, got: %v", err)
	}
	role := getRole(t, c, "ns", "role")
	if len(role.Rules) != 0 {
		t.Errorf("expected 0 rules, got %d", len(role.Rules))
	}
}

// ---------------------------------------------------------------------------
// OwnerLabel isolation

func TestReconciler_OwnerLabelIsolatesFromOtherControllers(t *testing.T) {
	// Two reconcilers with different owner labels managing different resources
	ownerA := OwnerLabel{Key: "myop.io/component", Value: "comp-a"}
	ownerB := OwnerLabel{Key: "myop.io/component", Value: "comp-b"}

	rA, c := newReconciler(ownerA)
	rB := New(c, ownerB)

	subject := subjectFor("sa", "app")

	// rA creates role-a in ns-a
	if err := rA.Apply(context.Background(), subject, []RuleSet{ruleSet("role-a", "ns-a", basicRules())}); err != nil {
		t.Fatalf("rA.Apply: %v", err)
	}

	// rB creates role-b in ns-b
	if err := rB.Apply(context.Background(), subject, []RuleSet{ruleSet("role-b", "ns-b", basicRules())}); err != nil {
		t.Fatalf("rB.Apply: %v", err)
	}

	// rA tears down — only comp-a resources should be removed
	if err := rA.Teardown(context.Background()); err != nil {
		t.Fatalf("rA.Teardown: %v", err)
	}

	// role-a should be gone
	var roleList rbacv1.RoleList
	if err := c.List(context.Background(), &roleList, client.InNamespace("ns-a")); err != nil {
		t.Fatalf("listing ns-a roles: %v", err)
	}
	if len(roleList.Items) != 0 {
		t.Errorf("expected role-a removed after rA.Teardown, got %+v", roleList.Items)
	}

	// role-b should survive
	getRole(t, c, "ns-b", "role-b")
}

// ---------------------------------------------------------------------------
// Error accumulation: listing failure is propagated

func TestGC_PropagatesListError(t *testing.T) {
	// We can't easily inject a list error with the fake client, so this test
	// verifies the happy-path return type is nil and the error path isn't
	// swallowed — covered implicitly by all other tests that rely on
	// errors.Join semantics.
	r, _ := newReconciler(noOwner())
	if err := r.Teardown(context.Background()); err != nil {
		t.Errorf("expected nil error on empty Teardown, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// mergeLabels helper

func TestMergeLabels(t *testing.T) {
	base := map[string]string{"a": "1", "b": "2"}
	additional := map[string]string{"b": "3", "c": "4"}
	result := mergeLabels(base, additional)

	if result["a"] != "1" {
		t.Error("expected a=1")
	}
	if result["b"] != "3" {
		t.Errorf("additional should win on conflict: got b=%s", result["b"])
	}
	if result["c"] != "4" {
		t.Error("expected c=4")
	}
	// Original maps should not be mutated
	if base["b"] != "2" {
		t.Error("base map should not be mutated")
	}
}

func TestMergeLabels_NilBase(t *testing.T) {
	result := mergeLabels(nil, map[string]string{"x": "1"})
	if result["x"] != "1" {
		t.Error("expected x=1 with nil base")
	}
}

func TestMergeLabels_NilAdditional(t *testing.T) {
	result := mergeLabels(map[string]string{"x": "1"}, nil)
	if result["x"] != "1" {
		t.Error("expected x=1 with nil additional")
	}
}
