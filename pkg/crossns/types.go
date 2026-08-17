package crossns

import (
	rbacv1 "k8s.io/api/rbac/v1"
)

const (
	// ManagedLabelKey is applied to Roles and RoleBindings created by the
	// crossns reconciler. The value must match ManagedLabelValue so that
	// label-based list queries can find only resources owned by this library.
	ManagedLabelKey   = "operator-rbac-toolkit.io/crossns-managed"
	ManagedLabelValue = "true"
)

// RuleSet describes a single cross-namespace RBAC grant: the Role name, the
// target namespace, and the rules the Role should carry. The RoleBinding name
// is derived as RoleName + "-binding".
//
// RoleName and Namespace must both be non-empty; Apply returns an error if
// either is empty.
//
// Naming constraint: avoid RoleName values that end with "-binding" to prevent
// accidental collisions between the derived RoleBinding name and other Roles.
//
// Security: Kubernetes enforces privilege non-escalation at the API server level.
// The operator's own ServiceAccount must already hold the verbs and resources
// specified in Rules, otherwise the Create will be rejected. Do not rely on
// this library as a privilege boundary.
type RuleSet struct {
	// RoleName is the metadata.name of the Role (and the base for the RoleBinding name).
	RoleName string

	// Namespace is the target namespace in which the Role and RoleBinding are created.
	Namespace string

	// Rules are the policy rules for the Role. An empty slice creates a Role
	// with no permissions, which is valid but likely unintentional.
	Rules []rbacv1.PolicyRule
}

// SubjectRef identifies the ServiceAccount that is granted the Role.
// Only ServiceAccount subjects are supported; use Kind=ServiceAccount in
// the resulting RoleBinding. Name must be non-empty.
type SubjectRef struct {
	// Name is the ServiceAccount name. Must not be empty.
	Name string

	// Namespace is the namespace that contains the ServiceAccount.
	Namespace string
}

// OwnerLabel is an optional label pair that narrows the list scope so multiple
// independent controllers can each manage their own set of crossns resources
// without interfering with each other's label sweep.
//
// If set, the reconciler adds this label to every managed resource and filters
// by it during GC/Teardown. If empty (zero value), only ManagedLabelKey is
// used — meaning Teardown will sweep ALL resources carrying ManagedLabelKey
// cluster-wide, including resources created by other Reconciler instances.
//
// Always set a distinct OwnerLabel when multiple operators or controller
// instances share the same cluster.
//
// If Key is non-empty and Value is empty string, the label is stamped with an
// empty-string value and the list query performs an exact-match on "".
type OwnerLabel struct {
	Key   string
	Value string
}
