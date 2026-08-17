package scoper

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
)

type ScopingTarget struct {
	WatchGVK              schema.GroupVersionKind
	ClusterRoleName       string
	ManagedRoleBindingName string
	NamespaceSelector     *metav1.LabelSelector
	TargetNamespaceSource *NamespaceSource

	// Resource is the plural resource name (e.g. "networkpolicies"). When empty,
	// the webhook handler derives it from WatchGVK.Kind via pluralize().
	Resource string

	// WebhookProvisioning enables MutatingAdmissionWebhook provisioning (same-namespace only)
	WebhookProvisioning bool

	// NamespaceLabelTrigger pre-provisions RoleBindings when namespaces match this label selector
	NamespaceLabelTrigger *metav1.LabelSelector

	// --- SA resolution (exactly one of TargetSA / TargetSASource / TargetSAFunc must be set) ---

	// TargetSA is the static service account this target grants access to.
	// Use this for operators with a single, known SA at configuration time (Option A).
	TargetSA types.NamespacedName

	// TargetSASource resolves the SA name and/or namespace from fields in the
	// reconciled CR at runtime. Use this when each CR instance names the SA it
	// owns in a spec field (Option B).
	TargetSASource *SASource

	// TargetSAFunc is a callback that returns the SA for a given CR instance.
	// Use this when the resolution logic is too complex for a field path (Option C).
	TargetSAFunc func(*unstructured.Unstructured) types.NamespacedName

	// ManagedRoleBindingNameFunc, when set, overrides ManagedRoleBindingName by
	// computing a per-CR RoleBinding name. Required when TargetSASource or
	// TargetSAFunc is used and multiple CR instances can target the same namespace
	// with different SAs — otherwise a static name would cause the last writer to
	// overwrite the first.
	ManagedRoleBindingNameFunc func(*unstructured.Unstructured) string
}

// SASource resolves a service account name and/or namespace from CR spec fields.
// Fields that are empty strings are left at their default (SA name from
// NameFieldPath, namespace from NamespaceFieldPath). Both paths must start with
// ".spec." to prevent escalation via user-controlled metadata fields.
type SASource struct {
	// NameFieldPath is the dot-separated path to the SA name in the CR
	// (e.g. ".spec.serviceAccountName"). Required.
	NameFieldPath string

	// NamespaceFieldPath is the dot-separated path to the SA namespace in the CR
	// (e.g. ".spec.serviceAccountNamespace"). Optional: if empty, the SA is
	// assumed to live in the CR's own namespace.
	NamespaceFieldPath string
}

type NamespaceSource struct {
	FieldPath string
}

type Config struct {
	Targets          []ScopingTarget
	DenyList         DenyListConfig
	CleanupInterval  metav1.Duration
	ControllerNamespace string
}

type DenyListConfig struct {
	Namespaces []string
	Prefixes   []string
}

func DefaultDenyList(controllerNamespace string) DenyListConfig {
	ns := []string{
		"kube-system",
		"kube-public",
		"kube-node-lease",
		"default",
	}
	if controllerNamespace != "" {
		ns = append(ns, controllerNamespace)
	}
	return DenyListConfig{
		Namespaces: ns,
		Prefixes:   []string{"openshift-"},
	}
}

const (
	OwnerAnnotationKey = "operator-rbac-toolkit.io/scoped-access-owners"

	// ManagedLabelKey is applied to RoleBindings created by the scoper so
	// cleanup can list only managed resources instead of every RoleBinding
	// in the cluster.
	ManagedLabelKey   = "operator-rbac-toolkit.io/managed"
	ManagedLabelValue = "true"

	// PendingOwnerAnnotationKey stores pending ownership info for webhook-created RoleBindings
	// Format: namespace/name/GVK/RFC3339-timestamp
	PendingOwnerAnnotationKey = "operator-rbac-toolkit.io/pending-owner"

	// CreatedByAnnotationKey indicates which component created the RoleBinding
	CreatedByAnnotationKey = "operator-rbac-toolkit.io/created-by"

	// CreatedBy values
	CreatedByWebhook      = "webhook"
	CreatedByScoper       = "scoper"
	CreatedByLabelTrigger = "label-trigger"
)
