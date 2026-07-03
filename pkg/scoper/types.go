package scoper

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
)

type ScopingTarget struct {
	WatchGVK              schema.GroupVersionKind
	TargetSA              types.NamespacedName
	ClusterRoleName       string
	ManagedRoleBindingName string
	NamespaceSelector     *metav1.LabelSelector
	TargetNamespaceSource *NamespaceSource
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
)
