package audit

import (
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/types"
)

type Severity string

const (
	Critical Severity = "Critical"
	Warning  Severity = "Warning"
	Info     Severity = "Info"
)

type Finding struct {
	Severity Severity
	Category string
	Message  string
	Resource *ResourceRef
}

type ResourceRef struct {
	Kind      string
	Name      string
	Namespace string
}

type Config struct {
	ServiceAccount types.NamespacedName
	ExpectedRules  []rbacv1.PolicyRule
}
