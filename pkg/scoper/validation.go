package scoper

import (
	"context"
	"fmt"
	"strings"

	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func IsDenied(namespace string, denyList DenyListConfig) bool {
	for _, ns := range denyList.Namespaces {
		if namespace == ns {
			return true
		}
	}
	for _, prefix := range denyList.Prefixes {
		if strings.HasPrefix(namespace, prefix) {
			return true
		}
	}
	return false
}

func ValidateClusterRole(ctx context.Context, c client.Client, name string) error {
	cr := &rbacv1.ClusterRole{}
	if err := c.Get(ctx, types.NamespacedName{Name: name}, cr); err != nil {
		return fmt.Errorf("ClusterRole %q not found: %w", name, err)
	}
	if cr.AggregationRule != nil {
		return fmt.Errorf("ClusterRole %q uses aggregationRule, which is not allowed for static ClusterRoles", name)
	}
	return nil
}

func MatchesSelector(nsLabels map[string]string, selector *labels.Selector) bool {
	if selector == nil {
		return true
	}
	return (*selector).Matches(labels.Set(nsLabels))
}
