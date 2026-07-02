package audit

import (
	"context"
	"fmt"
	"slices"
	"strings"

	rbacv1 "k8s.io/api/rbac/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func scanImpersonationGrants(ctx context.Context, c client.Client) ([]Finding, error) {
	var findings []Finding

	clusterRoles := &rbacv1.ClusterRoleList{}
	if err := c.List(ctx, clusterRoles); err != nil {
		return nil, fmt.Errorf("listing ClusterRoles: %w", err)
	}
	for _, cr := range clusterRoles.Items {
		for _, rule := range cr.Rules {
			if grantsImpersonateOnSAs(rule) {
				findings = append(findings, Finding{
					Severity: Critical,
					Category: "impersonation-grants",
					Message:  fmt.Sprintf("ClusterRole %q grants impersonate on ServiceAccounts", cr.Name),
					Resource: &ResourceRef{Kind: "ClusterRole", Name: cr.Name},
				})
				break
			}
		}
	}

	roles := &rbacv1.RoleList{}
	if err := c.List(ctx, roles); err != nil {
		return nil, fmt.Errorf("listing Roles: %w", err)
	}
	for _, r := range roles.Items {
		for _, rule := range r.Rules {
			if grantsImpersonateOnSAs(rule) {
				findings = append(findings, Finding{
					Severity: Critical,
					Category: "impersonation-grants",
					Message:  fmt.Sprintf("Role %q in namespace %q grants impersonate on ServiceAccounts", r.Name, r.Namespace),
					Resource: &ResourceRef{Kind: "Role", Name: r.Name, Namespace: r.Namespace},
				})
				break
			}
		}
	}

	return findings, nil
}

func scanTokenRequestExposure(ctx context.Context, c client.Client) ([]Finding, error) {
	var findings []Finding

	clusterRoles := &rbacv1.ClusterRoleList{}
	if err := c.List(ctx, clusterRoles); err != nil {
		return nil, fmt.Errorf("listing ClusterRoles: %w", err)
	}
	for _, cr := range clusterRoles.Items {
		for _, rule := range cr.Rules {
			if grantsTokenRequest(rule) {
				findings = append(findings, Finding{
					Severity: Critical,
					Category: "tokenrequest-exposure",
					Message:  fmt.Sprintf("ClusterRole %q grants create on serviceaccounts/token", cr.Name),
					Resource: &ResourceRef{Kind: "ClusterRole", Name: cr.Name},
				})
				break
			}
		}
	}

	roles := &rbacv1.RoleList{}
	if err := c.List(ctx, roles); err != nil {
		return nil, fmt.Errorf("listing Roles: %w", err)
	}
	for _, r := range roles.Items {
		for _, rule := range r.Rules {
			if grantsTokenRequest(rule) {
				findings = append(findings, Finding{
					Severity: Critical,
					Category: "tokenrequest-exposure",
					Message:  fmt.Sprintf("Role %q in namespace %q grants create on serviceaccounts/token", r.Name, r.Namespace),
					Resource: &ResourceRef{Kind: "Role", Name: r.Name, Namespace: r.Namespace},
				})
				break
			}
		}
	}

	return findings, nil
}

func scanAggregateToEditStatus(ctx context.Context, c client.Client) ([]Finding, error) {
	cr := &rbacv1.ClusterRole{}
	key := client.ObjectKey{Name: "system:aggregate-to-edit"}
	if err := c.Get(ctx, key, cr); err != nil {
		return nil, fmt.Errorf("getting system:aggregate-to-edit: %w", err)
	}

	for _, rule := range cr.Rules {
		if grantsImpersonateOnSAs(rule) {
			return []Finding{{
				Severity: Warning,
				Category: "aggregate-to-edit-impersonate",
				Message:  "system:aggregate-to-edit still includes the impersonate verb for ServiceAccounts",
				Resource: &ResourceRef{Kind: "ClusterRole", Name: "system:aggregate-to-edit"},
			}}, nil
		}
	}

	return nil, nil
}

func scanUnusedPermissions(ctx context.Context, c client.Client, cfg Config) ([]Finding, error) {
	if len(cfg.ExpectedRules) == 0 {
		return nil, nil
	}

	bindings := &rbacv1.ClusterRoleBindingList{}
	if err := c.List(ctx, bindings); err != nil {
		return nil, fmt.Errorf("listing ClusterRoleBindings: %w", err)
	}

	var clusterRoleName string
	for _, b := range bindings.Items {
		for _, s := range b.Subjects {
			if s.Kind == "ServiceAccount" &&
				s.Name == cfg.ServiceAccount.Name &&
				s.Namespace == cfg.ServiceAccount.Namespace {
				if b.RoleRef.Kind == "ClusterRole" {
					clusterRoleName = b.RoleRef.Name
					break
				}
			}
		}
		if clusterRoleName != "" {
			break
		}
	}

	if clusterRoleName == "" {
		return nil, nil
	}

	cr := &rbacv1.ClusterRole{}
	if err := c.Get(ctx, client.ObjectKey{Name: clusterRoleName}, cr); err != nil {
		return nil, fmt.Errorf("getting ClusterRole %q: %w", clusterRoleName, err)
	}

	var findings []Finding
	for _, actual := range cr.Rules {
		if !ruleMatchesAnyExpected(actual, cfg.ExpectedRules) {
			findings = append(findings, Finding{
				Severity: Info,
				Category: "unused-permissions",
				Message:  fmt.Sprintf("Rule in ClusterRole %q not in expected set: %s", clusterRoleName, formatRule(actual)),
				Resource: &ResourceRef{Kind: "ClusterRole", Name: clusterRoleName},
			})
		}
	}

	return findings, nil
}

func scanAggregationRules(ctx context.Context, c client.Client, cfg Config) ([]Finding, error) {
	bindings := &rbacv1.ClusterRoleBindingList{}
	if err := c.List(ctx, bindings); err != nil {
		return nil, fmt.Errorf("listing ClusterRoleBindings: %w", err)
	}

	var findings []Finding
	seen := make(map[string]bool)

	for _, b := range bindings.Items {
		for _, s := range b.Subjects {
			if s.Kind == "ServiceAccount" &&
				s.Name == cfg.ServiceAccount.Name &&
				s.Namespace == cfg.ServiceAccount.Namespace &&
				b.RoleRef.Kind == "ClusterRole" &&
				!seen[b.RoleRef.Name] {

				seen[b.RoleRef.Name] = true

				cr := &rbacv1.ClusterRole{}
				if err := c.Get(ctx, client.ObjectKey{Name: b.RoleRef.Name}, cr); err != nil {
					return nil, fmt.Errorf("getting ClusterRole %q: %w", b.RoleRef.Name, err)
				}

				if cr.AggregationRule != nil {
					findings = append(findings, Finding{
						Severity: Warning,
						Category: "aggregation-rules",
						Message:  fmt.Sprintf("ClusterRole %q uses aggregationRule, which allows rule injection via label-matching ClusterRoles", b.RoleRef.Name),
						Resource: &ResourceRef{Kind: "ClusterRole", Name: b.RoleRef.Name},
					})
				}
			}
		}
	}

	return findings, nil
}

func grantsImpersonateOnSAs(rule rbacv1.PolicyRule) bool {
	hasVerb := containsAny(rule.Verbs, "impersonate", "*")
	hasResource := containsAny(rule.Resources, "serviceaccounts", "*")
	hasCoreGroup := containsAny(rule.APIGroups, "", "*")
	return hasVerb && hasResource && hasCoreGroup
}

func grantsTokenRequest(rule rbacv1.PolicyRule) bool {
	hasVerb := containsAny(rule.Verbs, "create", "*")
	hasResource := containsAny(rule.Resources, "serviceaccounts/token", "*")
	hasCoreGroup := containsAny(rule.APIGroups, "", "*")
	return hasVerb && hasResource && hasCoreGroup
}

func containsAny(haystack []string, needles ...string) bool {
	for _, n := range needles {
		if slices.Contains(haystack, n) {
			return true
		}
	}
	return false
}

func ruleMatchesAnyExpected(actual rbacv1.PolicyRule, expected []rbacv1.PolicyRule) bool {
	for _, exp := range expected {
		if rulesOverlap(actual, exp) {
			return true
		}
	}
	return false
}

// rulesOverlap returns true if the actual rule shares at least one apiGroup,
// one resource, and one verb with the expected rule. This is a conservative
// match: it flags rules that have zero overlap with anything expected.
func rulesOverlap(actual, expected rbacv1.PolicyRule) bool {
	return hasCommon(actual.APIGroups, expected.APIGroups) &&
		hasCommon(actual.Resources, expected.Resources) &&
		hasCommon(actual.Verbs, expected.Verbs)
}

func hasCommon(a, b []string) bool {
	for _, v := range a {
		if slices.Contains(b, v) {
			return true
		}
	}
	return false
}

func formatRule(rule rbacv1.PolicyRule) string {
	return fmt.Sprintf("apiGroups=%s resources=%s verbs=%s",
		strings.Join(rule.APIGroups, ","),
		strings.Join(rule.Resources, ","),
		strings.Join(rule.Verbs, ","))
}
