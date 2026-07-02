package graceful

import (
	"context"
	"fmt"
	"sync"

	authorizationv1 "k8s.io/api/authorization/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type ssarCheck struct {
	group     string
	resource  string
	verb      string
	namespace string
}

// DiscoverPermissions performs SelfSubjectAccessReview checks for each
// resource/verb/namespace combination in the spec. SSAR calls are rate-limited
// by MaxConcurrency (defaults to DefaultMaxConcurrency if zero or negative).
func DiscoverPermissions(ctx context.Context, c client.Client, spec PermissionSpec) (*PermissionReport, error) {
	concurrency := spec.MaxConcurrency
	if concurrency <= 0 {
		concurrency = DefaultMaxConcurrency
	}

	var checks []ssarCheck
	for _, res := range spec.Resources {
		namespaces := spec.Namespaces
		if len(namespaces) == 0 {
			namespaces = []string{""}
		}
		for _, verb := range res.Verbs {
			for _, ns := range namespaces {
				checks = append(checks, ssarCheck{
					group:     res.Group,
					resource:  res.Resource,
					verb:      verb,
					namespace: ns,
				})
			}
		}
	}

	results := make([]PermissionResult, len(checks))
	errs := make([]error, len(checks))
	sem := make(chan struct{}, concurrency)

	var wg sync.WaitGroup
	for i, check := range checks {
		wg.Add(1)
		go func(idx int, ch ssarCheck) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			allowed, err := checkSSAR(ctx, c, ch)
			if err != nil {
				errs[idx] = err
				return
			}
			results[idx] = PermissionResult{
				Group:     ch.group,
				Resource:  ch.resource,
				Verb:      ch.verb,
				Namespace: ch.namespace,
				Allowed:   allowed,
			}
		}(i, check)
	}
	wg.Wait()

	for _, err := range errs {
		if err != nil {
			return nil, fmt.Errorf("SSAR check failed: %w", err)
		}
	}

	report := &PermissionReport{}
	for _, r := range results {
		if r.Allowed {
			report.Granted = append(report.Granted, r)
		} else {
			report.Denied = append(report.Denied, r)
		}
	}

	totalNamespaces := len(spec.Namespaces)
	if totalNamespaces == 0 {
		totalNamespaces = 1
	}
	report.Summary = fmt.Sprintf("%d/%d permissions granted across %d namespace(s)",
		len(report.Granted), len(results), totalNamespaces)

	return report, nil
}

func checkSSAR(ctx context.Context, c client.Client, check ssarCheck) (bool, error) {
	ssar := &authorizationv1.SelfSubjectAccessReview{
		Spec: authorizationv1.SelfSubjectAccessReviewSpec{
			ResourceAttributes: &authorizationv1.ResourceAttributes{
				Namespace: check.namespace,
				Verb:      check.verb,
				Group:     check.group,
				Resource:  check.resource,
			},
		},
	}

	if err := c.Create(ctx, ssar, &client.CreateOptions{}); err != nil {
		return false, fmt.Errorf("creating SelfSubjectAccessReview for %s %s/%s in %q: %w",
			check.verb, check.group, check.resource, check.namespace, err)
	}

	return ssar.Status.Allowed, nil
}

// CheckPermission performs a single SelfSubjectAccessReview check.
func CheckPermission(ctx context.Context, c client.Client, group, resource, verb, namespace string) (bool, error) {
	return checkSSAR(ctx, c, ssarCheck{
		group:     group,
		resource:  resource,
		verb:      verb,
		namespace: namespace,
	})
}

// ApplyReport sets status conditions on a StatusProvider based on the report.
// If there are denied permissions, PermissionGranted is set to False and
// Degraded is set to True. If all permissions are granted, the conditions
// reflect a healthy state.
func ApplyReport(ctx context.Context, c client.Client, obj client.Object, report *PermissionReport) error {
	sp, ok := obj.(StatusProvider)
	if !ok {
		return nil
	}

	if len(report.Denied) > 0 {
		msgs := make([]string, 0, len(report.Denied))
		for _, d := range report.Denied {
			msgs = append(msgs, permissionDeniedMessage(d.Verb, d.Resource, d.Namespace))
		}
		msg := fmt.Sprintf("%d permission(s) denied: %s", len(report.Denied), joinMax(msgs, 3))
		SetPermissionGranted(sp, false, msg)
	} else {
		SetPermissionGranted(sp, true, report.Summary)
	}

	return UpdateStatus(ctx, c, obj)
}

func joinMax(items []string, max int) string {
	if len(items) <= max {
		return join(items)
	}
	result := join(items[:max])
	return fmt.Sprintf("%s (and %d more)", result, len(items)-max)
}

func join(items []string) string {
	if len(items) == 0 {
		return ""
	}
	result := items[0]
	for _, item := range items[1:] {
		result += "; " + item
	}
	return result
}

// DiscoverNamespacedPermissions is a convenience wrapper that discovers
// permissions for a single resource across a set of namespaces. Returns a map
// of namespace to whether the permission is allowed, enabling callers to
// decide which namespaces to skip during reconciliation.
func DiscoverNamespacedPermissions(ctx context.Context, c client.Client, group, resource, verb string, namespaces []string) (map[string]bool, error) {
	report, err := DiscoverPermissions(ctx, c, PermissionSpec{
		Resources: []ResourceSpec{
			{Group: group, Resource: resource, Verbs: []string{verb}},
		},
		Namespaces: namespaces,
	})
	if err != nil {
		return nil, err
	}

	result := make(map[string]bool, len(namespaces))
	for _, r := range report.Granted {
		result[r.Namespace] = true
	}
	for _, r := range report.Denied {
		if _, exists := result[r.Namespace]; !exists {
			result[r.Namespace] = false
		}
	}
	return result, nil
}
