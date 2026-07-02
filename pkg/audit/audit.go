package audit

import (
	"context"
	"errors"
	"fmt"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

type scannerFunc func() ([]Finding, error)

func Scan(ctx context.Context, c client.Client, cfg Config) ([]Finding, error) {
	scanners := []scannerFunc{
		func() ([]Finding, error) { return scanImpersonationGrants(ctx, c) },
		func() ([]Finding, error) { return scanTokenRequestExposure(ctx, c) },
		func() ([]Finding, error) { return scanAggregateToEditStatus(ctx, c) },
		func() ([]Finding, error) { return scanUnusedPermissions(ctx, c, cfg) },
		func() ([]Finding, error) { return scanAggregationRules(ctx, c, cfg) },
	}

	var all []Finding
	var scanErrors []error
	for _, scan := range scanners {
		findings, err := scan()
		if err != nil {
			scanErrors = append(scanErrors, err)
			continue
		}
		all = append(all, findings...)
	}

	if len(scanErrors) > 0 {
		return all, fmt.Errorf("audit scan errors: %w", errors.Join(scanErrors...))
	}

	return all, nil
}
