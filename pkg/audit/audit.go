package audit

import (
	"context"
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
	for _, scan := range scanners {
		findings, err := scan()
		if err != nil {
			return nil, fmt.Errorf("audit scan failed: %w", err)
		}
		all = append(all, findings...)
	}

	return all, nil
}
