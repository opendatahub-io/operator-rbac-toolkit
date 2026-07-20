package scoper

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	rbacv1 "k8s.io/api/rbac/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
)

// TargetHealthStatus represents the health status of a single scoping target.
type TargetHealthStatus struct {
	Name                 string `json:"name"`
	ClusterRoleExists    bool   `json:"clusterRoleExists"`
	ManagedRoleBindings  int    `json:"managedRoleBindings"`
	OrphanRoleBindings   int    `json:"orphanRoleBindings"`
	WebhookProvisioning  bool   `json:"webhookProvisioning"`
}

// RBACHealthResponse is the JSON structure returned by RBACHealthHandler.
type RBACHealthResponse struct {
	Targets           []TargetHealthStatus `json:"targets"`
	Healthy           bool                 `json:"healthy"`
	WebhookRegistered bool                 `json:"webhookRegistered"`
	LastFullResync    string               `json:"lastFullResync"`
}

// RBACHealthHandler returns an http.Handler that serves RBAC health status as JSON.
// The host operator registers this on its debug server (e.g., /debug/rbac-health).
func RBACHealthHandler(cfg Config, c client.Client) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// Single cluster-wide list call for all managed RoleBindings (MINOR 8 optimization)
		rbList := &rbacv1.RoleBindingList{}
		var listErr error
		if err := c.List(ctx, rbList, client.MatchingLabels{ManagedLabelKey: ManagedLabelValue}); err != nil {
			listErr = err
		}

		now := time.Now()
		const pendingOwnerTTL = 30 * time.Second

		targets := make([]TargetHealthStatus, 0, len(cfg.Targets))
		allHealthy := true

		for _, target := range cfg.Targets {
			status := TargetHealthStatus{
				Name:                target.ManagedRoleBindingName,
				WebhookProvisioning: target.WebhookProvisioning,
			}

			// Check if ClusterRole exists
			err := ValidateClusterRole(ctx, c, target.ClusterRoleName)
			status.ClusterRoleExists = (err == nil)
			if !status.ClusterRoleExists {
				allHealthy = false
			}

			// Count managed RoleBindings and orphans from the pre-fetched list
			if listErr == nil {
				for _, rb := range rbList.Items {
					if rb.Name != target.ManagedRoleBindingName {
						continue
					}
					status.ManagedRoleBindings++
					// Count expired pending-owner RoleBindings as orphans
					if pendingAnnotation, ok := rb.Annotations[PendingOwnerAnnotationKey]; ok {
						_, _, timestamp, err := parsePendingOwner(pendingAnnotation)
						if err == nil && now.Sub(timestamp) > pendingOwnerTTL {
							status.OrphanRoleBindings++
						}
					}
				}
			}

			targets = append(targets, status)
		}

		response := RBACHealthResponse{
			Targets:           targets,
			Healthy:           allHealthy,
			WebhookRegistered: false, // placeholder, webhook registration check can be added later
			LastFullResync:    "",     // placeholder for future resync tracking
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			http.Error(w, fmt.Sprintf("failed to encode response: %v", err), http.StatusInternalServerError)
			return
		}
	})
}

// RBACHealthzCheck returns a healthz.Checker that passes when all ClusterRoles exist.
// Use with mgr.AddHealthzCheck("rbac", RBACHealthzCheck(cfg, c)).
func RBACHealthzCheck(cfg Config, c client.Client) healthz.Checker {
	return func(req *http.Request) error {
		ctx := req.Context()

		var missingRoles []string
		for _, target := range cfg.Targets {
			if err := ValidateClusterRole(ctx, c, target.ClusterRoleName); err != nil {
				missingRoles = append(missingRoles, target.ClusterRoleName)
			}
		}

		if len(missingRoles) > 0 {
			return fmt.Errorf("missing ClusterRoles: %v", missingRoles)
		}
		return nil
	}
}

// countManagedRoleBindings counts RoleBindings with the managed label for a specific target.
func countManagedRoleBindings(ctx context.Context, c client.Client, targetName string) (int, error) {
	rbList := &rbacv1.RoleBindingList{}

	// List all RoleBindings with the managed label
	if err := c.List(ctx, rbList, client.MatchingLabels{
		ManagedLabelKey: ManagedLabelValue,
	}); err != nil {
		return 0, fmt.Errorf("failed to list managed RoleBindings: %w", err)
	}

	count := 0
	for _, rb := range rbList.Items {
		// Filter by target name (the RoleBinding name matches ManagedRoleBindingName)
		if rb.Name == targetName {
			count++
		}
	}

	return count, nil
}
