# Troubleshooting

## Scoping controller fails to start with "no scoping targets configured"

The `Config.Targets` slice is empty. At least one `ScopingTarget` must be provided.

## "ClusterRole uses aggregationRule, which is not allowed"

The static ClusterRole specified in `ClusterRoleName` has an `aggregationRule` field. This is rejected because aggregated ClusterRoles allow rule injection via label-matching component ClusterRoles. Remove the `aggregationRule` from the ClusterRole and define rules explicitly.

## "CRD not available, skipping controller registration"

The CRD for the configured `WatchGVK` is not installed in the cluster. The scoping controller logs a warning and skips this target. Install the CRD and restart the scoping controller.

## Operator shows "Degraded: InsufficientRBAC" status condition

The operator is missing one or more RBAC permissions. Check the condition's `message` field for the specific permission. Common causes:

- The scoping controller has not yet created a RoleBinding (check if the CR exists and the namespace is allowed).
- The static ClusterRole is missing the required rule.
- The legacy ClusterRoleBinding was removed before the scoping controller was deployed.

## RoleBindings not created in expected namespaces

Check these in order:

1. **Is the namespace in the deny-list?** Check whether the namespace appears in the deny-list configuration (default: kube-system, kube-public, kube-node-lease, default, the controller's own namespace, and any openshift-* prefixed namespaces).
2. **Does the namespace match the `NamespaceSelector`?** The namespace must have the required labels.
3. **Does the static ClusterRole exist?** The controller logs a warning and emits an event if the ClusterRole is missing.
4. **Does the CR exist in the namespace?** The controller only creates RoleBindings in namespaces that contain CRs of the configured GVK (or in the target namespace for cross-namespace grants).

## Cross-namespace RoleBindings persist after CR deletion

Cross-namespace RoleBindings use annotation-based ownership with periodic cleanup (default: 5 minutes). If the cleanup reconciler was down when the CR was deleted, the RoleBinding persists until the next cleanup scan. This is a temporary over-grant, not a bug. The design prioritizes avoiding stuck finalizers (which block namespace deletion) over immediate cleanup.

## SA protection webhook blocks all pod creation

The webhook is deployed with `failurePolicy: Fail`. If the webhook pod is down, all pod creation in namespaces matching the webhook's `namespaceSelector` is blocked. Verify the webhook pod is running. Deploy the webhook in a separate namespace from the operator it protects, with a `PriorityClass` and `PodDisruptionBudget`.

## Impersonation guard finds no ClusterRoles to modify

The guard watches ClusterRoles with `rbac.authorization.kubernetes.io/aggregate-to-edit: "true"`. If no such ClusterRoles exist (possible on non-standard Kubernetes distributions), the guard is a no-op. Run the RBAC audit component to verify whether `system:aggregate-to-edit` still includes the `impersonate` verb.

## RBAC audit shows "unused-permissions" findings

These are `Info` severity findings indicating that rules in ClusterRoles bound to your SA don't match any of your `ExpectedRules`. Review each finding. If the permission is genuinely needed, add it to `ExpectedRules`. If it is truly unused, remove it from the ClusterRole to reduce blast radius.

## Permission discovery shows denied permissions that should be allowed

`DiscoverPermissions` uses `SelfSubjectAccessReview`, which checks the actual permissions of the SA making the call. If the discovery runs before the scoping controller creates the RoleBinding (e.g., during startup race), permissions may show as denied. Retry after the scoping controller has had time to reconcile, or add the graceful degradation library's `Do()` wrapper to handle the transient denial.
