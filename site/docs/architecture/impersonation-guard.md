# Impersonation Guard

## Purpose

A reconciler that closes the impersonation bypass in Kubernetes RBAC. The default `system:aggregate-to-edit` ClusterRole includes the `impersonate` verb for ServiceAccounts. This allows any namespace editor to impersonate any ServiceAccount in their namespace, inheriting that SA's full permissions.

---

## Approach

`system:aggregate-to-edit` is an aggregated ClusterRole. Its `rules` field is computed by the Kubernetes aggregation controller from component ClusterRoles matching the `rbac.authorization.kubernetes.io/aggregate-to-edit: "true"` label selector. The `impersonate` verb comes from one of these component ClusterRoles.

The impersonation guard takes a three-part approach:

1. **Component ClusterRole modification.** Identifies the component ClusterRole that contributes the `impersonate` verb for ServiceAccounts (the one with the `aggregate-to-edit` label) and removes the `impersonate` verb from it. This causes the aggregation controller to recompute `system:aggregate-to-edit` without the verb.
2. **Autoupdate annotation.** Sets `rbac.authorization.kubernetes.io/autoupdate: "false"` on the component ClusterRole to prevent the RBAC bootstrap reconciliation controller (which runs on API server startup) from resetting it to defaults.
3. **Continuous reconciliation.** Watches for drift and re-applies the fix. During Kubernetes upgrades, the bootstrap reconciliation may reset the component ClusterRole. The guard detects and corrects this.

The guard does **not** directly modify the `rules` field of `system:aggregate-to-edit` itself, as the aggregation controller would immediately overwrite any such change. Instead, it modifies the source (the component ClusterRole) so the aggregation controller computes the desired result.

This component operates in the admin trust domain and requires write access to RBAC ClusterRole resources, consistent with the design principle that admin-side components may manage RBAC resources.

---

## Why Webhooks Cannot Solve This

Impersonation headers (`Impersonate-User`, `Impersonate-Group`) are resolved during the authentication phase, and the authorization check for the `impersonate` verb happens at the authorization layer. Both occur **before** the request reaches the admission chain.

By the time a ValidatingWebhook sees a Pod CREATE request, the caller's identity has already been swapped to the impersonated identity. The webhook cannot distinguish an impersonated request from a direct one, and cannot block the impersonation itself.

---

## Startup Race Window

Between the impersonation guard starting and completing its first reconciliation, the `impersonate` verb may be active in the component ClusterRole (and therefore in the aggregated `system:aggregate-to-edit`). This window is typically sub-second but is unbounded if the guard pod is pending (e.g., due to resource pressure).

Mitigations:

- Deploy the impersonation guard with a high PriorityClass to ensure it schedules before operator workloads.
- Deploy the companion VAP (`deny-impersonate-grants`) which blocks attempts to re-add the `impersonate` verb via UPDATE operations on ClusterRoles. The VAP prevents re-addition after the guard removes the verb, but does not help during the initial startup window when the verb is already present in the component ClusterRole.
- Monitor for the `impersonate` verb via the RBAC audit component and alert if detected.

During Kubernetes version upgrades, the API server's built-in role reconciliation may reset the component ClusterRole. The guard's continuous reconciliation detects and corrects this, but there is a brief window. The companion VAP prevents external actors from re-adding the verb during this window, but the API server's own bootstrap reconciliation is not subject to admission policies.

---

## Future: KEP-5284 Constrained Impersonation

[KEP-5284](https://github.com/kubernetes/enhancements/issues/5284) (Constrained Impersonation) restricts impersonation so that "an impersonating user cannot perform actions they themselves are not allowed to do." When this KEP reaches GA, the impersonation guard becomes less critical but remains valuable as a belt-and-suspenders measure. Target timeline should be verified against the current KEP status.
