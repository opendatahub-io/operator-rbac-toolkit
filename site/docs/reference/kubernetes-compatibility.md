# Kubernetes Version Compatibility

This page documents the minimum Kubernetes version required for each toolkit component and the corresponding OpenShift version mapping.

---

## Component Compatibility

| Component | Minimum K8s Version | Notes |
|-----------|--------------------|----- |
| Graceful Degradation Library | 1.25+ | Uses SelfSubjectAccessReview (stable since 1.0) |
| RBAC Scoping Controller | 1.25+ | Uses standard RBAC resources and controller-runtime |
| SA Protection Webhook | 1.25+ | ValidatingWebhookConfiguration (stable since 1.16) |
| Impersonation Guard | 1.25+ | Modifies standard ClusterRole resources |
| RBAC Audit | 1.25+ | Reads standard RBAC resources |
| VAP Templates | 1.30+ | ValidatingAdmissionPolicy GA in 1.30 |
| KEP-4601 (Authorization with Selectors) | 1.31+ (alpha) | Future direction, not a current dependency |

The core components (graceful degradation library, scoping controller, SA protection webhook, impersonation guard, RBAC audit) all work on Kubernetes 1.25 and later. The VAP templates require Kubernetes 1.30+ where ValidatingAdmissionPolicy reached GA.

---

## OpenShift Version Mapping

| OpenShift | Kubernetes | VAP Support |
|-----------|-----------|-------------|
| 4.14 | 1.27 | No |
| 4.15 | 1.28 | No |
| 4.16 | 1.29 | No |
| 4.17 | 1.30 | Yes (GA) |
| 4.18+ | 1.31+ | Yes |

---

## Clusters Without VAP Support

On clusters running Kubernetes versions below 1.30 (or OpenShift versions below 4.17), ValidatingAdmissionPolicy is not available. In this case, deploy the core components:

- **RBAC Scoping Controller.** Manages namespace-scoped RoleBindings dynamically.
- **Graceful Degradation Library.** Handles missing permissions in operator reconcilers.
- **SA Protection Webhook.** Prevents unauthorized use of operator ServiceAccount identity.
- **Impersonation Guard.** Closes the impersonation bypass in `system:aggregate-to-edit`.
- **RBAC Audit.** Identifies remaining RBAC exposure risks at startup.

The VAP templates provide defense-in-depth enforcement at the API server level but are not required for the core scoping functionality. Once the cluster is upgraded to a version with VAP support, deploy the VAP templates to add API-server-enforced invariants as an additional security layer.
