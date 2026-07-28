# v1 vs v2

This page summarizes the differences between the operator-security-runtime (v1) and the operator-rbac-toolkit (v2).

## Trust Model

The core architectural shift: in v1 the operator was both consumer and producer of RBAC. In v2, the operator only consumes permissions. Someone else (the scoping controller or the cluster admin) produces them.

| Version | Who manages RBAC | Verbs on operator SA | Compromise blast radius |
|---------|-----------------|---------------------|------------------------|
| v1 escalate mode | Operator itself | `escalate`, `create` roles | Can grant itself any permission |
| v1 bind mode | Operator itself | `bind` on specific ClusterRole | Can create RoleBindings for one ClusterRole in any namespace |
| v2 embedded | Operator itself | `bind` on specific ClusterRole | Same as v1 bind mode, but with drift detection, cleanup, and VAP protection |
| v2 standalone | Scoping controller | None | Can't touch RBAC at all |

!!! note "v2 embedded vs standalone"
    v2 can be imported as a Go library (embedded in the operator process) or deployed as a standalone binary with its own ServiceAccount. The trust domain separation only applies in standalone mode. When embedded, the operator SA still holds `bind`, same as v1 bind mode, but gains all the v2 features (drift detection, cleanup, VAPs, metrics).

## Feature Comparison

| Feature | v1 | v2 |
|---------|:--:|:--:|
| **RBAC Scoping** | | |
| Bind mode (RoleBindings referencing static ClusterRole) | :material-check: | :material-check: |
| Escalate mode (create Roles at runtime) | :material-check: | :material-close: Removed |
| Standalone deployment with separate SA | :material-close: | :material-check: |
| Embeddable Go library | :material-check: | :material-check: |
| Cross-namespace ownership (annotation-based) | :material-close: | :material-check: |
| Cross-namespace cleanup with TTL | :material-close: | :material-check: |
| Drift detection and correction (RoleRef, Subjects) | :material-close: | :material-check: |
| Deny-list (kube-system, openshift-*) | :material-close: | :material-check: |
| NamespaceSelector filtering | :material-close: | :material-check: |
| Webhook pre-provisioning (MutatingAdmissionWebhook) | :material-close: | :material-check: |
| Namespace-label trigger (pre-provisioning) | :material-close: | :material-check: |
| ClusterRole validation (aggregationRule blocked) | :material-close: | :material-check: |
| **Graceful Degradation** | | |
| Permission-aware error handling | :material-close: | :material-check: |
| ProvisioningPending vs PermissionDenied distinction | :material-close: | :material-check: |
| Exponential backoff with configurable ceiling | :material-close: | :material-check: |
| Permission discovery via SSAR | :material-close: | :material-check: |
| Status condition management | :material-close: | :material-check: |
| **Observability** | | |
| Prometheus metrics (scoper, webhook, graceful) | :material-close: | :material-check: |
| Health check endpoint (JSON) | :material-close: | :material-check: |
| Kubernetes events on RBAC changes | :material-close: | :material-check: |
| **Defense-in-Depth** | | |
| RBAC audit scanner | :material-check: | :material-check: |
| SA identity protection webhook | :material-check: | :material-check: |
| Impersonation guard | :material-check: | :material-check: |
| ValidatingAdmissionPolicy templates | :material-close: | :material-check: 12 templates |
| **Developer Experience** | | |
| Kubebuilder v4 external plugin | :material-check: | :material-check: |
| MkDocs documentation site | :material-close: | :material-check: |
| Integration guide | :material-close: | :material-check: |

## Why escalate was removed

v1 offered an escalate mode where the operator could create Roles at runtime with arbitrary rules. This required the `escalate` verb on the operator SA, which allows a compromised SA to grant itself any permission in the cluster. The CNCF, NSA/CISA, and Kubernetes upstream documentation all warn against this pattern.

v2 uses bind mode exclusively. Static ClusterRoles are deployed via manifests (Helm, Kustomize, OLM). The scoping controller creates RoleBindings referencing those static ClusterRoles. Kubernetes RBAC escalation prevention ensures the creating principal must already hold all permissions in any ClusterRole it binds.

## Migration

See the [Migration Guide](../integration/migration.md) for step-by-step instructions on upgrading from v1 to v2.
