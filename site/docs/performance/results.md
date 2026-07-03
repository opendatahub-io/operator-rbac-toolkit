# Performance and Observability

This page covers the performance characteristics of each toolkit component and the observability instrumentation available for monitoring, alerting, and auditing.

---

## Performance Characteristics

### Graceful Degradation Library

The library adds negligible overhead to reconciliation. At steady state (permissions unchanged), it adds zero API calls. Cost is incurred only on permission state transitions.

| Operation | Cost | When |
|-----------|------|------|
| `SelfSubjectAccessReview` | 1 API call per check (rate-limited, default 10 concurrent) | Startup discovery, after Forbidden errors |
| Status condition update | 1 API call (patch) | When permission state changes |
| Event emission | 1 API call | When permission state changes |
| Forbidden handling | 0 additional API calls | Intercepts existing error, no new calls |

### RBAC Scoping Controller

| Operation | Cost | When |
|-----------|------|------|
| RoleBinding creation | 1 API call | First CR in a new namespace |
| OwnerReference patch | 1 API call | Additional CR in existing namespace |
| Steady-state reconcile | 0 API calls | DeepEqual skip when no changes |
| Orphan scan | 1 list + N get calls | Startup + periodic interval (default: 5 minutes) |

### v1 Baseline Numbers

The RoleBinding management logic is ported from operator-security-runtime v1 (bind mode path). The v1 bind mode was validated via 4-phase A/B testing on two OCP clusters (320 total trials). Those results provide a baseline, but v2's architecture differs (external controller vs. embedded library), so the numbers should be re-validated.

| Metric | Value |
|--------|-------|
| p95 reconcile latency | +13-18% (~123ms absolute, one-time per namespace) |
| Steady-state cost | 0 additional API calls |
| First-time provisioning | 2 API calls per namespace (1 RoleBinding create + 1 OwnerReference patch) |

V2 adds namespace label watching (when `NamespaceSelector` is configured), cross-namespace cleanup scans, and CRD availability retries, which may increase API call volume compared to v1. Performance validation for v2 is planned before GA release.

### Defense-in-Depth Components

| Component | Overhead |
|-----------|----------|
| SA protection webhook | ~2ms added to pod admission decisions |
| Impersonation guard reconciler | Runs once at startup, then watches for drift (negligible steady-state cost) |

---

## Observability

### Scoping Controller Metrics

The scoping controller exports the following Prometheus metrics.

| Metric | Type | Description |
|--------|------|-------------|
| `rbac_scoper_rolebinding_created_total` | Counter | Total RoleBindings created, labeled by target SA and namespace |
| `rbac_scoper_rolebinding_deleted_total` | Counter | Total RoleBindings deleted (GC), labeled by target SA and namespace |
| `rbac_scoper_reconcile_duration_seconds` | Histogram | Reconciliation latency |
| `rbac_scoper_reconcile_errors_total` | Counter | Reconciliation errors, labeled by error type |
| `rbac_scoper_orphan_rolebindings` | Gauge | Current count of orphan RoleBindings pending cleanup |
| `rbac_scoper_clusterrole_missing` | Gauge | Whether a configured static ClusterRole is missing (0 = present, 1 = missing) |

### Graceful Degradation Library Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `graceful_permission_denied_total` | Counter | Total Forbidden errors handled, labeled by resource and verb |
| `graceful_permission_restored_total` | Counter | Total permission restorations detected |
| `graceful_ssar_duration_seconds` | Histogram | SelfSubjectAccessReview call latency |
| `graceful_ssar_calls_total` | Counter | Total SSAR calls |

### Recommended Alerts

| Alert | Condition | Severity |
|-------|-----------|----------|
| `RBACScoperReconcileErrors` | `rbac_scoper_reconcile_errors_total` increasing for 10m | Warning |
| `RBACScoperClusterRoleMissing` | `rbac_scoper_clusterrole_missing == 1` for 5m | Critical |
| `RBACScoperOrphanAccumulation` | `rbac_scoper_orphan_rolebindings > 10` for 15m | Warning |
| `OperatorPermissionDenied` | `graceful_permission_denied_total` increasing for 5m | Warning |
| `ImpersonateVerbDetected` | RBAC audit finding with category `aggregate-to-edit-impersonate` | Critical |

### Kubernetes Audit Log Integration

The toolkit's detective controls are complemented by Kubernetes API server audit logging. Recommended audit policy rules:

- **RBAC mutations.** Log `rbac.authorization.k8s.io` resource mutations at `Request` level. This captures who created, modified, or deleted Roles and RoleBindings.
- **Auth reviews.** Log `authentication.k8s.io/tokenreviews` and `authorization.k8s.io/subjectaccessreviews` at `Metadata` level.
- **Pod creation.** Log pod creation in the operator's namespace at `Request` level. This captures SA usage attempts.

The RBAC audit component (`pkg/audit`) reads existing RBAC state but does not interact with the audit log directly. Correlation between audit log events and RBAC audit findings is an operational concern left to the cluster admin's SIEM or log aggregation tooling.

### Structured Logging

All components use structured logging (JSON format) with consistent fields per component.

| Field | Description | Components |
|-------|-------------|------------|
| `component` | Which toolkit component emitted the log | All (scoper, graceful, audit, saprotection, impersonation) |
| `target_sa` | The ServiceAccount being scoped or protected | All |
| `namespace` | The namespace where the action occurred | All |
| `rolebinding` | The managed RoleBinding name | Scoping controller |
| `permission` | The specific permission being checked or denied | Graceful degradation library |
