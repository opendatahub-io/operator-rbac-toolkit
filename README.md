# Operator RBAC Toolkit

A Go library and controller for Kubernetes operators that enforces least-privilege RBAC through trust domain separation: operators consume permissions, admins manage them.

## The Problem

Kubernetes operators routinely ship with overly broad ClusterRole permissions. Build kits like the Operator SDK generate general RBAC defaults that developers rarely refine. In practice, operators get deployed with cluster-wide access to secrets, configmaps, and other sensitive resources across all namespaces, even when they only need access in the few namespaces where their Custom Resources exist.

This happens for three reasons. First, permissions get added erroneously (developers assume the ServiceAccount needs permissions that are actually accessed via user-token passthrough). Second, permission drift (features get removed or refactored, but the RBAC rules stay). Third, over-granted verbs (rules specify every verb when only `list` is needed). A real-world audit of the RHOAI Dashboard's ClusterRole found that only 2 out of 30 rules were correctly scoped. 9 rules were entirely unused, and 14 were over-permissioned.

The blast radius matters. When an operator's ServiceAccount token is compromised (pod escape, supply chain attack, token exfiltration), ClusterRoleBindings let the attacker read secrets in every namespace, including kube-system. With namespace-scoped RoleBindings, the same token is rejected with `Forbidden` for every namespace except those with active CRs. The previous approach (operator-security-runtime v1) had operators manage their own RBAC at runtime, but that pattern requires the `escalate` verb and collapses the trust boundary between the entity being constrained and the entity doing the constraining. The CNCF, Red Hat, NSA/CISA, and Kubernetes upstream documentation all warn against self-modifying RBAC.

## How It Works

The toolkit is split into three independent components. Each can be deployed on its own. They are complementary, not coupled.

| Component | Owner | What It Does | Requires RBAC Write Verbs? |
|-----------|-------|-------------|---------------------------|
| **Graceful Degradation Library** (`pkg/graceful`) | Operator author | Handles `Forbidden` errors gracefully: sets status conditions, emits events, retries with backoff | No. Zero RBAC write verbs. |
| **RBAC Scoping Controller** (`pkg/scoper`, `cmd/scoper`) | Cluster admin | Watches CRs, creates namespace-scoped RoleBindings, garbage collects on CR deletion | Yes, but only `bind` on specific ClusterRoles (no `escalate`). |
| **Defense-in-Depth Toolkit** (`pkg/audit`, `pkg/saprotection`, `pkg/impersonation`) | Cluster admin | RBAC auditing, SA identity protection webhook, impersonation bypass closure, VAP templates | Varies by component. |

## Architecture

```
Operator Author                          Cluster Admin
     |                                        |
     v                                        v
+------------------------------+   +----------------------------------+
|  Graceful Degradation        |   |  RBAC Scoping Controller         |
|  Library (pkg/graceful)      |   |  (pkg/scoper + cmd/scoper)       |
|                              |   |                                  |
|  - Handle Forbidden errors   |   |  - Watch CRs                    |
|  - Set status conditions     |   |  - Create RoleBindings           |
|  - Discover permissions      |   |  - Garbage collect on CR delete  |
|  - Emit K8s events           |   |  - Standalone binary OR          |
|                              |   |    importable Go package         |
|  Zero RBAC write verbs       |   |                                  |
+------------------------------+   +----------------------------------+
                                   |  Defense-in-Depth Toolkit         |
                                   |                                  |
                                   |  - RBAC Audit (pkg/audit)        |
                                   |  - SA Protection (webhook)       |
                                   |  - Impersonation Guard           |
                                   |  - 12 VAP Templates              |
                                   +----------------------------------+

Trust boundary:
  Operator SA  ------>  RBAC consumer (read-only, no escalate/bind)
  Scoper SA   ------>  RBAC manager  (bind on specific ClusterRoles)
  Compromise of operator SA cannot escalate into admin trust domain.
```

## Packages

### pkg/graceful

Permission-aware error handling for controller-runtime reconcilers. When an operator encounters a `Forbidden` error, the library degrades gracefully instead of crashing: it sets structured status conditions on the CR, emits Kubernetes events, and returns a `RequeueAfter` with exponential backoff.

**Key types:**

```go
// Handler wraps client operations with permission-aware error handling.
h := graceful.NewHandler(recorder,
    graceful.WithRequeueAfter(30 * time.Second),
    graceful.WithMaxRequeue(5 * time.Minute),
    graceful.WithBackoffFactor(2.0),
)

// Do wraps a single operation. On Forbidden, it sets status conditions and
// returns RequeueAfter. On success, it restores the PermissionGranted condition.
result, err := h.Do(ctx, client, cr, func() error {
    return client.List(ctx, secrets, client.InNamespace(cr.Namespace))
})
```

**Permission discovery** via SelfSubjectAccessReview (rate-limited, concurrent):

```go
report, err := graceful.DiscoverPermissions(ctx, client, graceful.PermissionSpec{
    Resources: []graceful.ResourceSpec{
        {Group: "", Resource: "secrets", Verbs: []string{"get", "list"}},
    },
    Namespaces: []string{"notebooks", "model-registry"},
    MaxConcurrency: 10,
})
// report.Granted, report.Denied, report.Summary
```

**Convenience helpers:**

```go
// Check a single permission.
allowed, err := graceful.CheckPermission(ctx, c, "", "secrets", "list", "my-ns")

// Discover permissions across namespaces, returns map[namespace]bool.
perms, err := graceful.DiscoverNamespacedPermissions(ctx, c, "", "secrets", "list",
    []string{"ns-a", "ns-b", "ns-c"})

// Apply a PermissionReport to a CR's status conditions.
err = graceful.ApplyReport(ctx, c, cr, report)
```

CRs must implement the `StatusProvider` interface to receive status conditions:

```go
type StatusProvider interface {
    GetConditions() []metav1.Condition
    SetConditions([]metav1.Condition)
}
```

RBAC requirement: zero write verbs. Only `create` on `selfsubjectaccessreviews` (already granted to all authenticated SAs via `system:basic-user`).

---

### pkg/scoper

Admin-side controller that dynamically manages namespace-scoped RoleBindings. When a CR appears in a namespace, the controller creates a RoleBinding granting the operator's SA access via a pre-deployed static ClusterRole. When the CR is deleted, Kubernetes OwnerReference GC (same-namespace) or annotation-based cleanup (cross-namespace) removes the RoleBinding.

**Configuration:**

```go
err := scoper.Setup(mgr, scoper.Config{
    Targets: []scoper.ScopingTarget{
        {
            WatchGVK:              schema.GroupVersionKind{Group: "example.io", Version: "v1", Kind: "Widget"},
            TargetSA:              types.NamespacedName{Name: "my-operator", Namespace: "operator-ns"},
            ClusterRoleName:       "my-operator-scoped",
            ManagedRoleBindingName: "my-operator-scoped-binding",
            NamespaceSelector:     &metav1.LabelSelector{MatchLabels: map[string]string{"managed": "true"}},
        },
    },
    ControllerNamespace: "scoper-system",
    DenyList: scoper.DefaultDenyList("scoper-system"),
    CleanupInterval: metav1.Duration{Duration: 5 * time.Minute},
})
```

**Key behaviors:**

- Uses **bind mode only**. No `escalate` verb. The static ClusterRole defines the permission ceiling.
- Validates that the static ClusterRole does **not** use `aggregationRule` (prevents rule injection).
- Same-namespace CRs use Kubernetes OwnerReferences for GC. Cross-namespace CRs use annotation-based ownership (`operator-rbac-toolkit.io/scoped-access-owners`).
- Cross-namespace target namespaces are validated against a deny-list (kube-system, kube-public, kube-node-lease, default, openshift-* prefixes) and optional NamespaceSelector.
- Drift recovery: detects and corrects modified RoleBindings (immutable RoleRef changes trigger delete/recreate).
- Namespace label watch: when a namespace no longer matches the NamespaceSelector, its RoleBinding is revoked.

---

### pkg/audit

Scans the cluster for RBAC exposure risks and produces structured findings.

```go
findings, err := audit.Scan(ctx, client, audit.Config{
    ServiceAccount: types.NamespacedName{Name: "my-operator", Namespace: "my-ns"},
    ExpectedRules:  expectedPolicyRules,
})

for _, f := range findings {
    log.Info("RBAC finding", "severity", f.Severity, "category", f.Category, "message", f.Message)
}
```

**Scan categories:**

| Category | Severity | Detects |
|----------|----------|---------|
| `impersonation-grants` | Critical | Any Role/ClusterRole granting `impersonate` on ServiceAccounts |
| `tokenrequest-exposure` | Critical | Any Role/ClusterRole granting `create` on `serviceaccounts/token` |
| `aggregate-to-edit-impersonate` | Warning | Whether `system:aggregate-to-edit` still includes the `impersonate` verb |
| `unused-permissions` | Info | Permissions in the SA's ClusterRole not matching any expected rule |
| `aggregation-rules` | Warning | Whether the SA's ClusterRole uses `aggregationRule` |

---

### pkg/saprotection

ValidatingWebhook that prevents unauthorized use of an operator's ServiceAccount identity. Intercepts Pod CREATE and UPDATE requests to ensure only allowed identities can create pods mounting a protected SA's token.

```go
webhook := saprotection.NewWebhook(saprotection.WebhookConfig{
    ProtectedServiceAccounts: []string{"my-operator"},
    AllowedIdentities: []string{
        "system:serviceaccount:operator-ns:my-operator",
        "system:serviceaccount:kube-system:replicaset-controller",
    },
}, scheme)
```

Uses name-only SA matching (scoped to the operator's namespace via webhook namespaceSelector). Update operations that don't change the ServiceAccount field are short-circuited. `failurePolicy: Fail` for fail-secure behavior.

---

### pkg/impersonation

Reconciler that closes the impersonation bypass in Kubernetes RBAC. The default `system:aggregate-to-edit` ClusterRole includes the `impersonate` verb for ServiceAccounts, allowing any namespace editor to impersonate any SA in their namespace.

```go
guard := impersonation.NewGuard(client, logger, impersonation.DefaultGuardConfig())
err := guard.SetupWithManager(mgr)
```

The guard identifies the component ClusterRole that contributes the `impersonate` verb (labeled `rbac.authorization.kubernetes.io/aggregate-to-edit: "true"`), removes the verb, and sets `rbac.authorization.kubernetes.io/autoupdate: "false"` to prevent the bootstrap reconciliation controller from resetting it. Continuously watches for drift and re-applies the fix after Kubernetes upgrades.

## Quick Start

The most common integration path: add graceful degradation to an existing operator.

```go
import (
    "github.com/ugiordan/operator-rbac-toolkit/pkg/graceful"
)

// 1. Your CR must implement StatusProvider.
func (s *MyStatus) GetConditions() []metav1.Condition  { return s.Conditions }
func (s *MyStatus) SetConditions(c []metav1.Condition) { s.Conditions = c }

// 2. Create a Handler in your reconciler setup.
type MyReconciler struct {
    client.Client
    Scheme   *runtime.Scheme
    graceful *graceful.Handler
}

func (r *MyReconciler) SetupWithManager(mgr ctrl.Manager) error {
    r.graceful = graceful.NewHandler(mgr.GetEventRecorderFor("my-operator"))
    return ctrl.NewControllerManagedBy(mgr).
        For(&v1alpha1.MyCR{}).
        Complete(r)
}

// 3. Wrap operations that may be subject to admin-scoped RBAC.
func (r *MyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
    cr := &v1alpha1.MyCR{}
    if err := r.Get(ctx, req.NamespacedName, cr); err != nil {
        return ctrl.Result{}, client.IgnoreNotFound(err)
    }

    secrets := &corev1.SecretList{}
    result, err := r.graceful.Do(ctx, r.Client, cr, func() error {
        return r.List(ctx, secrets, client.InNamespace(cr.Namespace))
    })
    if err != nil {
        return result, err
    }
    if result.RequeueAfter > 0 {
        // Permission denied, status conditions are set, will retry.
        return result, nil
    }

    // Permission granted, proceed with secrets.Items.
    return ctrl.Result{}, nil
}
```

No webhooks, no CRDs, no additional deployments. Just `go get github.com/ugiordan/operator-rbac-toolkit` and wire it in.

## VAP Templates

ValidatingAdmissionPolicy templates for defense-in-depth. Deploy via Kustomize, Helm, or GitOps from `config/vap/`. Requires Kubernetes 1.30+ (VAP GA).

| Template | Purpose |
|----------|---------|
| `deny-impersonate-grants` | Block impersonation privilege grants in any Role/ClusterRole |
| `restrict-scoped-rolebinding-creation` | Only the scoping controller's SA can create managed RoleBindings |
| `restrict-scoped-rolebinding-mutation` | Only the scoping controller's SA can update or delete managed RoleBindings |
| `restrict-scoped-rolebinding-subjects` | Managed RoleBindings can only reference the target operator's SA |
| `deny-rolebinding-in-protected-namespaces` | Block RoleBinding creation in system namespaces (kube-system, etc.) |
| `allow-rolebinding-in-labeled-namespaces` | Only admin-labeled namespaces can receive managed RoleBindings |
| `protect-rbac-allowed-label` | Prevent non-admin namespace label manipulation |
| `protect-vap-enforcement-labels` | Prevent manipulation of labels used by VAP binding namespaceSelectors |
| `protect-static-clusterrole` | Prevent modification of the static ClusterRole |
| `deny-aggregated-static-clusterrole` | Block addition of `aggregationRule` to the static ClusterRole |
| `protect-scoper-config` | Restrict write access to the scoping controller's ConfigMap |
| `restrict-ephemeral-containers-on-protected-pods` | Restrict who can create ephemeral containers on pods using protected SAs |

## Standalone Scoper Binary

The `cmd/scoper` directory contains a standalone binary for cluster admins who want to deploy the scoping controller as a separate Deployment rather than embedding `pkg/scoper` in an existing operator. It reads configuration from a YAML file (typically mounted from a ConfigMap), starts the controller with leader election, and manages RoleBindings independently from the operators it scopes.

Recommended deployment: 2 replicas with leader election enabled. The standalone binary runs with its own ServiceAccount, providing full trust domain separation from the operators it manages.

## Performance

At steady state (no permission changes, no new CRs), both the graceful degradation library and the scoping controller add zero additional API calls. Cost is incurred only on state transitions.

| Component | Steady-State Cost | Per-Event Cost |
|-----------|-------------------|---------------|
| Graceful degradation | 0 API calls | 1 SSAR + 1 status patch + 1 event per Forbidden |
| Scoping controller | 0 API calls (DeepEqual skip) | 1 RoleBinding create per new namespace |
| SA protection webhook | N/A (admission path) | ~2ms added to pod admission |
| Impersonation guard | 0 API calls (watch-based) | 1 ClusterRole update on drift detection |

Cross-namespace cleanup runs on a configurable interval (default: 5 minutes). SSAR calls during permission discovery are rate-limited (default: 10 concurrent).

For full details, see [TECHNICAL_DESIGN.md, section 10](docs/TECHNICAL_DESIGN.md#10-performance-characteristics).

## Kubernetes Version Compatibility

| Component | Minimum K8s Version | Notes |
|-----------|--------------------|----|
| Graceful Degradation Library | 1.25+ | SelfSubjectAccessReview (stable since 1.0) |
| RBAC Scoping Controller | 1.25+ | Standard RBAC resources and controller-runtime |
| SA Protection Webhook | 1.25+ | ValidatingWebhookConfiguration (stable since 1.16) |
| Impersonation Guard | 1.25+ | Standard ClusterRole resources |
| RBAC Audit | 1.25+ | Standard RBAC resources |
| VAP Templates | **1.30+** | ValidatingAdmissionPolicy GA in 1.30 |

**OpenShift version mapping:**

| OpenShift | Kubernetes | VAP Support |
|-----------|-----------|-------------|
| 4.14 | 1.27 | No |
| 4.15 | 1.28 | No |
| 4.16 | 1.29 | No |
| 4.17 | 1.30 | Yes (GA) |
| 4.18+ | 1.31+ | Yes |

On clusters without VAP support, deploy the core components (scoping controller, graceful degradation library, SA protection webhook, impersonation guard) without the VAP templates. The VAPs provide defense-in-depth but are not required for core functionality.

## Migration from operator-security-runtime v1

| v1 Package | v2 Component | Change |
|------------|-------------|--------|
| `pkg/rbacscope` (operator-embedded) | `pkg/scoper` (external controller) | RBAC management moves from operator to scoping controller |
| `pkg/rbacscope` (bind mode) | `pkg/scoper` (bind-only) | Direct port. Scoping controller uses bind mode exclusively. |
| `pkg/saprotection` | `pkg/saprotection` | No change |
| `pkg/impersonationguard` | `pkg/impersonation` | Package rename only |
| `pkg/rbacaudit` | `pkg/audit` | Package rename only |
| N/A | `pkg/graceful` | New component. Add to operator reconciler. |

The core architectural change: operators stop managing their own RBAC (no more `escalate`/`bind` verbs on the operator SA). The scoping controller or cluster admin handles RBAC. The operator just handles missing permissions gracefully.

For step-by-step migration instructions and rollback safety, see [TECHNICAL_DESIGN.md, section 12](docs/TECHNICAL_DESIGN.md#12-migration-from-operator-security-runtime-v1).

## Documentation

- **[Technical Design](docs/TECHNICAL_DESIGN.md)**: Full architecture, threat model, design decisions, known limitations.
- **[Integration Guide](docs/INTEGRATION_GUIDE.md)**: Step-by-step integration for operator authors and cluster admins.

## License

Apache 2.0
