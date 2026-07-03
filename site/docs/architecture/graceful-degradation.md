# Graceful Degradation Library

## Purpose

The graceful degradation library (`pkg/graceful`) provides permission-aware error handling for Kubernetes operators. When an operator encounters a `Forbidden` error due to missing RBAC permissions, the library helps the operator degrade gracefully instead of failing hard.

No reusable library exists for this pattern today. ArgoCD built `resource.respectRBAC` internally. Prometheus Operator has ad-hoc error handling. Every operator reinvents permission error handling. This library fills that gap.

---

## Core Capabilities

### Permission-Aware Error Handling

The library wraps controller-runtime client operations with permission-aware error handling. When a `Forbidden` error is returned:

1. The error is classified (missing verb, missing resource, missing namespace).
2. A structured `PermissionDenied` condition is set on the CR's status.
3. A Kubernetes event is emitted with the specific permission that is missing.
4. The reconciler returns a `RequeueAfter` result to retry when permissions may have changed.

```go
type MyReconciler struct {
    client.Client
    graceful *graceful.Handler
}

func NewMyReconciler(mgr ctrl.Manager) *MyReconciler {
    return &MyReconciler{
        Client:   mgr.GetClient(),
        graceful: graceful.NewHandler(mgr.GetEventRecorderFor("my-operator")),
    }
}

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
        return result, nil
    }

    // Permission was granted, proceed with secrets.Items
}
```

### Permission Discovery

At startup or on demand, the library performs `SelfSubjectAccessReview` checks to discover the operator's actual permissions. SSAR calls are rate-limited (default: 10 concurrent, configurable) to avoid overwhelming the API server during startup in clusters with many namespaces.

```go
report, err := graceful.DiscoverPermissions(ctx, client, graceful.PermissionSpec{
    Resources: []graceful.ResourceSpec{
        {Group: "", Resource: "secrets", Verbs: []string{"get", "list", "create"}},
        {Group: "", Resource: "configmaps", Verbs: []string{"get", "list"}},
    },
    Namespaces: []string{"notebooks", "model-registry"},
    MaxConcurrency: 10,
})

// report.Granted:  [{secrets, get, notebooks}, ...]
// report.Denied:   [{secrets, get, kube-system}, ...]
// report.Summary:  "8/10 permissions granted across 2 namespaces"
```

### Status Condition Management

The library manages structured status conditions on the CR that surface RBAC issues to users and monitoring systems.

| Condition Type | Status | Reason | Meaning |
|----------------|--------|--------|---------|
| `PermissionGranted` | `True` | `AllPermissionsAvailable` | All required permissions are available |
| `PermissionGranted` | `False` | `MissingPermissions` | One or more required permissions are denied |
| `Degraded` | `True` | `InsufficientRBAC` | Operator is running in degraded mode due to missing permissions |
| `Degraded` | `False` | `FullyOperational` | All permissions are available, operator is fully functional |

Status conditions follow the OpenShift conventions for operator status reporting (`Available`, `Progressing`, `Degraded`).

### Event Emission

The library emits Kubernetes events when permission changes are detected:

```
NAMESPACE   LAST SEEN   TYPE      REASON              OBJECT              MESSAGE
notebooks   2m          Warning   PermissionDenied    mycr/my-instance    Missing permission: list secrets in namespace "kube-system"
notebooks   1m          Normal    PermissionRestored  mycr/my-instance    Permission restored: list secrets in namespace "notebooks"
```

---

## RBAC Requirements

The graceful degradation library requires **zero RBAC write verbs**. It needs:

| Permission | Purpose |
|------------|---------|
| `create` on `selfsubjectaccessreviews` | Permission discovery via SSAR. Already granted to all authenticated SAs via `system:basic-user`, so no explicit RBAC configuration is needed. |
| `create` on `events` | Emitting permission-related events |
| `update` on the operator's CR status subresource | Setting status conditions |

The SSAR permission is granted to all authenticated service accounts by default. The events permission is standard. The third is a standard controller-runtime requirement.

---

## Design Decisions

### Why SSAR Instead of SSRR

SelfSubjectAccessReview (SSAR) checks a specific permission (verb + resource + namespace) and returns a yes/no answer. SelfSubjectRulesReview (SSRR) returns all permissions for a namespace but is computationally expensive and can produce incomplete results (the API docs note that the result may be incomplete). SSAR is cheaper, more reliable, and sufficient for the use case.

### Why RequeueAfter Instead of Fail-Fast

When permissions are denied, the operator should retry because the admin may be in the process of updating RBAC. A hard failure forces the admin to manually restart the operator after fixing permissions. RequeueAfter lets the operator self-heal when permissions are restored.

The default backoff schedule for repeated denials on the same permission:

| Attempt | Interval |
|---------|----------|
| 1st | 30 seconds |
| 2nd | 60 seconds |
| 3rd | 120 seconds |
| 4th | 240 seconds |
| 5th+ | 300 seconds (capped) |

This balances recovery speed against API server load during prolonged permission gaps.

### Why Structured Conditions Instead of Log-Only

Logs are not observable by cluster monitoring systems. Status conditions are queryable via the Kubernetes API, can trigger alerts, and are visible in the OpenShift console. This aligns with the operator framework's status condition conventions.

### Why Not Wrap the Client Globally

A global wrapper would intercept every API call, including those that should fail hard (e.g., getting the CR itself). The library provides explicit wrapping for operations that may be subject to admin-scoped RBAC, leaving the operator author in control of which operations degrade gracefully.
