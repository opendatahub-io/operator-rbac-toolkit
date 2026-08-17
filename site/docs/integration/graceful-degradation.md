# Integrating Graceful Degradation

The graceful degradation library (`pkg/graceful`) gives your operator the ability to handle `Forbidden` errors cleanly instead of crashing. It surfaces structured status conditions, emits Kubernetes events, and retries with exponential backoff.

## RBAC Requirements

The library requires zero RBAC write verbs. It only needs:

- `create` on `selfsubjectaccessreviews`: permission discovery via SSAR. Already granted to all authenticated ServiceAccounts via `system:basic-user`, so no explicit RBAC configuration is needed.
- `create` on `events`: emitting permission-related events.

## 2.1 Implement the StatusProvider Interface

Your CR's status struct must expose `[]metav1.Condition` via the `StatusProvider` interface:

```go
import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// StatusProvider is defined in pkg/graceful/types.go:
//
//   type StatusProvider interface {
//       GetConditions() []metav1.Condition
//       SetConditions([]metav1.Condition)
//   }

type MyCRStatus struct {
    Conditions []metav1.Condition `json:"conditions,omitempty"`
    // ... your other status fields
}

// Implement graceful.StatusProvider on your CR type.
func (m *MyCR) GetConditions() []metav1.Condition {
    return m.Status.Conditions
}

func (m *MyCR) SetConditions(conditions []metav1.Condition) {
    m.Status.Conditions = conditions
}
```

If your CR does not implement `StatusProvider`, the library still handles `Forbidden` errors and emits events. It just skips setting status conditions.

## 2.2 Create a Handler in Your Reconciler

Create a `graceful.Handler` during reconciler setup. The handler needs a `record.EventRecorder` from the controller manager:

```go
import (
    "github.com/opendatahub-io/operator-rbac-toolkit/pkg/graceful"
    ctrl "sigs.k8s.io/controller-runtime"
)

type MyReconciler struct {
    client.Client
    Scheme   *runtime.Scheme
    graceful *graceful.Handler
}

func (r *MyReconciler) SetupWithManager(mgr ctrl.Manager) error {
    recorder := mgr.GetEventRecorderFor("my-operator")

    r.graceful = graceful.NewHandler(recorder)

    return ctrl.NewControllerManagedBy(mgr).
        For(&v1alpha1.MyCR{}).
        Complete(r)
}
```

## 2.3 Wrap Operations with handler.Do()

Wrap any client operation that might be denied by RBAC with `handler.Do()`. The function signature:

```go
func (h *Handler) Do(
    ctx context.Context,
    c client.Client,
    obj client.Object,   // must also implement StatusProvider for status conditions
    fn func() error,     // the operation to attempt
) (ctrl.Result, error)
```

**Return behavior:**

- **Success:** returns `(ctrl.Result{}, nil)`. Continue reconciliation normally.
- **Forbidden:** sets `PermissionGranted=False` and `Degraded=True` conditions on the CR, emits a warning event, and returns `(ctrl.Result{RequeueAfter: d}, nil)` with exponential backoff.
- **Other errors:** returns `(ctrl.Result{}, err)` unchanged.

Example reconciler:

```go
func (r *MyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
    cr := &v1alpha1.MyCR{}
    if err := r.Get(ctx, req.NamespacedName, cr); err != nil {
        return ctrl.Result{}, client.IgnoreNotFound(err)
    }

    // Wrap operations that may fail with Forbidden.
    secrets := &corev1.SecretList{}
    result, err := r.graceful.Do(ctx, r.Client, cr, func() error {
        return r.List(ctx, secrets, client.InNamespace(cr.Namespace))
    })
    if err != nil {
        return result, err        // non-Forbidden error, propagate
    }
    if result.RequeueAfter > 0 {
        return result, nil        // Forbidden, requeue with backoff
    }

    // Permission was granted. Use secrets.Items normally.
    configMaps := &corev1.ConfigMapList{}
    result, err = r.graceful.Do(ctx, r.Client, cr, func() error {
        return r.List(ctx, configMaps, client.InNamespace(cr.Namespace))
    })
    if err != nil {
        return result, err
    }
    if result.RequeueAfter > 0 {
        return result, nil
    }

    // All permissions available, proceed with full reconciliation.
    return ctrl.Result{}, nil
}
```

When a previously-denied permission is restored, the handler automatically sets `PermissionGranted=True` and `Degraded=False`, and emits a `PermissionRestored` event.

## 2.4 Permission Discovery at Startup

Use `DiscoverPermissions` to check which permissions your SA has at startup or on demand. This uses `SelfSubjectAccessReview` calls, rate-limited by `MaxConcurrency`:

```go
import "github.com/opendatahub-io/operator-rbac-toolkit/pkg/graceful"

func (r *MyReconciler) checkPermissionsAtStartup(ctx context.Context) error {
    report, err := graceful.DiscoverPermissions(ctx, r.Client, graceful.PermissionSpec{
        Resources: []graceful.ResourceSpec{
            {Group: "", Resource: "secrets", Verbs: []string{"get", "list", "create"}},
            {Group: "", Resource: "configmaps", Verbs: []string{"get", "list"}},
            {Group: "apps", Resource: "deployments", Verbs: []string{"get", "list", "update"}},
        },
        Namespaces:     []string{"notebooks", "model-registry", "data-science-pipelines"},
        MaxConcurrency: 10,  // default is 10 if zero or negative
    })
    if err != nil {
        return err
    }

    // report.Granted:  []PermissionResult with Allowed=true
    // report.Denied:   []PermissionResult with Allowed=false
    // report.Summary:  "24/24 permissions granted across 3 namespace(s)"

    log.Info("permission discovery complete", "summary", report.Summary)

    for _, denied := range report.Denied {
        log.Info("permission denied",
            "resource", denied.Resource,
            "verb", denied.Verb,
            "namespace", denied.Namespace)
    }

    return nil
}
```

### ApplyReport

Apply the report to a CR's status conditions using `ApplyReport`:

```go
// Sets PermissionGranted and Degraded conditions based on the report.
if err := graceful.ApplyReport(ctx, r.Client, cr, report); err != nil {
    return ctrl.Result{}, err
}
```

### CheckPermission

For checking a single permission:

```go
allowed, err := graceful.CheckPermission(ctx, r.Client,
    "",           // apiGroup (core group)
    "secrets",    // resource
    "list",       // verb
    "notebooks",  // namespace
)
```

### DiscoverNamespacedPermissions

For bulk per-namespace checks on a single resource:

```go
// Returns map[string]bool: namespace -> allowed
nsPerms, err := graceful.DiscoverNamespacedPermissions(ctx, r.Client,
    "",          // apiGroup
    "secrets",   // resource
    "list",      // verb
    []string{"notebooks", "model-registry", "kube-system"},
)
// nsPerms["notebooks"] = true
// nsPerms["kube-system"] = false
```

## 2.5 Configuration Options

Customize backoff behavior with functional options:

```go
handler := graceful.NewHandler(recorder,
    graceful.WithRequeueAfter(15 * time.Second),   // initial requeue (default: 30s)
    graceful.WithMaxRequeue(10 * time.Minute),      // backoff cap (default: 5m)
    graceful.WithBackoffFactor(3.0),                // multiplier (default: 2.0, min: 1.0)
)
```

The backoff sequence with defaults: 30s, 60s, 120s, 240s, 300s (capped at 5m).

## 2.6 Status Conditions Set by the Library

The library manages two condition types on your CR:

| Condition Type | Status | Reason | Meaning |
|----------------|--------|--------|---------|
| `PermissionGranted` | `True` | `AllPermissionsAvailable` | All required permissions are available |
| `PermissionGranted` | `False` | `MissingPermissions` | One or more required permissions are denied |
| `Degraded` | `True` | `InsufficientRBAC` | Operator is running in degraded mode |
| `Degraded` | `False` | `FullyOperational` | All permissions available, fully functional |

These follow OpenShift operator status conventions. You can also use the low-level function directly:

```go
graceful.SetPermissionGranted(cr, false, "Missing permission: list secrets in namespace \"kube-system\"")
graceful.UpdateStatus(ctx, r.Client, cr)
```

**Note:** `UpdateStatus` accepts `client.Object`, so the CR passed to it must implement both `client.Object` (satisfied by embedding into a runtime object registered with the scheme) and `StatusProvider` (for `SetPermissionGranted` to set conditions). In practice, any kubebuilder/operator-sdk generated CR type already satisfies `client.Object`.
