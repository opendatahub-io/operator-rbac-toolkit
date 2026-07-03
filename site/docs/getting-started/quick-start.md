# Quick Start

The most common integration path: add graceful degradation to an existing operator.

This requires zero RBAC write verbs, no webhooks, no CRDs, and no additional deployments. Just `go get` the package and wire it into your reconciler.

## Step 1: Implement the StatusProvider Interface

Your CR's status struct must expose `[]metav1.Condition` via the `StatusProvider` interface. This allows the library to set structured status conditions on your CR when permissions are missing.

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

## Step 2: Create a Handler in Your Reconciler

Create a `graceful.Handler` during reconciler setup. The handler needs a `record.EventRecorder` from the controller manager.

```go
import (
    "github.com/ugiordan/operator-rbac-toolkit/pkg/graceful"
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

## Step 3: Wrap Operations with handler.Do()

Wrap any client operation that might be denied by RBAC with `handler.Do()`. The function signature:

```go
func (h *Handler) Do(
    ctx context.Context,
    c client.Client,
    obj client.Object,   // must also implement StatusProvider for status conditions
    fn func() error,     // the operation to attempt
) (ctrl.Result, error)
```

Return behavior:

- **Success:** returns `(ctrl.Result{}, nil)`. Continue reconciliation normally.
- **Forbidden:** sets `PermissionGranted=False` and `Degraded=True` conditions on the CR, emits a warning event, and returns `(ctrl.Result{RequeueAfter: d}, nil)` with exponential backoff.
- **Other errors:** returns `(ctrl.Result{}, err)` unchanged.

Full reconciler example:

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

## That's It

No webhooks, no CRDs, no additional deployments. Just `go get github.com/ugiordan/operator-rbac-toolkit` and wire it in.

The default backoff sequence is: 30s, 60s, 120s, 240s, 300s (capped at 5 minutes). Customize with functional options:

```go
handler := graceful.NewHandler(recorder,
    graceful.WithRequeueAfter(15 * time.Second),   // initial requeue (default: 30s)
    graceful.WithMaxRequeue(10 * time.Minute),      // backoff cap (default: 5m)
    graceful.WithBackoffFactor(3.0),                // multiplier (default: 2.0, min: 1.0)
)
```

## Next Steps

For the full integration reference, including permission discovery at startup, RBAC audit scanning, SA identity protection, the scoping controller, and VAP templates, see the [Integration Guide](../integration/index.md).
