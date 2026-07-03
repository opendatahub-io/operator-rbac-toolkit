# Operator RBAC Toolkit

**A Go library and controller for Kubernetes operators that enforces least-privilege RBAC through trust domain separation: operators consume permissions, admins manage them.**

## The Problem

Kubernetes operators routinely ship with overly broad ClusterRole permissions. Build kits like the Operator SDK generate general RBAC defaults that developers rarely refine. In practice, operators get deployed with cluster-wide access to secrets, configmaps, and other sensitive resources across all namespaces, even when they only need access in the few namespaces where their Custom Resources exist.

This happens for three reasons:

1. **Permissions added erroneously.** Developers assume the ServiceAccount needs permissions that are actually accessed via user-token passthrough. The permission is granted but never exercised by the SA.
2. **Permission drift.** Features get removed or refactored, but the RBAC rules stay. Nobody audits the gap.
3. **Over-granted verbs.** Rules specify every verb when only `list` is needed. Scaffolding tools generate broad defaults and developers don't refine them.

A real-world audit of the RHOAI Dashboard's ClusterRole found that only 2 out of 30 rules were correctly scoped. 9 rules were entirely unused, and 14 were over-permissioned.

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

## Next Steps

- **[Installation](getting-started/installation.md)**: Install packages and review prerequisites.
- **[Quick Start](getting-started/quick-start.md)**: Step-by-step graceful degradation integration.
- **[Choose Your Deployment Model](getting-started/choose-your-deployment.md)**: Standalone binary vs. embedded library.
- **[Technical Design](design/tradeoffs.md)**: Full architecture, threat model, and design decisions.
- **[Integration Guide](integration/index.md)**: Complete integration reference for operator authors and cluster admins.
