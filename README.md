<h1 align="center">Operator RBAC Toolkit</h1>

<p align="center">
  Least-privilege RBAC for Kubernetes operators through trust domain separation.<br>
  Operators consume permissions. Admins manage them. No <code>escalate</code>.
</p>

<p align="center">
  <a href="http://ort-docs-operator-rbac-toolkit-docs.apps.secaudit.aws.rh-ods.com/">Documentation</a> |
  <a href="docs/TECHNICAL_DESIGN.md">Technical Design</a> |
  <a href="docs/INTEGRATION_GUIDE.md">Integration Guide</a>
</p>

## Why

Operators routinely ship with overly broad ClusterRoles. A real-world audit of the RHOAI Dashboard found only 2 of 30 rules correctly scoped, 9 entirely unused, 14 over-permissioned. When an operator SA is compromised, ClusterRoleBindings let the attacker read secrets in every namespace.

The previous approach (operators manage their own RBAC at runtime) requires the `escalate` verb, which collapses the trust boundary between the entity being constrained and the entity doing the constraining. The CNCF, Red Hat, NSA/CISA, and Kubernetes upstream all warn against self-modifying RBAC.

## Three Independent Components

| Component | Who uses it | What it does | Needs RBAC write verbs? |
|-----------|-------------|-------------|------------------------|
| **Graceful Degradation** | Operator author | Handles `Forbidden` errors with status conditions, events, and backoff | No |
| **RBAC Scoping Controller** | Cluster admin | Watches CRs, creates namespace-scoped RoleBindings, garbage collects | Yes, `bind` only (no `escalate`) |
| **Defense-in-Depth** | Cluster admin | RBAC audit, SA protection webhook, impersonation guard, 12 VAP templates | Varies |

Each deploys independently. They're complementary, not coupled.

## Quick Start

Add graceful degradation to an existing operator (zero additional deployments):

```go
import "github.com/opendatahub-io/operator-rbac-toolkit/pkg/graceful"

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
        return result, nil // Permission denied, status set, will retry
    }

    // Permission granted, proceed with secrets.Items
    return ctrl.Result{}, nil
}
```

## Key Design Decisions

**Bind mode only.** Static ClusterRoles deployed via manifests. RoleBindings created dynamically. No `escalate` verb. K8s RBAC escalation prevention ensures the creating SA must hold all permissions in any ClusterRole it binds.

**Trust domain separation.** Operator SA has zero RBAC write verbs. Scoping controller SA manages RoleBindings. Compromise of operator SA cannot escalate into the admin trust domain.

**Namespace-scoped by default.** RoleBindings are created only in namespaces where CRs exist. Cross-namespace cleanup via annotation-based ownership with configurable TTL.

**Defense-in-depth with VAPs.** 12 ValidatingAdmissionPolicy templates (K8s 1.30+) protect managed RoleBindings, static ClusterRoles, namespace labels, and SA identity.

## Packages

| Package | Description |
|---------|-------------|
| `pkg/graceful` | Permission-aware error handling, status conditions, permission discovery via SSAR |
| `pkg/scoper` | RoleBinding lifecycle controller with drift detection, deny-list, namespace selectors |
| `pkg/audit` | RBAC scanner (impersonation, token exposure, unused permissions, aggregation rules) |
| `pkg/saprotection` | Webhook preventing unauthorized use of operator SA identity |
| `pkg/impersonation` | Reconciler closing the `system:aggregate-to-edit` impersonation bypass |
| `cmd/scoper` | Standalone binary for deploying the scoping controller as a separate Deployment |
| `config/vap` | 12 ValidatingAdmissionPolicy templates |

## VAP Templates

| Template | Purpose |
|----------|---------|
| `deny-impersonate-grants` | Block impersonation grants in any Role/ClusterRole |
| `restrict-scoped-rolebinding-creation` | Only scoper SA can create managed RoleBindings |
| `restrict-scoped-rolebinding-mutation` | Only scoper SA can update/delete managed RoleBindings |
| `restrict-scoped-rolebinding-subjects` | Managed RoleBindings can only reference the target SA |
| `deny-rolebinding-in-protected-namespaces` | Block RoleBinding creation in system namespaces |
| `allow-rolebinding-in-labeled-namespaces` | Only admin-labeled namespaces receive managed RoleBindings |
| `protect-rbac-allowed-label` | Prevent namespace label manipulation |
| `protect-vap-enforcement-labels` | Prevent VAP binding label manipulation |
| `protect-static-clusterrole` | Prevent static ClusterRole modification |
| `deny-aggregated-static-clusterrole` | Block aggregationRule on static ClusterRoles |
| `protect-scoper-config` | Restrict scoper ConfigMap access |
| `restrict-ephemeral-containers-on-protected-pods` | Restrict debug containers on protected pods |

## Compatibility

| Component | Min K8s | Notes |
|-----------|---------|-------|
| Core (graceful, scoper, audit, SA protection, impersonation) | 1.25+ | Standard RBAC + controller-runtime |
| VAP templates | **1.30+** | ValidatingAdmissionPolicy GA |

OpenShift: VAPs available from 4.17+ (K8s 1.30). Core components work on 4.14+.

## Performance

At steady state (no permission changes, no new CRs), both the graceful library and the scoping controller add **zero additional API calls**. Cost is incurred only on state transitions.

| Component | Steady state | Per-event cost |
|-----------|-------------|----------------|
| Graceful degradation | 0 API calls | 1 SSAR + 1 status patch + 1 event |
| Scoping controller | 0 API calls | 1 RoleBinding create per new namespace |
| SA protection webhook | N/A | ~2ms added to pod admission |

## License

Apache 2.0
