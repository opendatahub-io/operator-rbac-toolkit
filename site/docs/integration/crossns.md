# Cross-Namespace RBAC (`pkg/crossns`)

`pkg/crossns` manages Role+RoleBinding pairs in namespaces outside the operator's own namespace and garbage-collects stale ones when the desired set shrinks.

## The Problem It Solves

Kubernetes owner references are silently ignored when the owner and the owned resource are in different namespaces. If a cluster-scoped CR owns a Role in a foreign namespace, and the CR's target namespace changes, the old Role and RoleBinding are never garbage-collected — they become permanent orphans.

The standard `pkg/scoper` pattern (ClusterRole + RoleBinding) does not help here: `pkg/scoper` binds a pre-existing ClusterRole into a namespace. `pkg/crossns` creates the Role itself in the foreign namespace, which is needed when the operator must grant a specific, narrowly-scoped set of verbs in a namespace it does not own, without granting those verbs cluster-wide.

## Stale-Sweep Pattern

On every reconcile, `Apply`:

1. Computes the desired set of `(namespace, roleName)` pairs from the input `[]RuleSet`.
2. Creates or updates the Role and RoleBinding for each pair.
3. Lists all managed resources cluster-wide (by label).
4. Deletes any resource whose `(namespace, roleName)` is not in the desired set.

This handles namespace field changes in CRs without requiring a full teardown: when the CR moves from `old-ns` to `new-ns`, the next reconcile creates resources in `new-ns` and GCs the ones in `old-ns`.

## Quick Start

```go
import "github.com/opendatahub-io/operator-rbac-toolkit/pkg/crossns"

// Create a reconciler with an owner label that isolates your controller's
// resources from other controllers in the same cluster.
r := crossns.New(client, crossns.OwnerLabel{
    Key:   "myop.io/component",
    Value: "dashboard",
})

// On each reconcile — idempotent, safe to call every cycle.
err := r.Apply(ctx,
    crossns.SubjectRef{Name: "my-sa", Namespace: "my-operator-ns"},
    []crossns.RuleSet{
        {
            RoleName:  "dashboard-notebooks-role",
            Namespace: notebooksNamespace,
            Rules:     notebooksRBACRules(),
        },
        {
            RoleName:  "dashboard-model-registry-role",
            Namespace: modelRegistryNamespace,
            Rules:     modelRegistryRBACRules(),
        },
    },
)

// On CR deletion or ManagementState=Removed — cluster-wide sweep.
err = r.Teardown(ctx)
```

## API Reference

### `RuleSet`

```go
type RuleSet struct {
    RoleName  string                // metadata.name of the Role to create
    Namespace string                // target namespace
    Rules     []rbacv1.PolicyRule  // rules for the Role
}
```

The RoleBinding name is derived as `RoleName + "-binding"`. The `RoleName` must not end in `"-binding"` to avoid naming collisions.

### `SubjectRef`

```go
type SubjectRef struct {
    Name      string  // ServiceAccount name (required)
    Namespace string  // ServiceAccount namespace
}
```

Only `ServiceAccount` subjects are supported.

### `OwnerLabel`

```go
type OwnerLabel struct {
    Key   string
    Value string
}
```

Narrows the label sweep so multiple independent controllers in the same cluster do not interfere with each other's GC or Teardown.

!!! warning "Zero OwnerLabel"
    If `OwnerLabel` is left at its zero value, `Teardown` sweeps **all** resources carrying `operator-rbac-toolkit.io/crossns-managed=true` in the entire cluster, including resources created by other `Reconciler` instances. Always set a distinct `OwnerLabel` when multiple operators share a cluster.

### `Apply`

```go
func (r *Reconciler) Apply(ctx context.Context, subject SubjectRef, ruleSets []RuleSet) error
```

Creates or updates a Role and RoleBinding for each `RuleSet`, then GCs any previously managed resources whose `(namespace, roleName)` pair is not in `ruleSets`.

Returns an error if `SubjectRef.Name`, any `RuleSet.RoleName`, or any `RuleSet.Namespace` is empty.

### `Teardown`

```go
func (r *Reconciler) Teardown(ctx context.Context) error
```

Deletes all managed resources cluster-wide. Call on CR deletion or `ManagementState=Removed`.

## Isolation Between Controllers

Each `Reconciler` instance is scoped to the `(ManagedLabelKey, OwnerLabel)` pair it was created with. Two operators using different `OwnerLabel` values manage independent sets of resources:

```go
// Operator A
rA := crossns.New(client, crossns.OwnerLabel{Key: "myop.io/component", Value: "dashboard"})

// Operator B — its Teardown will not touch operator A's resources
rB := crossns.New(client, crossns.OwnerLabel{Key: "myop.io/component", Value: "pipeline"})
```

## GC Granularity

The desired set is keyed on `(namespace, roleName)`, not just `namespace`. This means partial removal from a shared namespace works correctly:

```go
// Reconcile 1: two roles in shared-ns
r.Apply(ctx, subject, []crossns.RuleSet{
    {RoleName: "role-a", Namespace: "shared-ns", Rules: rulesA()},
    {RoleName: "role-b", Namespace: "shared-ns", Rules: rulesB()},
})

// Reconcile 2: only role-a desired — role-b and its RoleBinding are GC'd
r.Apply(ctx, subject, []crossns.RuleSet{
    {RoleName: "role-a", Namespace: "shared-ns", Rules: rulesA()},
})
```

## RoleRef Drift Recovery

RoleRef is immutable in Kubernetes. If a RoleBinding's `RoleRef` drifts from the desired state (which should not happen in practice but can occur if the RoleBinding was manually modified), `Apply` deletes and recreates the RoleBinding. There is a brief access-outage window between the Delete and the Create.

## Steady-State Cost

At steady state (no rule changes, no namespace changes), `Apply` generates:

- 1 `List` call for Roles (cluster-wide, label-scoped)
- 1 `List` call for RoleBindings (cluster-wide, label-scoped)
- 1 `Get` per Role, 1 `Get` per RoleBinding
- 0 `Update` calls (no-op guard via `reflect.DeepEqual`)
- 0 `Delete` calls (nothing to GC)

## Required Permissions

The operator's ServiceAccount needs the following to use `pkg/crossns`:

```yaml
rules:
  - apiGroups: ["rbac.authorization.k8s.io"]
    resources: ["roles", "rolebindings"]
    verbs: ["get", "list", "create", "update", "delete"]
```

!!! note "Privilege non-escalation"
    Kubernetes enforces privilege non-escalation at the API server level. The operator SA must already hold every verb and resource it specifies in `RuleSet.Rules`. If the SA does not hold those permissions, the Role `Create` will be rejected with `Forbidden`.

## Difference from `pkg/scoper`

| | `pkg/scoper` | `pkg/crossns` |
|---|---|---|
| What it creates | RoleBindings only | Roles **and** RoleBindings |
| ClusterRole required | Yes (pre-existing) | No |
| Use case | Bind a ClusterRole into namespaces where CRs exist | Create scoped Roles in foreign namespaces |
| GC mechanism | Owner annotation + TTL requeue | Stale-sweep (cluster-wide label list) |
| Typical user | Cluster admin running standalone scoper | Operator author embedding crossns |
