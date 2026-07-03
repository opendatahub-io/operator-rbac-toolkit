# Migration from operator-security-runtime v1

The core architectural change: RBAC management moves from the operator itself (which required `escalate`/`bind` verbs and violated trust domain separation) to an external scoping controller. The operator becomes a pure RBAC consumer, and the admin controls the permission ceiling via a static ClusterRole.

## Component Mapping

| v1 Package | v2 Package | Change |
|------------|------------|--------|
| `pkg/rbacscope` (operator-embedded) | `pkg/scoper` (external controller) | RBAC management moves from operator to scoping controller |
| `pkg/rbacscope` (bind mode) | `pkg/scoper` (bind-only) | Direct port |
| `pkg/saprotection` | `pkg/saprotection` | No change |
| `pkg/impersonationguard` | `pkg/impersonation` | Package renamed |
| `pkg/rbacaudit` | `pkg/audit` | Package renamed |
| N/A | `pkg/graceful` | New. Add to your operator |

## Step-by-Step Migration

Each step is independently reversible. You can pause the migration at any point and roll back without data loss.

### Step 1: Add graceful degradation library

This is additive. No behavior change when permissions are available.

```go
// In your reconciler, wrap RBAC-sensitive operations:
result, err := r.graceful.Do(ctx, r.Client, cr, func() error {
    return r.List(ctx, secrets, client.InNamespace(ns))
})
```

**Rollback:** remove the `Do()` calls and revert to direct client operations.

### Step 2: Deploy the static ClusterRole

Create the static ClusterRole with the scoped permissions your operator needs. Use the same rules that were previously in the operator's self-managed Roles.

```bash
kubectl apply -f static-clusterrole.yaml
```

**Rollback:** `kubectl delete clusterrole my-operator-scoped`

### Step 3: Deploy the scoping controller

Configure it with your operator's SA and CR GVK. The scoping controller creates RoleBindings that coexist with any existing ClusterRoleBinding.

**Rollback:** uninstall the scoping controller. Managed RoleBindings with OwnerReferences will be garbage collected when CRs are deleted. Cross-namespace RoleBindings persist but are harmless while the ClusterRoleBinding still exists.

### Step 4: Verify scoped access works

Before removing the legacy ClusterRoleBinding, verify the scoping controller has created RoleBindings in the expected namespaces:

```bash
kubectl get rolebindings -A | grep my-operator-scoped-binding
```

Test with a minted token:

```bash
TOKEN=$(kubectl create token my-operator -n my-operator-system)
# Should succeed in CR-bearing namespaces:
kubectl get secrets -n notebooks --token="$TOKEN"
# Should fail in non-CR namespaces (once ClusterRoleBinding is removed):
kubectl get secrets -n kube-system --token="$TOKEN"
```

**Rollback:** no destructive changes in this step. Verification only.

### Step 5: Remove RBAC management code from the operator

Remove the v1 `pkg/rbacscope` integration from your operator's reconciler. Remove `escalate` and `bind` verb requirements from the operator's RBAC markers/manifests.

**Rollback:** re-add the v1 integration code.

### Step 6: Remove the legacy ClusterRoleBinding

This is the point of no return for the RBAC scoping. After this, the operator only has access in namespaces where the scoping controller has created RoleBindings.

```bash
kubectl delete clusterrolebinding my-operator-binding
```

**Rollback:** recreate the ClusterRoleBinding. All existing tokens immediately regain cluster-wide access (no token rotation needed, Kubernetes evaluates RBAC on every request).

### Step 7: Deploy VAP templates

Apply the protection policies for defense in depth (see the [VAP Templates](../architecture/vap-templates.md) section).

```bash
kubectl apply -f config/vap/
```

**Rollback:** `kubectl delete validatingadmissionpolicy <name>`
