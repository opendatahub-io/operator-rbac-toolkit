# Multi-Tenant SA Resolution

The scoping controller supports three strategies for resolving which ServiceAccount a RoleBinding grants access to. Choosing the right one depends on whether you know the SA at configuration time (static cluster install) or only at CR creation time (per-tenant, dynamic SAs).

Exactly one of `TargetSA`, `TargetSASource`, or `TargetSAFunc` must be set on each `ScopingTarget`. The library validates this at startup and returns an error if zero or more than one is set.

---

## Option A: Static SA (`TargetSA`)

The simplest case. One SA is known at setup time and applies to every CR instance.

```go
scoper.ScopingTarget{
    WatchGVK:               schema.GroupVersionKind{Group: "apps.example.com", Version: "v1alpha1", Kind: "MyApp"},
    ClusterRoleName:        "my-operator-scoped",
    ManagedRoleBindingName: "my-operator-rb",
    TargetSA:               types.NamespacedName{Name: "my-operator", Namespace: "my-operator-system"},
}
```

Every CR of kind `MyApp` gets a RoleBinding in its namespace (or in `spec.targetNamespace` if `TargetNamespaceSource` is set) binding `my-operator-system/my-operator` to `my-operator-scoped`.

**When to use:** Operators with a single shared SA — the common case. Works with all other features: `NamespaceSelector`, `TargetNamespaceSource`, `WebhookProvisioning`, `NamespaceLabelTrigger`.

**Tradeoff:** One SA is granted access to every namespace where any instance of the CR exists. If the operator SA is compromised, all tenant namespaces are exposed. For strict per-tenant isolation, see Option B or C.

---

## Option B: Field Path (`TargetSASource`)

The SA name (and optionally namespace) is extracted from a field in the reconciled CR at runtime. Use this when each CR instance owns a tenant-specific SA and stores its name in a spec field.

```go
scoper.ScopingTarget{
    WatchGVK:        schema.GroupVersionKind{Group: "apps.example.com", Version: "v1alpha1", Kind: "Tenant"},
    ClusterRoleName: "tenant-operator-scoped",
    // Each Tenant CR gets its own RoleBinding — name it per-CR to avoid collisions.
    ManagedRoleBindingNameFunc: func(cr *unstructured.Unstructured) string {
        return "tenant-rb-" + cr.GetName()
    },
    TargetSASource: &scoper.SASource{
        // Required: path to the SA name in the CR spec.
        NameFieldPath: ".spec.serviceAccountName",
        // Optional: path to the SA namespace. Defaults to the CR's own namespace.
        NamespaceFieldPath: ".spec.serviceAccountNamespace",
    },
}
```

**Field path constraints:** Both `NameFieldPath` and `NamespaceFieldPath` must start with `.spec.` to prevent privilege escalation via user-controlled metadata fields (`.metadata.annotations`, `.metadata.labels`, `.status.*`). The library validates this at startup.

**What happens when the field is missing:** If the SA name field is absent or empty in a CR, `resolveTargetSA` returns an error and the reconcile loop requeues that specific CR. Other CRs reconcile normally.

**When to use:** When the CR schema already has a `serviceAccountName` field or similar — no custom callback needed, just wire up the field paths. Works well for generated SAs where the name follows a predictable pattern stored in spec.

**Tradeoff:** The field paths must point to spec fields that are immutable or rarely change. If a tenant updates `spec.serviceAccountName` mid-lifecycle, the next reconcile will update the RoleBinding's Subjects. This is the correct behavior, but it means the old SA loses access immediately without any grace period.

---

## Option C: Callback Function (`TargetSAFunc`)

A Go function that receives the full CR object and returns the SA. Use this when the resolution logic is too complex for a single field path: combining fields, looking up a secondary resource, or encoding a naming convention.

```go
scoper.ScopingTarget{
    WatchGVK:        schema.GroupVersionKind{Group: "apps.example.com", Version: "v1alpha1", Kind: "AITenant"},
    ClusterRoleName: "tenant-operator-scoped",
    ManagedRoleBindingNameFunc: func(cr *unstructured.Unstructured) string {
        return "tenant-rb-" + cr.GetName()
    },
    TargetSAFunc: func(cr *unstructured.Unstructured) types.NamespacedName {
        // Convention: tenant SA is always "ai-tenant-{cr.Name}" in the tenant's namespace.
        return types.NamespacedName{
            Name:      "ai-tenant-" + cr.GetName(),
            Namespace: "ai-tenant-" + cr.GetName(),
        }
    },
}
```

**When to use:** Complex naming conventions, multi-field composition, or when you want to centralize the resolution logic in one place rather than distributing it across field paths.

**Tradeoff:** The function runs synchronously in the reconcile loop. Keep it pure and fast — no API calls inside `TargetSAFunc`. If you need to look up another resource to determine the SA, use a dedicated reconciler step to cache that information in the CR spec, then use `TargetSASource` to read it.

---

## RoleBinding Name Collisions

When multiple CR instances can target the same namespace (cross-namespace scenarios via `TargetNamespaceSource`), a static `ManagedRoleBindingName` causes the second reconcile to overwrite the first RoleBinding. The last writer wins, and the first tenant's SA loses access.

**Fix:** Use `ManagedRoleBindingNameFunc` to compute a per-CR name.

```go
ManagedRoleBindingNameFunc: func(cr *unstructured.Unstructured) string {
    return "operator-rb-" + cr.GetName()
},
```

The function receives the full CR, so you can use any field — the CR name, a spec field, a label, or a hash of multiple values.

**With Option A (static SA):** Collision is not possible when every CR in a given namespace targets the same SA. A single shared RoleBinding covering all CRs is the correct behavior. Use the static `ManagedRoleBindingName`.

**With Options B or C (dynamic SA):** Collision is likely if different CRs resolve to different SAs in the same namespace. Always pair dynamic SA resolution with `ManagedRoleBindingNameFunc`.

---

## Choosing Between Options

| | Option A | Option B | Option C |
|---|---|---|---|
| SA known at config time | Yes | No | No |
| Per-CR SA isolation | No | Yes | Yes |
| CR schema change needed | No | Maybe (add SA field) | No |
| Custom resolution logic | No | No | Yes |
| Suitable for `WebhookProvisioning` | Yes | No* | No* |
| `ManagedRoleBindingNameFunc` needed | No | Usually | Usually |

*Webhook provisioning happens before the CR exists — the SA cannot be extracted from a non-existent CR.

---

## Integration Example: MaaS-style Tenancy

Models-as-a-Service (and similar platforms) use per-namespace tenancy rather than per-SA tenancy: one shared static SA per component, each tenant gets a dedicated namespace. This maps directly to Option A.

```go
scoper.ScopingTarget{
    WatchGVK:               schema.GroupVersionKind{Group: "maas.example.com", Version: "v1alpha1", Kind: "AITenant"},
    ClusterRoleName:        "payload-processing-scoped",
    ManagedRoleBindingName: "payload-processing-rb",
    // Single shared SA in a fixed namespace — new tenants just get a RoleBinding in their namespace.
    TargetSA: types.NamespacedName{Name: "payload-processing", Namespace: "ingress-system"},
    // Each AITenant CR points to the namespace it owns.
    TargetNamespaceSource: &scoper.NamespaceSource{FieldPath: ".spec.tenantNamespace"},
}
```

Option B would be appropriate if each AITenant provisioned its own SA and stored the SA name in `spec.serviceAccountName`. Option C would apply if the SA name followed a convention derived from multiple CR fields.
