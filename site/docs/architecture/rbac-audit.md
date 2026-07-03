# RBAC Audit

## Purpose

The RBAC audit package (`pkg/audit`) scans the cluster at startup to identify RBAC exposure risks. It produces structured findings that operators can surface via logs, events, or status conditions.

---

## Scan Categories

| Category | Severity | What It Detects |
|----------|----------|-----------------|
| Impersonation grants | Critical | Any Role/ClusterRole granting `impersonate` on ServiceAccounts |
| TokenRequest exposure | Critical | Any Role/ClusterRole granting `create` on `serviceaccounts/token` |
| Aggregate-to-edit status | Warning | Whether `system:aggregate-to-edit` still includes the `impersonate` verb |
| Unused permissions | Info | Permissions in the SA's ClusterRole that do not match any API call pattern |
| Aggregation rules | Warning | Whether the static ClusterRole uses `aggregationRule` (which enables permission injection) |

---

## Integration

```go
findings, err := audit.Scan(ctx, client, audit.Config{
    ServiceAccount:  types.NamespacedName{Name: "my-operator", Namespace: "my-namespace"},
    ExpectedRules:   expectedPolicyRules,
})

for _, f := range findings {
    log.Info("RBAC audit finding",
        "severity", f.Severity,
        "category", f.Category,
        "message", f.Message,
    )
}
```

Each finding includes a severity level, category, and human-readable message. The caller decides how to surface these findings: logging, Kubernetes events, status conditions, or external alerting.
