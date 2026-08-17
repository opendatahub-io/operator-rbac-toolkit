# Adding RBAC Audit

The RBAC audit package (`pkg/audit`) scans the cluster at startup to identify RBAC exposure risks. It produces structured findings that you can surface via logs, events, or status conditions.

## Startup Integration

```go
import (
    "github.com/opendatahub-io/operator-rbac-toolkit/pkg/audit"
    rbacv1 "k8s.io/api/rbac/v1"
    "k8s.io/apimachinery/pkg/types"
)

func runAudit(ctx context.Context, c client.Client) {
    findings, err := audit.Scan(ctx, c, audit.Config{
        ServiceAccount: types.NamespacedName{
            Name:      "my-operator",
            Namespace: "my-operator-system",
        },
        ExpectedRules: []rbacv1.PolicyRule{
            {
                APIGroups: []string{""},
                Resources: []string{"secrets"},
                Verbs:     []string{"get", "list", "create", "update"},
            },
            {
                APIGroups: []string{""},
                Resources: []string{"configmaps"},
                Verbs:     []string{"get", "list"},
            },
            {
                APIGroups: []string{"apps"},
                Resources: []string{"deployments"},
                Verbs:     []string{"get", "list", "update"},
            },
        },
    })
    if err != nil {
        log.Error(err, "RBAC audit completed with errors")
    }

    for _, f := range findings {
        log.Info("RBAC audit finding",
            "severity", string(f.Severity),
            "category", f.Category,
            "message", f.Message,
        )
    }
}
```

## Scan Categories

The `Scan` function runs five independent scanners:

| Scanner | Category | Severity | What It Detects |
|---------|----------|----------|-----------------|
| Impersonation grants | `impersonation-grants` | `Critical` | Any Role/ClusterRole granting `impersonate` on ServiceAccounts (excluding `system:aggregate-to-edit`, which has its own scanner) |
| TokenRequest exposure | `tokenrequest-exposure` | `Critical` | Any Role/ClusterRole granting `create` on `serviceaccounts/token` |
| Aggregate-to-edit | `aggregate-to-edit-impersonate` | `Warning` | Whether `system:aggregate-to-edit` still includes the `impersonate` verb |
| Unused permissions | `unused-permissions` | `Info` | Permissions in ClusterRoles bound to your SA that don't match any `ExpectedRules` entry |
| Aggregation rules | `aggregation-rules` | `Warning` | ClusterRoles bound to your SA that use `aggregationRule` |

## Finding Type

Each finding has the following structure:

```go
type Finding struct {
    Severity Severity     // "Critical", "Warning", or "Info"
    Category string       // scanner category identifier
    Message  string       // human-readable description
    Resource *ResourceRef // optional reference to the RBAC resource
}

type ResourceRef struct {
    Kind      string  // "ClusterRole" or "Role"
    Name      string
    Namespace string  // empty for cluster-scoped resources
}
```

## Custom Expected Rules

The `ExpectedRules` field in `audit.Config` defines the permissions your operator actually needs. The unused-permissions scanner compares rules in ClusterRoles bound to your SA against this list. Any rule that has zero overlap (no shared apiGroup, resource, or verb) with your expected rules is flagged as `Info` severity.

If `ExpectedRules` is empty, the unused-permissions scanner is skipped.
