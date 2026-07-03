# Adding the Impersonation Guard

The impersonation guard (`pkg/impersonation`) closes a privilege escalation path in Kubernetes. The default `system:aggregate-to-edit` ClusterRole includes the `impersonate` verb for ServiceAccounts, allowing any namespace editor to impersonate any ServiceAccount in their namespace.

## Register in main.go

```go
import (
    "github.com/ugiordan/operator-rbac-toolkit/pkg/impersonation"
    ctrl "sigs.k8s.io/controller-runtime"
)

func main() {
    mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
        Scheme: scheme,
    })
    if err != nil {
        setupLog.Error(err, "unable to start manager")
        os.Exit(1)
    }

    guard := impersonation.NewGuard(
        mgr.GetClient(),
        ctrl.Log,
        impersonation.DefaultGuardConfig(),  // RequeueAfter: 5 minutes
    )

    if err := guard.SetupWithManager(mgr); err != nil {
        setupLog.Error(err, "unable to setup impersonation guard")
        os.Exit(1)
    }

    // ... start manager ...
}
```

## Custom Configuration

```go
guard := impersonation.NewGuard(
    mgr.GetClient(),
    ctrl.Log,
    impersonation.GuardConfig{
        RequeueAfter: 10 * time.Minute,
    },
)
```

## RBAC for the Impersonation Guard

The guard needs write access to ClusterRoles (it modifies the component ClusterRole that contributes the `impersonate` verb):

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: impersonation-guard
rules:
  - apiGroups: ["rbac.authorization.k8s.io"]
    resources: ["clusterroles"]
    verbs: ["get", "list", "watch", "update"]
```

## How It Works

1. The guard watches ClusterRoles with the label `rbac.authorization.kubernetes.io/aggregate-to-edit: "true"`.
2. When it finds one with the `impersonate` verb on ServiceAccounts, it removes that verb from the rules.
3. It sets `rbac.authorization.kubernetes.io/autoupdate: "false"` on the ClusterRole to prevent the Kubernetes RBAC bootstrap controller from resetting it during API server restarts.
4. It re-checks on the configured interval (default: 5 minutes) to catch drift from Kubernetes upgrades.

If the original rule used a wildcard (`*`) for verbs, the guard replaces it with all standard verbs except `impersonate`: `get`, `list`, `watch`, `create`, `update`, `patch`, `delete`.

## Deploy Companion VAP

The `deny-impersonate-grants` VAP template blocks attempts to re-add the `impersonate` verb via UPDATE operations on ClusterRoles. Deploy this alongside the guard for defense in depth.

See `config/vap/deny-impersonate-grants.yaml` for the template.

**Important:** The VAP prevents *external actors* from re-adding the verb but does not help during:

- Initial startup, when the verb already exists in the component ClusterRole.
- Kubernetes version upgrades, when the API server's built-in bootstrap reconciliation resets the ClusterRole (the bootstrap controller is not subject to admission policies).

Deploy the impersonation guard with a high `PriorityClass` to minimize the startup race window.
