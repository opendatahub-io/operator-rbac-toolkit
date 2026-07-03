# Kubebuilder Plugin

The operator-rbac-toolkit includes a Kubebuilder v4 external plugin that scaffolds graceful degradation library integration into your operator project. The plugin generates the boilerplate code, webhook configuration, and RBAC audit setup so you can focus on your operator's domain logic.

## What It Scaffolds

The plugin generates the following files in your Kubebuilder project:

| File | Purpose |
|------|---------|
| `pkg/security/config.go` | Operator identity configuration (name, SA, namespace). User-owned, never overwritten on re-run. |
| `pkg/security/graceful_setup.go` | `NewGracefulHandler()` factory, `DiscoverPermissionsAtStartup()`, and `WrapReconcileOperation()` convenience wrapper. |
| `pkg/security/audit_setup.go` | `RunAuditAtStartup()` function that scans for RBAC exposure and logs findings. |
| `config/security/webhook/validatingwebhookconfiguration.yaml` | SA protection webhook manifest with namespace selector. |
| `SECURITY_INTEGRATION.md` | Step-by-step guide for wiring the generated code into your reconciler and main.go. |

## Installation

Build the plugin binary:

```bash
cd operator-rbac-toolkit
go build -o kubebuilder-plugin ./cmd/kubebuilder-plugin/...
```

Register it with Kubebuilder by placing the binary in your `$PATH` or referencing it directly.

## Usage

From your Kubebuilder project root:

```bash
kubebuilder create security \
  --plugins security.ort.io/v1 \
  --operator-name my-operator \
  --sa-name my-operator-controller-manager \
  --sa-namespace my-operator-system
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--operator-name` | Auto-detected from PROJECT file | DNS-1123 name for your operator |
| `--sa-name` | `<operator-name>-controller-manager` | ServiceAccount name to protect |
| `--sa-namespace` | `<operator-name>-system` | Namespace where the SA lives |
| `--sa-protection` | `true` | Generate SA protection webhook configuration |
| `--rbac-audit` | `true` | Generate RBAC audit startup integration |
| `--dry-run` | `false` | Print generated files without writing to disk |
| `--force` | `false` | Overwrite existing generated files (except `config.go`) |

### Auto-Detection

When flags are omitted, the plugin auto-detects values from your project:

- **`--operator-name`**: Read from `projectName` in the PROJECT file
- **`--sa-name`**: Inferred as `<operator-name>-controller-manager`
- **`--sa-namespace`**: Inferred as `<operator-name>-system`
- **Module path**: Read from the `repo` field in the PROJECT file, used for import paths in generated code

### Dry Run

Preview what the plugin would generate without writing files:

```bash
kubebuilder create security \
  --plugins security.ort.io/v1 \
  --dry-run
```

## Integration After Scaffolding

After running the plugin, follow the generated `SECURITY_INTEGRATION.md` for step-by-step instructions. The key integration points are:

### 1. Wire the Handler into Your Reconciler

```go
import "your-module/pkg/security"

type MyReconciler struct {
    client.Client
    Scheme   *runtime.Scheme
    graceful *graceful.Handler
}

func (r *MyReconciler) SetupWithManager(mgr ctrl.Manager) error {
    r.graceful = security.NewGracefulHandler(mgr)
    return ctrl.NewControllerManagedBy(mgr).
        For(&v1alpha1.MyCR{}).
        Complete(r)
}
```

### 2. Wrap Operations in Your Reconciler

```go
func (r *MyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
    cr := &v1alpha1.MyCR{}
    if err := r.Get(ctx, req.NamespacedName, cr); err != nil {
        return ctrl.Result{}, client.IgnoreNotFound(err)
    }

    secrets := &corev1.SecretList{}
    result, err := security.WrapReconcileOperation(ctx, r.graceful, r.Client, cr, func() error {
        return r.List(ctx, secrets, client.InNamespace(cr.Namespace))
    })
    if err != nil {
        return result, err
    }
    if result.RequeueAfter > 0 {
        return result, nil
    }

    // Permission granted, continue reconciliation
    return ctrl.Result{}, nil
}
```

### 3. Add Startup Permission Discovery (main.go)

```go
import "your-module/pkg/security"

func main() {
    // ... manager setup ...

    if _, err := security.RunAuditAtStartup(ctx, mgr.GetClient(), setupLog); err != nil {
        setupLog.Error(err, "RBAC audit failed")
    }

    if err := security.DiscoverPermissionsAtStartup(ctx, mgr.GetClient(), setupLog, graceful.PermissionSpec{
        Resources: []graceful.ResourceSpec{
            {Group: "", Resource: "secrets", Verbs: []string{"get", "list"}},
        },
        Namespaces: []string{"my-namespace"},
    }); err != nil {
        setupLog.Error(err, "permission discovery failed")
    }

    // ... start manager ...
}
```

### 4. Deploy the Webhook (if SA protection is enabled)

Apply the generated webhook configuration:

```bash
kubectl apply -f config/security/webhook/validatingwebhookconfiguration.yaml
```

Label the operator's namespace to enable enforcement:

```bash
kubectl label namespace my-operator-system operator-rbac-toolkit.io/sa-protection=true
```

## State Management

The plugin stores state in `.ort-plugin-state.json` in your project root. This file tracks which files were generated and with what configuration. On subsequent runs, the plugin detects drift between the current flags and the saved state, and warns about configuration changes.

## Differences from the v1 OSR Plugin

| Aspect | v1 (operator-security-runtime) | v2 (operator-rbac-toolkit) |
|--------|-------------------------------|---------------------------|
| RBAC scoping | Scaffolded into the operator | Not scaffolded (admin-side concern) |
| Escalate/bind mode | `--bind-mode` flag | Not applicable |
| Impersonation guard | `--impersonation-guard` flag | Not scaffolded (admin-side concern) |
| Graceful degradation | Not available | Primary feature |
| Permission discovery | Not available | Scaffolded with SSAR checks |
| RBAC audit | `--rbac-audit` flag | `--rbac-audit` flag |
| SA protection | `--sa-protection` flag | `--sa-protection` flag |

The v2 plugin focuses exclusively on operator-side concerns (graceful degradation, permission discovery, SA protection). Admin-side concerns (RBAC scoping, impersonation guard, VAP templates) are deployed by cluster administrators using the standalone controller and config/vap templates.
