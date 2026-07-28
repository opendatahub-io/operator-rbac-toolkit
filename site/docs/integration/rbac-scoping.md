# Deploying the RBAC Scoping Controller

The scoping controller (`pkg/scoper`) is an admin-side component that dynamically creates namespace-scoped RoleBindings when CRs appear and cleans them up when CRs are deleted. It runs with its own ServiceAccount, separate from the operators it manages.

## Prerequisites

Before deploying the scoping controller, you need a **static ClusterRole** that defines the permission ceiling for the target operator. This ClusterRole:

- Must NOT use `aggregationRule` (validated at startup, rejected if present)
- Must be deployed by the cluster admin (not the operator)
- Should be protected by the `protect-static-clusterrole` VAP template

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: my-operator-scoped
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get", "list", "create", "update"]
  - apiGroups: [""]
    resources: ["configmaps"]
    verbs: ["get", "list"]
  - apiGroups: ["apps"]
    resources: ["deployments"]
    verbs: ["get", "list", "update"]
```

## Option A: Embedded in Platform Operator

This is the simplest integration. Import `pkg/scoper` and call `scoper.Setup()` in your operator's `main.go`:

```go
import (
    "github.com/ugiordan/operator-rbac-toolkit/pkg/scoper"
    metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
    "k8s.io/apimachinery/pkg/runtime/schema"
    "k8s.io/apimachinery/pkg/types"
)

func main() {
    // ... standard controller-runtime manager setup ...

    mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
        Scheme: scheme,
        // ...
    })
    if err != nil {
        setupLog.Error(err, "unable to start manager")
        os.Exit(1)
    }

    // Configure scoping targets.
    scoperCfg := scoper.Config{
        Targets: []scoper.ScopingTarget{
            {
                WatchGVK: schema.GroupVersionKind{
                    Group:   "apps.example.com",
                    Version: "v1alpha1",
                    Kind:    "WidgetConfig",
                },
                TargetSA: types.NamespacedName{
                    Name:      "widget-operator",
                    Namespace: "widget-operator-system",
                },
                ClusterRoleName:       "widget-operator-scoped",
                ManagedRoleBindingName: "widget-operator-scoped-binding",
                NamespaceSelector: &metav1.LabelSelector{
                    MatchLabels: map[string]string{
                        "apps.example.com/managed": "true",
                    },
                },
            },
        },
        ControllerNamespace: "platform-operator-system",
    }

    if err := scoper.Setup(mgr, scoperCfg); err != nil {
        setupLog.Error(err, "unable to setup scoping controller")
        os.Exit(1)
    }

    // ... start manager ...
}
```

**Security tradeoff:** Embedded mode shares the platform operator's ServiceAccount, collapsing trust domain separation. Use this when the platform operator is already highly privileged and adding `bind` on specific ClusterRoles does not meaningfully increase blast radius.

## Option B: Standalone Binary Deployment

For full trust domain separation, deploy the scoping controller as a separate Deployment with its own ServiceAccount. The standalone binary reads configuration from a ConfigMap.

### ConfigMap

Deploy to an admin-controlled namespace, mounted as a file at `/etc/rbac-scoper/config.yaml`:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: rbac-scoper-config
  namespace: rbac-scoper-system
data:
  config.yaml: |
    controllerNamespace: rbac-scoper-system
    targets:
      - watchGVK:
          group: apps.example.com
          version: v1alpha1
          kind: WidgetConfig
        targetSA:
          name: widget-operator
          namespace: widget-operator-system
        clusterRoleName: widget-operator-scoped
        managedRoleBindingName: widget-operator-scoped-binding
        namespaceSelector:
          matchLabels:
            apps.example.com/managed: "true"
```

The standalone binary reads this file via `--config` flag (default: `/etc/rbac-scoper/config.yaml`). Mount the ConfigMap key `config.yaml` to this path in the Deployment's volume configuration.

### RBAC for the Scoping Controller's ServiceAccount

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: rbac-scoper-controller
rules:
  # Watch target CRs
  - apiGroups: ["apps.example.com"]
    resources: ["widgetconfigs"]
    verbs: ["get", "list", "watch"]
  # Manage RoleBindings
  - apiGroups: ["rbac.authorization.k8s.io"]
    resources: ["rolebindings"]
    verbs: ["get", "create", "update", "patch", "delete", "list", "watch"]
  # Bind the specific static ClusterRole (scoped by resourceNames)
  - apiGroups: ["rbac.authorization.k8s.io"]
    resources: ["clusterroles"]
    verbs: ["bind"]
    resourceNames: ["widget-operator-scoped"]
  # Validate ClusterRole at startup (no aggregationRule)
  - apiGroups: ["rbac.authorization.k8s.io"]
    resources: ["clusterroles"]
    verbs: ["get"]
    resourceNames: ["widget-operator-scoped"]
  # Watch namespace labels (only needed with NamespaceSelector)
  - apiGroups: [""]
    resources: ["namespaces"]
    verbs: ["get", "list", "watch"]
```

The controller does NOT need the `escalate` verb.

## Configuration Deep Dive

### ScopingTarget Fields

Each `ScopingTarget` specifies one CR-to-RoleBinding mapping:

```go
type ScopingTarget struct {
    // The GVK of the Custom Resource to watch.
    WatchGVK schema.GroupVersionKind

    // The ServiceAccount to grant access to.
    TargetSA types.NamespacedName

    // The ClusterRole to reference in the RoleBinding. Must not use aggregationRule.
    ClusterRoleName string

    // Deterministic name for managed RoleBindings. Enables drift detection and cleanup.
    ManagedRoleBindingName string

    // Optional: restrict which namespaces are watched.
    // If nil, all namespaces are watched.
    NamespaceSelector *metav1.LabelSelector

    // Optional: create RoleBinding in a different namespace than the CR.
    // Reads the target namespace from the specified field in the CR spec.
    TargetNamespaceSource *NamespaceSource
}

type NamespaceSource struct {
    FieldPath string  // e.g., ".spec.workloadController.workloadNamespace"
}
```

All of `WatchGVK.Kind`, `TargetSA.Name`, `TargetSA.Namespace`, `ClusterRoleName`, and `ManagedRoleBindingName` are required. Validation happens at setup time.

### Cross-Namespace Grants

When an operator needs access to a namespace different from where its CR exists, use `TargetNamespaceSource`. For example, an operator CR in `widget-operator-system` that needs access to `workload-ns`:

```go
scoper.ScopingTarget{
    WatchGVK: schema.GroupVersionKind{
        Group:   "apps.example.com",
        Version: "v1alpha1",
        Kind:    "WidgetConfig",
    },
    TargetSA: types.NamespacedName{
        Name:      "widget-operator",
        Namespace: "widget-operator-system",
    },
    ClusterRoleName:       "widget-operator-workloads",
    ManagedRoleBindingName: "widget-operator-workloads-binding",
    TargetNamespaceSource: &scoper.NamespaceSource{
        FieldPath: ".spec.workloadController.workloadNamespace",
    },
}
```

The `FieldPath` uses dot-notation to traverse the CR's unstructured fields. The value at that path must be a string containing a valid namespace name. This value is untrusted input and validated against the deny-list and `NamespaceSelector` before any RoleBinding is created.

Cross-namespace RoleBindings use annotation-based ownership (since Kubernetes does not allow cross-namespace `OwnerReferences`). The annotation key is `operator-rbac-toolkit.io/scoped-access-owners`, with comma-separated `namespace/name/uid` entries.

### Deny-List Customization

The deny-list prevents RoleBinding creation in sensitive namespaces. The default deny-list is generated by `DefaultDenyList()`:

```go
func DefaultDenyList(controllerNamespace string) DenyListConfig {
    return DenyListConfig{
        Namespaces: []string{
            "kube-system",
            "kube-public",
            "kube-node-lease",
            "default",
            controllerNamespace,  // the scoping controller's own namespace
        },
        Prefixes: []string{"openshift-"},
    }
}
```

To customize, set the `DenyList` field on `Config`:

```go
scoperCfg := scoper.Config{
    Targets: targets,
    DenyList: scoper.DenyListConfig{
        Namespaces: []string{
            "kube-system", "kube-public", "kube-node-lease", "default",
            "rbac-scoper-system",
            "istio-system",         // platform-specific
            "cert-manager",         // platform-specific
        },
        Prefixes: []string{
            "openshift-",
            "gke-",                 // GKE-specific
        },
    },
    ControllerNamespace: "rbac-scoper-system",
}
```

If `DenyList` is left empty, the default deny-list is used. The deny-list validation runs in the controller itself, independent of any VAPs.

### Cleanup Interval Configuration

Cross-namespace RoleBinding cleanup runs on a configurable interval (default: 5 minutes):

```go
import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

scoperCfg := scoper.Config{
    Targets:         targets,
    CleanupInterval: metav1.Duration{Duration: 3 * time.Minute},
}
```

## How the Controller Works

1. A CR of the configured GVK appears in a namespace.
2. The controller validates the namespace against the deny-list and `NamespaceSelector`.
3. The controller validates the static ClusterRole exists and has no `aggregationRule`.
4. The controller creates (or updates) a RoleBinding in the target namespace, referencing the static ClusterRole.
5. For same-namespace CRs, an `OwnerReference` is set on the RoleBinding pointing to the CR. Kubernetes GC handles cleanup when the CR is deleted.
6. For cross-namespace CRs, an annotation records ownership. The `CleanupReconciler` periodically scans for stale entries.
7. If multiple CRs exist in the same namespace, the RoleBinding persists until all CRs are removed.
8. Drift in RoleRef or Subjects is automatically corrected (RoleRef drift triggers delete+recreate since RoleRef is immutable in Kubernetes).
