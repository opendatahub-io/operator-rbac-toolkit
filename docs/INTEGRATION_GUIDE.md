# Operator RBAC Toolkit: Integration Guide

This guide walks through integrating the operator-rbac-toolkit into your Kubernetes operator and cluster, step by step. Every code example uses the real types and function signatures from the codebase. Read the [Technical Design](TECHNICAL_DESIGN.md) for architecture context and tradeoff analysis.

**Prerequisites:**
- Go 1.22+
- Kubernetes 1.25+ (1.30+ for VAP templates)
- [controller-runtime](https://github.com/kubernetes-sigs/controller-runtime) v0.18+
- A Kubernetes operator built with controller-runtime (Operator SDK, Kubebuilder, or equivalent)

---

## Table of Contents

1. [Installation](#1-installation)
2. [Add Graceful Degradation Library](#2-add-graceful-degradation-library)
3. [Deploy the RBAC Scoping Controller](#3-deploy-the-rbac-scoping-controller)
4. [Add SA Identity Protection](#4-add-sa-identity-protection)
5. [Add Impersonation Guard](#5-add-impersonation-guard)
6. [Add RBAC Audit](#6-add-rbac-audit)
7. [Deploy VAP Templates](#7-deploy-vap-templates)
8. [Migration from operator-security-runtime v1](#8-migration-from-operator-security-runtime-v1)
9. [Configuration Reference](#9-configuration-reference)
10. [Troubleshooting](#10-troubleshooting)

---

## 1. Installation

```bash
go get github.com/ugiordan/operator-rbac-toolkit@latest
```

The toolkit is split into independent packages. Import only what you need:

| Package | Owner | Purpose |
|---------|-------|---------|
| `pkg/graceful` | Operator author | Permission-aware error handling, status conditions, permission discovery |
| `pkg/scoper` | Cluster admin | Dynamic namespace-scoped RoleBinding management |
| `pkg/saprotection` | Cluster admin | ValidatingWebhook protecting operator ServiceAccount identity |
| `pkg/impersonation` | Cluster admin | Closes the `impersonate` verb bypass in `system:aggregate-to-edit` |
| `pkg/audit` | Operator author or admin | Startup RBAC exposure scanning |

No package requires any other. The graceful degradation library (`pkg/graceful`) is the typical starting point for operator authors. The admin-side packages (`pkg/scoper`, `pkg/saprotection`, `pkg/impersonation`) are deployed by cluster administrators or platform operators.

---

## 2. Add Graceful Degradation Library

The graceful degradation library (`pkg/graceful`) gives your operator the ability to handle `Forbidden` errors cleanly instead of crashing. It surfaces structured status conditions, emits Kubernetes events, and retries with exponential backoff.

**RBAC requirements:** zero RBAC write verbs. The library only needs `create` on `selfsubjectaccessreviews` (already granted to all authenticated SAs via `system:basic-user`) and `create` on `events`.

### 2.1 Implement the StatusProvider Interface

Your CR's status struct must expose `[]metav1.Condition` via the `StatusProvider` interface:

```go
import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// StatusProvider is defined in pkg/graceful/types.go:
//
//   type StatusProvider interface {
//       GetConditions() []metav1.Condition
//       SetConditions([]metav1.Condition)
//   }

type MyCRStatus struct {
    Conditions []metav1.Condition `json:"conditions,omitempty"`
    // ... your other status fields
}

// Implement graceful.StatusProvider on your CR type.
func (m *MyCR) GetConditions() []metav1.Condition {
    return m.Status.Conditions
}

func (m *MyCR) SetConditions(conditions []metav1.Condition) {
    m.Status.Conditions = conditions
}
```

If your CR does not implement `StatusProvider`, the library still handles `Forbidden` errors and emits events. It just skips setting status conditions.

### 2.2 Create a Handler in Your Reconciler

Create a `graceful.Handler` during reconciler setup. The handler needs a `record.EventRecorder` from the controller manager:

```go
import (
    "github.com/ugiordan/operator-rbac-toolkit/pkg/graceful"
    ctrl "sigs.k8s.io/controller-runtime"
)

type MyReconciler struct {
    client.Client
    Scheme   *runtime.Scheme
    graceful *graceful.Handler
}

func (r *MyReconciler) SetupWithManager(mgr ctrl.Manager) error {
    recorder := mgr.GetEventRecorderFor("my-operator")

    r.graceful = graceful.NewHandler(recorder)

    return ctrl.NewControllerManagedBy(mgr).
        For(&v1alpha1.MyCR{}).
        Complete(r)
}
```

### 2.3 Wrap Operations with handler.Do()

Wrap any client operation that might be denied by RBAC with `handler.Do()`. The function signature:

```go
func (h *Handler) Do(
    ctx context.Context,
    c client.Client,
    obj client.Object,   // must also implement StatusProvider for status conditions
    fn func() error,     // the operation to attempt
) (ctrl.Result, error)
```

Return behavior:
- **Success:** returns `(ctrl.Result{}, nil)`. Continue reconciliation normally.
- **Forbidden:** sets `PermissionGranted=False` and `Degraded=True` conditions on the CR, emits a warning event, and returns `(ctrl.Result{RequeueAfter: d}, nil)` with exponential backoff.
- **Other errors:** returns `(ctrl.Result{}, err)` unchanged.

Example reconciler:

```go
func (r *MyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
    cr := &v1alpha1.MyCR{}
    if err := r.Get(ctx, req.NamespacedName, cr); err != nil {
        return ctrl.Result{}, client.IgnoreNotFound(err)
    }

    // Wrap operations that may fail with Forbidden.
    secrets := &corev1.SecretList{}
    result, err := r.graceful.Do(ctx, r.Client, cr, func() error {
        return r.List(ctx, secrets, client.InNamespace(cr.Namespace))
    })
    if err != nil {
        return result, err        // non-Forbidden error, propagate
    }
    if result.RequeueAfter > 0 {
        return result, nil        // Forbidden, requeue with backoff
    }

    // Permission was granted. Use secrets.Items normally.
    configMaps := &corev1.ConfigMapList{}
    result, err = r.graceful.Do(ctx, r.Client, cr, func() error {
        return r.List(ctx, configMaps, client.InNamespace(cr.Namespace))
    })
    if err != nil {
        return result, err
    }
    if result.RequeueAfter > 0 {
        return result, nil
    }

    // All permissions available, proceed with full reconciliation.
    return ctrl.Result{}, nil
}
```

When a previously-denied permission is restored, the handler automatically sets `PermissionGranted=True` and `Degraded=False`, and emits a `PermissionRestored` event.

### 2.4 Permission Discovery at Startup

Use `DiscoverPermissions` to check which permissions your SA has at startup or on demand. This uses `SelfSubjectAccessReview` calls, rate-limited by `MaxConcurrency`:

```go
import "github.com/ugiordan/operator-rbac-toolkit/pkg/graceful"

func (r *MyReconciler) checkPermissionsAtStartup(ctx context.Context) error {
    report, err := graceful.DiscoverPermissions(ctx, r.Client, graceful.PermissionSpec{
        Resources: []graceful.ResourceSpec{
            {Group: "", Resource: "secrets", Verbs: []string{"get", "list", "create"}},
            {Group: "", Resource: "configmaps", Verbs: []string{"get", "list"}},
            {Group: "apps", Resource: "deployments", Verbs: []string{"get", "list", "update"}},
        },
        Namespaces:     []string{"notebooks", "model-registry", "data-science-pipelines"},
        MaxConcurrency: 10,  // default is 10 if zero or negative
    })
    if err != nil {
        return err
    }

    // report.Granted:  []PermissionResult with Allowed=true
    // report.Denied:   []PermissionResult with Allowed=false
    // report.Summary:  "24/24 permissions granted across 3 namespace(s)"

    log.Info("permission discovery complete", "summary", report.Summary)

    for _, denied := range report.Denied {
        log.Info("permission denied",
            "resource", denied.Resource,
            "verb", denied.Verb,
            "namespace", denied.Namespace)
    }

    return nil
}
```

Apply the report to a CR's status conditions using `ApplyReport`:

```go
// Sets PermissionGranted and Degraded conditions based on the report.
if err := graceful.ApplyReport(ctx, r.Client, cr, report); err != nil {
    return ctrl.Result{}, err
}
```

For checking a single permission:

```go
allowed, err := graceful.CheckPermission(ctx, r.Client,
    "",           // apiGroup (core group)
    "secrets",    // resource
    "list",       // verb
    "notebooks",  // namespace
)
```

For bulk per-namespace checks on a single resource:

```go
// Returns map[string]bool: namespace -> allowed
nsPerms, err := graceful.DiscoverNamespacedPermissions(ctx, r.Client,
    "",          // apiGroup
    "secrets",   // resource
    "list",      // verb
    []string{"notebooks", "model-registry", "kube-system"},
)
// nsPerms["notebooks"] = true
// nsPerms["kube-system"] = false
```

### 2.5 Configuration Options

Customize backoff behavior with functional options:

```go
handler := graceful.NewHandler(recorder,
    graceful.WithRequeueAfter(15 * time.Second),   // initial requeue (default: 30s)
    graceful.WithMaxRequeue(10 * time.Minute),      // backoff cap (default: 5m)
    graceful.WithBackoffFactor(3.0),                // multiplier (default: 2.0, min: 1.0)
)
```

The backoff sequence with defaults: 30s, 60s, 120s, 240s, 300s (capped at 5m).

### 2.6 Status Conditions Set by the Library

The library manages two condition types on your CR:

| Condition Type | Status | Reason | Meaning |
|----------------|--------|--------|---------|
| `PermissionGranted` | `True` | `AllPermissionsAvailable` | All required permissions are available |
| `PermissionGranted` | `False` | `MissingPermissions` | One or more required permissions are denied |
| `Degraded` | `True` | `InsufficientRBAC` | Operator is running in degraded mode |
| `Degraded` | `False` | `FullyOperational` | All permissions available, fully functional |

These follow OpenShift operator status conventions. You can also use the low-level function directly:

```go
graceful.SetPermissionGranted(cr, false, "Missing permission: list secrets in namespace \"kube-system\"")
graceful.UpdateStatus(ctx, r.Client, cr)
```

---

## 3. Deploy the RBAC Scoping Controller

The scoping controller (`pkg/scoper`) is an admin-side component that dynamically creates namespace-scoped RoleBindings when CRs appear and cleans them up when CRs are deleted. It runs with its own ServiceAccount, separate from the operators it manages.

### 3.1 Prerequisites

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

### 3.2 Option A: Embedded in Platform Operator

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
                    Group:   "dashboard.opendatahub.io",
                    Version: "v1alpha1",
                    Kind:    "OdhDashboardConfig",
                },
                TargetSA: types.NamespacedName{
                    Name:      "odh-dashboard",
                    Namespace: "redhat-ods-applications",
                },
                ClusterRoleName:       "odh-dashboard-scoped",
                ManagedRoleBindingName: "odh-dashboard-scoped-binding",
                NamespaceSelector: &metav1.LabelSelector{
                    MatchLabels: map[string]string{
                        "opendatahub.io/dashboard": "true",
                    },
                },
            },
        },
        ControllerNamespace: "redhat-ods-operator",
    }

    if err := scoper.Setup(mgr, scoperCfg); err != nil {
        setupLog.Error(err, "unable to setup scoping controller")
        os.Exit(1)
    }

    // ... start manager ...
}
```

**Security tradeoff:** Embedded mode shares the platform operator's ServiceAccount, collapsing trust domain separation. Use this when the platform operator is already highly privileged and adding `bind` on specific ClusterRoles does not meaningfully increase blast radius.

### 3.3 Option B: Standalone Binary Deployment

For full trust domain separation, deploy the scoping controller as a separate Deployment with its own ServiceAccount. The standalone binary reads configuration from a ConfigMap.

**ConfigMap** (deploy to an admin-controlled namespace):

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: rbac-scoper-config
  namespace: rbac-scoper-system
data:
  targets: |
    - watchGVK:
        group: dashboard.opendatahub.io
        version: v1alpha1
        kind: OdhDashboardConfig
      targetSA:
        name: odh-dashboard
        namespace: redhat-ods-applications
      clusterRoleName: odh-dashboard-scoped
      managedRoleBindingName: odh-dashboard-scoped-binding
      namespaceSelector:
        matchLabels:
          opendatahub.io/dashboard: "true"
```

**RBAC for the scoping controller's ServiceAccount:**

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: rbac-scoper-controller
rules:
  # Watch target CRs
  - apiGroups: ["dashboard.opendatahub.io"]
    resources: ["odhdashboardconfigs"]
    verbs: ["get", "list", "watch"]
  # Manage RoleBindings
  - apiGroups: ["rbac.authorization.k8s.io"]
    resources: ["rolebindings"]
    verbs: ["get", "create", "update", "patch", "delete", "list", "watch"]
  # Bind the specific static ClusterRole (scoped by resourceNames)
  - apiGroups: ["rbac.authorization.k8s.io"]
    resources: ["clusterroles"]
    verbs: ["bind"]
    resourceNames: ["odh-dashboard-scoped"]
  # Validate ClusterRole at startup (no aggregationRule)
  - apiGroups: ["rbac.authorization.k8s.io"]
    resources: ["clusterroles"]
    verbs: ["get"]
    resourceNames: ["odh-dashboard-scoped"]
  # Watch namespace labels (only needed with NamespaceSelector)
  - apiGroups: [""]
    resources: ["namespaces"]
    verbs: ["get", "list", "watch"]
```

The controller does NOT need the `escalate` verb.

### 3.4 Configuration Deep Dive

#### ScopingTarget Fields

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
    FieldPath string  // e.g., ".spec.notebookController.notebookNamespace"
}
```

All of `WatchGVK.Kind`, `TargetSA.Name`, `TargetSA.Namespace`, `ClusterRoleName`, and `ManagedRoleBindingName` are required. Validation happens at setup time.

#### Cross-Namespace Grants

When an operator needs access to a namespace different from where its CR exists, use `TargetNamespaceSource`. For example, a Dashboard CR in `redhat-ods-applications` that needs access to `rhods-notebooks`:

```go
scoper.ScopingTarget{
    WatchGVK: schema.GroupVersionKind{
        Group:   "dashboard.opendatahub.io",
        Version: "v1alpha1",
        Kind:    "OdhDashboardConfig",
    },
    TargetSA: types.NamespacedName{
        Name:      "odh-dashboard",
        Namespace: "redhat-ods-applications",
    },
    ClusterRoleName:       "odh-dashboard-notebooks",
    ManagedRoleBindingName: "odh-dashboard-notebooks-binding",
    TargetNamespaceSource: &scoper.NamespaceSource{
        FieldPath: ".spec.notebookController.notebookNamespace",
    },
}
```

The `FieldPath` uses dot-notation to traverse the CR's unstructured fields. The value at that path must be a string containing a valid namespace name. This value is untrusted input and validated against the deny-list and `NamespaceSelector` before any RoleBinding is created.

Cross-namespace RoleBindings use annotation-based ownership (since Kubernetes does not allow cross-namespace `OwnerReferences`). The annotation key is `operator-rbac-toolkit.io/scoped-access-owners`, with comma-separated `namespace/name/uid` entries.

#### Deny-List Customization

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

#### Cleanup Interval

Cross-namespace RoleBinding cleanup runs on a configurable interval (default: 5 minutes):

```go
import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

scoperCfg := scoper.Config{
    Targets:         targets,
    CleanupInterval: metav1.Duration{Duration: 3 * time.Minute},
}
```

### 3.5 How the Controller Works

1. A CR of the configured GVK appears in a namespace.
2. The controller validates the namespace against the deny-list and `NamespaceSelector`.
3. The controller validates the static ClusterRole exists and has no `aggregationRule`.
4. The controller creates (or updates) a RoleBinding in the target namespace, referencing the static ClusterRole.
5. For same-namespace CRs, an `OwnerReference` is set on the RoleBinding pointing to the CR. Kubernetes GC handles cleanup when the CR is deleted.
6. For cross-namespace CRs, an annotation records ownership. The `CleanupReconciler` periodically scans for stale entries.
7. If multiple CRs exist in the same namespace, the RoleBinding persists until all CRs are removed.
8. Drift in RoleRef or Subjects is automatically corrected (RoleRef drift triggers delete+recreate since RoleRef is immutable in Kubernetes).

---

## 4. Add SA Identity Protection

The SA protection webhook (`pkg/saprotection`) prevents unauthorized workloads from using your operator's ServiceAccount. Without this, any user with `create pods` permission in the operator's namespace can create a pod that inherits the operator's full RBAC permissions.

### 4.1 Register the Webhook in main.go

```go
import (
    "github.com/ugiordan/operator-rbac-toolkit/pkg/saprotection"
    "sigs.k8s.io/controller-runtime/pkg/webhook"
)

func main() {
    mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
        Scheme: scheme,
        WebhookServer: webhook.NewServer(webhook.Options{
            Port:    9443,
            CertDir: "/tmp/k8s-webhook-server/serving-certs",
        }),
    })
    if err != nil {
        setupLog.Error(err, "unable to start manager")
        os.Exit(1)
    }

    saWebhook := saprotection.NewWebhook(
        saprotection.WebhookConfig{
            ProtectedServiceAccounts: []string{
                "odh-dashboard",
                "my-operator-controller-manager",
            },
            AllowedIdentities: []string{
                // The operator's own controller SA
                "system:serviceaccount:redhat-ods-applications:odh-dashboard",
                // Kubernetes system controllers that create pods on behalf of Deployments/Jobs
                "system:serviceaccount:kube-system:replicaset-controller",
                "system:serviceaccount:kube-system:job-controller",
                "system:serviceaccount:kube-system:statefulset-controller",
                "system:serviceaccount:kube-system:daemon-set-controller",
            },
        },
        mgr.GetScheme(),
    )

    mgr.GetWebhookServer().Register("/validate-sa-protection", &webhook.Admission{Handler: saWebhook})

    // ... start manager ...
}
```

### 4.2 Deploy the ValidatingWebhookConfiguration

```yaml
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: sa-protection
webhooks:
  - name: sa-protection.operator-rbac-toolkit.io
    admissionReviewVersions: ["v1"]
    clientConfig:
      service:
        name: my-operator-webhook-service
        namespace: redhat-ods-applications
        path: /validate-sa-protection
    failurePolicy: Fail
    sideEffects: None
    rules:
      - apiGroups: [""]
        apiVersions: ["v1"]
        operations: ["CREATE", "UPDATE"]
        resources: ["pods"]
    namespaceSelector:
      matchLabels:
        operator-rbac-toolkit.io/sa-protection: "true"
```

Label the operator's namespace to enable enforcement:

```bash
kubectl label namespace redhat-ods-applications operator-rbac-toolkit.io/sa-protection=true
```

### 4.3 How It Works

The webhook intercepts Pod CREATE and UPDATE requests:

1. If the pod does not use a protected ServiceAccount, the request is allowed.
2. For UPDATE operations, if the ServiceAccount field has not changed, the request is allowed (avoids false positives from kubelet status updates).
3. If the requesting user is in the `AllowedIdentities` list, the request is allowed.
4. Otherwise, the request is denied with `"ServiceAccount <name> is protected"`.

### 4.4 System Controller Tradeoff

Including system controllers (e.g., `replicaset-controller`) in `AllowedIdentities` means any Deployment in the operator's namespace can reference the protected SA. The webhook prevents *direct* Pod creation with the SA but does not prevent *indirect* creation via Deployments or Jobs.

**Compensating control:** restrict `create` on Deployments, StatefulSets, and Jobs in the operator's namespace to authorized principals via standard RBAC.

### 4.5 Deployment Considerations

- Deploy the webhook in a **separate namespace** from the operator it protects. If the webhook pod is down and `failurePolicy: Fail` is set, all pod creation in the scoped namespace is blocked.
- Use a `PriorityClass` to ensure the webhook pod schedules before operator workloads.
- Configure `PodDisruptionBudgets` for high availability.

---

## 5. Add Impersonation Guard

The impersonation guard (`pkg/impersonation`) closes a privilege escalation path in Kubernetes. The default `system:aggregate-to-edit` ClusterRole includes the `impersonate` verb for ServiceAccounts, allowing any namespace editor to impersonate any ServiceAccount in their namespace.

### 5.1 Register in main.go

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

With custom configuration:

```go
guard := impersonation.NewGuard(
    mgr.GetClient(),
    ctrl.Log,
    impersonation.GuardConfig{
        RequeueAfter: 10 * time.Minute,
    },
)
```

### 5.2 RBAC for the Impersonation Guard

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

### 5.3 How It Works

1. The guard watches ClusterRoles with the label `rbac.authorization.kubernetes.io/aggregate-to-edit: "true"`.
2. When it finds one with the `impersonate` verb on ServiceAccounts, it removes that verb from the rules.
3. It sets `rbac.authorization.kubernetes.io/autoupdate: "false"` on the ClusterRole to prevent the Kubernetes RBAC bootstrap controller from resetting it during API server restarts.
4. It re-checks on the configured interval (default: 5 minutes) to catch drift from Kubernetes upgrades.

If the original rule used a wildcard (`*`) for verbs, the guard replaces it with all standard verbs except `impersonate`: `get`, `list`, `watch`, `create`, `update`, `patch`, `delete`.

### 5.4 Deploy Companion VAP

The `deny-impersonate-grants` VAP template blocks attempts to re-add the `impersonate` verb via UPDATE operations on ClusterRoles. Deploy this alongside the guard for defense in depth:

```yaml
# See config/vap/deny-impersonate-grants.yaml
```

**Important:** The VAP prevents *external actors* from re-adding the verb but does not help during:
- Initial startup, when the verb already exists in the component ClusterRole.
- Kubernetes version upgrades, when the API server's built-in bootstrap reconciliation resets the ClusterRole (the bootstrap controller is not subject to admission policies).

Deploy the impersonation guard with a high `PriorityClass` to minimize the startup race window.

---

## 6. Add RBAC Audit

The RBAC audit package (`pkg/audit`) scans the cluster at startup to identify RBAC exposure risks. It produces structured findings that you can surface via logs, events, or status conditions.

### 6.1 Startup Integration

```go
import (
    "github.com/ugiordan/operator-rbac-toolkit/pkg/audit"
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

### 6.2 Scan Categories

The `Scan` function runs five independent scanners:

| Scanner | Category | Severity | What It Detects |
|---------|----------|----------|-----------------|
| Impersonation grants | `impersonation-grants` | `Critical` | Any Role/ClusterRole granting `impersonate` on ServiceAccounts (excluding `system:aggregate-to-edit`, which has its own scanner) |
| TokenRequest exposure | `tokenrequest-exposure` | `Critical` | Any Role/ClusterRole granting `create` on `serviceaccounts/token` |
| Aggregate-to-edit | `aggregate-to-edit-impersonate` | `Warning` | Whether `system:aggregate-to-edit` still includes the `impersonate` verb |
| Unused permissions | `unused-permissions` | `Info` | Permissions in ClusterRoles bound to your SA that don't match any `ExpectedRules` entry |
| Aggregation rules | `aggregation-rules` | `Warning` | ClusterRoles bound to your SA that use `aggregationRule` |

### 6.3 Finding Type

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

### 6.4 Custom Expected Rules

The `ExpectedRules` field in `audit.Config` defines the permissions your operator actually needs. The unused-permissions scanner compares rules in ClusterRoles bound to your SA against this list. Any rule that has zero overlap (no shared apiGroup, resource, or verb) with your expected rules is flagged as `Info` severity.

If `ExpectedRules` is empty, the unused-permissions scanner is skipped.

---

## 7. Deploy VAP Templates

ValidatingAdmissionPolicy (VAP) templates enforce RBAC invariants at the API server level. They work independently of the toolkit's Go packages and provide guarantees that a compromised SA cannot bypass.

**Requirement:** Kubernetes 1.30+ (VAP GA). On OpenShift, this means 4.17+.

### 7.1 Available Templates

| Template | Purpose |
|----------|---------|
| `deny-impersonate-grants` | Block `impersonate` verb grants in any Role/ClusterRole |
| `restrict-scoped-rolebinding-creation` | Only the scoping controller's SA can create managed RoleBindings |
| `restrict-scoped-rolebinding-mutation` | Only the scoping controller's SA can update or delete managed RoleBindings |
| `restrict-scoped-rolebinding-subjects` | Managed RoleBindings can only reference the target operator's SA |
| `deny-rolebinding-in-protected-namespaces` | Block RoleBinding creation in sensitive namespaces (kube-system, etc.) |
| `allow-rolebinding-in-labeled-namespaces` | Only admin-labeled namespaces can receive managed RoleBindings |
| `protect-rbac-allowed-label` | Prevent non-admin label manipulation on namespaces |
| `protect-vap-enforcement-labels` | Prevent removal of labels used by VAP binding namespaceSelectors |
| `protect-static-clusterrole` | Prevent modification of the static ClusterRole |
| `deny-aggregated-static-clusterrole` | Block adding `aggregationRule` to the static ClusterRole |
| `protect-scoper-config` | Restrict write access to the scoping controller's ConfigMap |
| `restrict-ephemeral-containers-on-protected-pods` | Restrict `kubectl debug` on pods using protected SAs |

Templates are YAML files in `config/vap/`. Each template includes inline documentation.

### 7.2 Recommended Production Stack

Deploy these VAPs in order of priority:

**Tier 1: Critical (deploy immediately)**
- `protect-static-clusterrole` . prevents permission ceiling tampering
- `deny-aggregated-static-clusterrole` . prevents aggregation-based rule injection
- `restrict-scoped-rolebinding-creation` . only scoping controller creates managed RoleBindings
- `restrict-scoped-rolebinding-mutation` . prevents unauthorized RoleBinding modification
- `deny-impersonate-grants` . companion to the impersonation guard

**Tier 2: Namespace protection (deploy with scoping controller)**
- `deny-rolebinding-in-protected-namespaces` . deny-list for sensitive namespaces
- `allow-rolebinding-in-labeled-namespaces` . allow-list for authorized namespaces
- `protect-rbac-allowed-label` . prevents namespace label spoofing

**Tier 3: Defense in depth (deploy when ready)**
- `restrict-scoped-rolebinding-subjects` . prevents subject manipulation
- `protect-vap-enforcement-labels` . prevents VAP bypass via label removal
- `protect-scoper-config` . protects scoping controller configuration
- `restrict-ephemeral-containers-on-protected-pods` . prevents SA token access via `kubectl debug`

### 7.3 Customization

Each VAP template needs to be customized for your environment. Common fields to update:

- **ServiceAccount names** in `restrict-scoped-rolebinding-creation` (the scoping controller's SA)
- **ClusterRole names** in `protect-static-clusterrole` (the static ClusterRole to protect)
- **Namespace names** in `deny-rolebinding-in-protected-namespaces` (additional platform-specific namespaces)
- **Label keys** in `allow-rolebinding-in-labeled-namespaces` (the admin-controlled label that authorizes a namespace)

### 7.4 Clusters Without VAP Support

On Kubernetes < 1.30 (OpenShift < 4.17), deploy the core components without VAPs:

1. Scoping controller (for dynamic RoleBinding management)
2. Graceful degradation library (for permission-aware error handling)
3. SA protection webhook (for SA identity protection)
4. Impersonation guard (for impersonate verb removal)
5. RBAC audit (for exposure scanning)

The VAP templates provide defense in depth but are not required for the core scoping functionality to work.

---

## 8. Migration from operator-security-runtime v1

### 8.1 Component Mapping

| v1 Package | v2 Package | Change |
|------------|------------|--------|
| `pkg/rbacscope` (operator-embedded) | `pkg/scoper` (external controller) | RBAC management moves from operator to scoping controller |
| `pkg/rbacscope` (bind mode) | `pkg/scoper` (bind-only) | Direct port |
| `pkg/saprotection` | `pkg/saprotection` | No change |
| `pkg/impersonationguard` | `pkg/impersonation` | Package renamed |
| `pkg/rbacaudit` | `pkg/audit` | Package renamed |
| N/A | `pkg/graceful` | New. Add to your operator |

### 8.2 Step-by-Step Migration

Each step is independently reversible. You can pause the migration at any point and roll back without data loss.

**Step 1: Add graceful degradation library.**

This is additive. No behavior change when permissions are available.

```go
// In your reconciler, wrap RBAC-sensitive operations:
result, err := r.graceful.Do(ctx, r.Client, cr, func() error {
    return r.List(ctx, secrets, client.InNamespace(ns))
})
```

Rollback: remove the `Do()` calls and revert to direct client operations.

**Step 2: Deploy the static ClusterRole.**

Create the static ClusterRole with the scoped permissions your operator needs. Use the same rules that were previously in the operator's self-managed Roles.

```bash
kubectl apply -f static-clusterrole.yaml
```

Rollback: `kubectl delete clusterrole my-operator-scoped`

**Step 3: Deploy the scoping controller.**

Configure it with your operator's SA and CR GVK. The scoping controller creates RoleBindings that coexist with any existing ClusterRoleBinding.

Rollback: uninstall the scoping controller. Managed RoleBindings with OwnerReferences will be garbage collected when CRs are deleted. Cross-namespace RoleBindings persist but are harmless while the ClusterRoleBinding still exists.

**Step 4: Verify scoped access works.**

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

**Step 5: Remove RBAC management code from the operator.**

Remove the v1 `pkg/rbacscope` integration from your operator's reconciler. Remove `escalate` and `bind` verb requirements from the operator's RBAC markers/manifests.

Rollback: re-add the v1 integration code.

**Step 6: Remove the legacy ClusterRoleBinding.**

This is the point of no return for the RBAC scoping. After this, the operator only has access in namespaces where the scoping controller has created RoleBindings.

```bash
kubectl delete clusterrolebinding my-operator-binding
```

Rollback: recreate the ClusterRoleBinding. All existing tokens immediately regain cluster-wide access (no token rotation needed, Kubernetes evaluates RBAC on every request).

**Step 7: Deploy VAP templates.**

Apply the protection policies for defense in depth (see [section 7](#7-deploy-vap-templates)).

Rollback: `kubectl delete validatingadmissionpolicy <name>`

---

## 9. Configuration Reference

### 9.1 Graceful Degradation Library (`pkg/graceful`)

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `WithRequeueAfter(d)` | `time.Duration` | 30s | Initial requeue interval after a Forbidden error |
| `WithMaxRequeue(d)` | `time.Duration` | 5m | Maximum requeue interval (backoff cap) |
| `WithBackoffFactor(f)` | `float64` | 2.0 | Backoff multiplier (minimum 1.0, values below 1.0 reset to 2.0) |
| `PermissionSpec.MaxConcurrency` | `int` | 10 | Maximum concurrent SSAR calls during discovery (values <= 0 default to 10) |

### 9.2 RBAC Scoping Controller (`pkg/scoper`)

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `Config.Targets` | `[]ScopingTarget` | (required) | List of CR-to-RoleBinding mappings. Must be non-empty. |
| `Config.DenyList` | `DenyListConfig` | `DefaultDenyList()` | Namespaces and prefixes where RoleBindings are never created |
| `Config.CleanupInterval` | `metav1.Duration` | 5m | Interval for cross-namespace orphan cleanup scans |
| `Config.ControllerNamespace` | `string` | `""` | The scoping controller's own namespace (added to deny-list) |
| `ScopingTarget.WatchGVK` | `schema.GroupVersionKind` | (required) | GVK of the Custom Resource to watch |
| `ScopingTarget.TargetSA` | `types.NamespacedName` | (required) | ServiceAccount to grant access to |
| `ScopingTarget.ClusterRoleName` | `string` | (required) | Static ClusterRole to reference (no aggregationRule) |
| `ScopingTarget.ManagedRoleBindingName` | `string` | (required) | Deterministic name for managed RoleBindings |
| `ScopingTarget.NamespaceSelector` | `*metav1.LabelSelector` | nil (all namespaces) | Restrict which namespaces are watched |
| `ScopingTarget.TargetNamespaceSource` | `*NamespaceSource` | nil (same namespace) | Create RoleBinding in a different namespace than the CR |

### 9.3 SA Protection Webhook (`pkg/saprotection`)

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `WebhookConfig.ProtectedServiceAccounts` | `[]string` | (required) | SA names to protect (name-only, not namespace-qualified) |
| `WebhookConfig.AllowedIdentities` | `[]string` | (required) | `userInfo.username` values allowed to create pods with protected SAs |

### 9.4 Impersonation Guard (`pkg/impersonation`)

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `GuardConfig.RequeueAfter` | `time.Duration` | 5m | Interval for periodic drift checks |

### 9.5 RBAC Audit (`pkg/audit`)

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `Config.ServiceAccount` | `types.NamespacedName` | (required) | The SA to audit |
| `Config.ExpectedRules` | `[]rbacv1.PolicyRule` | nil (skip unused-permissions scan) | Expected permissions for the unused-permissions scanner |

### 9.6 Default Deny-List

Generated by `scoper.DefaultDenyList(controllerNamespace)`:

| Type | Values |
|------|--------|
| Namespaces | `kube-system`, `kube-public`, `kube-node-lease`, `default`, plus `controllerNamespace` if non-empty |
| Prefixes | `openshift-` |

---

## 10. Troubleshooting

### Scoping controller fails to start with "no scoping targets configured"

The `Config.Targets` slice is empty. At least one `ScopingTarget` must be provided.

### "ClusterRole uses aggregationRule, which is not allowed"

The static ClusterRole specified in `ClusterRoleName` has an `aggregationRule` field. This is rejected because aggregated ClusterRoles allow rule injection via label-matching component ClusterRoles. Remove the `aggregationRule` from the ClusterRole and define rules explicitly.

### "CRD not available, skipping controller registration"

The CRD for the configured `WatchGVK` is not installed in the cluster. The scoping controller logs a warning and skips this target. Install the CRD and restart the scoping controller.

### Operator shows "Degraded: InsufficientRBAC" status condition

The operator is missing one or more RBAC permissions. Check the condition's `message` field for the specific permission. Common causes:
- The scoping controller has not yet created a RoleBinding (check if the CR exists and the namespace is allowed).
- The static ClusterRole is missing the required rule.
- The legacy ClusterRoleBinding was removed before the scoping controller was deployed.

### RoleBindings not created in expected namespaces

Check these in order:
1. **Is the namespace in the deny-list?** Run `scoper.IsDenied(namespace, denyList)` or check the deny-list configuration.
2. **Does the namespace match the `NamespaceSelector`?** The namespace must have the required labels.
3. **Does the static ClusterRole exist?** The controller logs a warning and emits an event if the ClusterRole is missing.
4. **Does the CR exist in the namespace?** The controller only creates RoleBindings in namespaces that contain CRs of the configured GVK (or in the target namespace for cross-namespace grants).

### Cross-namespace RoleBindings persist after CR deletion

Cross-namespace RoleBindings use annotation-based ownership with periodic cleanup (default: 5 minutes). If the cleanup reconciler was down when the CR was deleted, the RoleBinding persists until the next cleanup scan. This is a temporary over-grant, not a bug. The design prioritizes avoiding stuck finalizers (which block namespace deletion) over immediate cleanup.

### SA protection webhook blocks all pod creation

The webhook is deployed with `failurePolicy: Fail`. If the webhook pod is down, all pod creation in namespaces matching the webhook's `namespaceSelector` is blocked. Verify the webhook pod is running. Deploy the webhook in a separate namespace from the operator it protects, with a `PriorityClass` and `PodDisruptionBudget`.

### Impersonation guard finds no ClusterRoles to modify

The guard watches ClusterRoles with `rbac.authorization.kubernetes.io/aggregate-to-edit: "true"`. If no such ClusterRoles exist (possible on non-standard Kubernetes distributions), the guard is a no-op. Run the RBAC audit component to verify whether `system:aggregate-to-edit` still includes the `impersonate` verb.

### RBAC audit shows "unused-permissions" findings

These are `Info` severity findings indicating that rules in ClusterRoles bound to your SA don't match any of your `ExpectedRules`. Review each finding. If the permission is genuinely needed, add it to `ExpectedRules`. If it is truly unused, remove it from the ClusterRole to reduce blast radius.

### Permission discovery shows denied permissions that should be allowed

`DiscoverPermissions` uses `SelfSubjectAccessReview`, which checks the actual permissions of the SA making the call. If the discovery runs before the scoping controller creates the RoleBinding (e.g., during startup race), permissions may show as denied. Retry after the scoping controller has had time to reconcile, or add the graceful degradation library's `Do()` wrapper to handle the transient denial.
