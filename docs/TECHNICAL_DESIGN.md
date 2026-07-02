# Operator RBAC Toolkit: Technical Design

## Table of Contents

1. [Problem Analysis](#1-problem-analysis)
2. [Design Principles](#2-design-principles)
3. [Solution Architecture](#3-solution-architecture)
4. [Component 1: Graceful Degradation Library](#4-component-1-graceful-degradation-library)
5. [Component 2: RBAC Scoping Controller](#5-component-2-rbac-scoping-controller)
6. [Component 3: Defense-in-Depth Toolkit](#6-component-3-defense-in-depth-toolkit)
7. [Threat Model](#7-threat-model)
8. [Key Architectural Tradeoffs](#8-key-architectural-tradeoffs)
9. [Observability](#9-observability)
10. [Performance Characteristics](#10-performance-characteristics)
11. [Kubernetes Version Compatibility](#11-kubernetes-version-compatibility)
12. [Migration from operator-security-runtime v1](#12-migration-from-operator-security-runtime-v1)
13. [Known Limitations](#13-known-limitations)

---

## 1. Problem Analysis

### 1.1 Root Cause

Kubernetes operators routinely ship with overly broad ClusterRole permissions. The CNCF Operator White Paper confirms that operator build kits such as the Operator SDK "use general RBAC defaults that developers may have not refined for their specific operator." In practice, this means operators are deployed with cluster-wide access to secrets, configmaps, and other sensitive resources across all namespaces, even when they only need access in the namespaces where their Custom Resources exist.

Three systemic patterns cause this:

1. **Permissions added erroneously.** Developers assume the ServiceAccount needs permissions that are actually accessed via user-token passthrough. The permission is granted but never exercised by the SA.
2. **Permission drift.** Features are removed or refactored, but the corresponding RBAC rules remain in the ClusterRole. Nobody audits the gap.
3. **Over-granted verbs.** Rules specify `[get, list, watch, create, update, patch, delete]` when only `[list]` is needed. Scaffolding tools generate broad defaults and developers don't refine them.

A real-world audit of the RHOAI Dashboard's ClusterRole found that only 2 out of 30 rules were correctly scoped. 9 rules were entirely unused, 14 were over-permissioned, and the `watch` verb was granted on nearly every resource despite never being used (the backend polls with `setInterval` + `list`, not the Kubernetes watch API).

### 1.2 Why Standard RBAC Does Not Solve This

Kubernetes RBAC provides the primitives to enforce least privilege, but it does not automate their application. The gap is operational, not technical:

- **ClusterRoleBindings are the default.** When an operator needs cross-namespace access (e.g., to a notebooks namespace and a model registry namespace), developers grant a ClusterRoleBinding rather than creating per-namespace RoleBindings. The ClusterRoleBinding grants access everywhere.
- **Namespace locations are dynamic.** Components like notebooks or model registries can be deployed to admin-configurable namespaces (via DSC/DSCI). Static RBAC manifests cannot target namespaces that are determined at runtime.
- **Nobody scopes after deployment.** Cluster admins install operators via OLM, Helm, or GitOps. The operator ships with a ClusterRole and ClusterRoleBinding. Nobody goes back to create namespace-scoped alternatives.

### 1.3 Impact Assessment

When an operator's ServiceAccount token is compromised (via pod escape, supply chain attack, or token exfiltration), the blast radius is determined by the RBAC permissions granted to that SA:

| Vector | With ClusterRoleBinding | With Namespace-Scoped RoleBindings |
|--------|------------------------|------------------------------------|
| **Secret access** | All secrets in all namespaces (e.g., 43 secrets in kube-system alone) | Only secrets in namespaces with active CRs (e.g., 5 secrets in one namespace) |
| **Lateral movement** | Token can access resources in any namespace, enabling pivot to other workloads | Access is confined to CR-bearing namespaces |
| **Privilege escalation** | Broad verb grants (create, patch, delete) across cluster enable multiple escalation paths | Reduced verb surface in fewer namespaces limits escalation options |

### 1.4 Attack Scenarios

**Scenario 1: Secret Exfiltration.** An attacker gains access to the operator's SA token (e.g., through a container escape in a co-located workload). With a ClusterRoleBinding granting `list` on secrets, the token can enumerate secrets in every namespace, including kube-system (cloud provider credentials, TLS certificates, database passwords). With namespace-scoped RoleBindings, the same token is rejected with `Forbidden` for every namespace except those with active CRs.

**Scenario 2: Impersonation Bypass.** The default `system:aggregate-to-edit` ClusterRole includes the `impersonate` verb for ServiceAccounts. Any user with namespace `edit` permissions can impersonate the operator's ServiceAccount and inherit its full ClusterRole permissions. This bypasses all RBAC restrictions on the user, turning a namespace-scoped editor into a cluster-wide privileged actor.

**Scenario 3: Unused Permission Exploitation.** An operator's ClusterRole grants `create` on `clusterrolebindings` even though no code ever calls that API. An attacker with access to the SA token can use this unused permission to create a ClusterRoleBinding granting `cluster-admin` to an attacker-controlled ServiceAccount.

### 1.5 The Previous Approach and Its Limitations

The predecessor project (operator-security-runtime v1) addressed this problem by having operators manage their own RBAC at runtime. The operator created namespace-scoped Roles and RoleBindings tied to the CR lifecycle, using OwnerReferences for garbage collection.

This approach worked but conflated two distinct concerns:

1. **Operator-side concern.** "I need to handle the case where I don't have permissions."
2. **Admin-side concern.** "I need to scope what permissions this operator has."

By having the operator do both, the architecture had structural problems:

- **Self-modifying RBAC.** The operator needed the `escalate` verb (or `bind` verb) to manage its own permissions. A compromised SA could modify its own Roles, violating least privilege. The CNCF, Red Hat, NSA/CISA, and Kubernetes upstream documentation all warn against this pattern.
- **Broken trust boundary.** The producer and consumer of RBAC were the same entity. There was no independent authority validating or constraining the operator's permission grants.
- **Complexity burden on operator authors.** Operator authors had to understand RBAC lifecycle management, drift recovery, and garbage collection, responsibilities that belong to the platform layer, not the application layer.

Community feedback, including from former Operator-SDK and OLM contributors, consistently reinforced this: "Let the operator worry about attempting to do the tasks it was meant to do and design it to gracefully fail on permission errors. Let the owners/managers of the cluster be responsible for managing permissions."

---

## 2. Design Principles

### 2.1 Trust Domain Separation

The RBAC management authority should be a separate entity from the operators it manages, with a separate ServiceAccount. Compromising an operator should not compromise RBAC management. This is the core architectural change from v1. The standalone controller deployment achieves full separation. The embedded library deployment (section 5.2) trades some separation for deployment convenience; section 7.3.1 documents the reduced guarantees.

### 2.2 Operators Are RBAC Consumers, Not Producers

Operator-side components (the operator itself and the graceful degradation library) should never create, modify, or delete Roles, ClusterRoles, RoleBindings, or ClusterRoleBindings. They should not require the `escalate`, `bind`, or any RBAC write verbs. Operators consume permissions granted by external authorities. Admin-side components (the scoping controller, impersonation guard) operate in the admin trust domain and may manage RBAC resources as part of their designated function.

### 2.3 Graceful Degradation Over Fail-Fast

When an operator lacks permissions, it should degrade gracefully rather than crash. This means surfacing structured status conditions, emitting events, and retrying when permissions change. This is the pattern established by ArgoCD's `resource.respectRBAC` feature, generalized into a reusable library.

### 2.4 Cluster Admin Owns the Policy

The cluster administrator decides what permissions an operator receives. The tooling should make this easy (scoping controller, VAP templates, audit reports) but never override admin decisions. The admin can choose to deploy the scoping controller, manage RBAC through GitOps, or use OLM OperatorGroups. All paths are valid.

### 2.5 Defense in Depth

No single mechanism is sufficient. The toolkit provides independent, complementary layers that each reduce risk. Each layer can be deployed independently. The combination provides coverage that no individual mechanism achieves alone.

### 2.6 Zero Friction for Operator Authors

The graceful degradation library requires zero RBAC verbs, no webhooks, no CRDs, and no additional deployment dependencies. Operator authors `go get` the package and wire it into their reconciler. The admin-side components (scoping controller, VAPs, audit) are separate concerns with separate deployment paths.

---

## 3. Solution Architecture

### 3.1 Component Overview

The toolkit is split into three independent components, each with a clear owner:

```
Operator Author                       Cluster Admin
     |                                     |
     v                                     v
+---------------------------+   +--------------------------------+
|  Graceful Degradation     |   |  RBAC Scoping Controller       |
|  Library (pkg/graceful)   |   |  (pkg/scoper + cmd/scoper)     |
|                           |   |                                |
|  - Handle Forbidden       |   |  - Watch CRs                  |
|  - Surface status         |   |  - Create RoleBindings         |
|  - Report permissions     |   |  - Garbage collect on CR       |
|  - Emit events            |   |    deletion                    |
|                           |   |  - Standalone binary OR        |
|  Zero RBAC verbs needed   |   |    importable package          |
+---------------------------+   +--------------------------------+
                                |  Defense-in-Depth Toolkit       |
                                |                                |
                                |  - RBAC Audit (pkg/audit)      |
                                |  - SA Protection (webhook)     |
                                |  - Impersonation Guard         |
                                |  - VAP Templates               |
                                +--------------------------------+
```

### 3.2 Component Interaction Model

The three components are independent. They do not require each other to function:

- An operator can use the graceful degradation library without the scoping controller being deployed.
- The scoping controller can manage RBAC for operators that don't use the graceful degradation library.
- The defense-in-depth toolkit can be deployed without either of the other components.

When all three are deployed together, they provide complementary coverage:

1. The **scoping controller** ensures the operator only has permissions in namespaces with active CRs.
2. The **graceful degradation library** ensures the operator handles missing permissions cleanly during transitions (CR creation before RoleBinding provisioning, admin RBAC changes mid-reconcile).
3. The **defense-in-depth toolkit** provides additional protection layers (SA identity protection, impersonation hardening, permission auditing).

**Asymmetry note:** The graceful degradation library detects under-grants (operator lacks permissions it needs) but not over-grants (operator retains permissions it should no longer have, e.g., orphan RoleBindings during cross-namespace cleanup latency). Over-grant detection is the scoping controller's responsibility via its garbage collection mechanisms.

### 3.3 Alternatives Considered

| Approach | Pros | Cons | Decision |
|----------|------|------|----------|
| Operator self-manages RBAC (v1) | Zero-friction deployment, single binary | Violates trust domain separation, requires escalate/bind verbs, community consensus against it | Rejected as primary model; redesigned into separated components |
| Pure admission policies (VAPs/OPA) | No RBAC manipulation, uses existing K8s primitives | Admission policies do not intercept GET/LIST/WATCH requests; cannot restrict read access | Used as defense-in-depth complement, not primary mechanism |
| Authorization with Selectors (KEP-4601) | Works at authorization layer, intercepts all operations including reads | Adds latency to every API call, requires K8s 1.31+ (alpha), complex to implement | Future direction, not current dependency. See [KEP-4601](https://github.com/kubernetes/enhancements/issues/4601) |
| Kubectl plugin for static RBAC generation | Zero runtime components, admin-controlled | Does not dynamically adjust as CRs are created/deleted | Complementary tool, not primary mechanism |
| OLM OperatorGroups with scoped ServiceAccounts | Upstream-supported, admin-controlled | Only works with OLM-managed operators, does not handle dynamic namespace scoping | Supported as an alternative deployment model |

### 3.4 Coexistence with OLM and Helm RBAC

The scoping controller can coexist with OLM OperatorGroups and Helm-managed RBAC:

- **OLM OperatorGroups.** OLM creates RoleBindings for operators based on OperatorGroup configuration. The scoping controller creates independently-named RoleBindings (`<name>-scoped-binding`). Both can coexist; they manage different RoleBinding resources for the same SA. During migration, the OLM-managed bindings can be removed after the scoping controller is verified.
- **Helm RBAC.** Helm charts with `rbac.create: true` create static RBAC resources. The scoping controller's RoleBindings are additive. Set `rbac.create: false` in the Helm chart after migrating to scoped bindings if the chart's ClusterRoleBinding is the resource being replaced.

---

## 4. Component 1: Graceful Degradation Library

### 4.1 Purpose

The graceful degradation library (`pkg/graceful`) provides permission-aware error handling for Kubernetes operators. When an operator encounters a `Forbidden` error due to missing RBAC permissions, the library helps the operator degrade gracefully instead of failing hard.

No reusable library exists for this pattern today. ArgoCD built `resource.respectRBAC` internally. Prometheus Operator has ad-hoc error handling. Every operator reinvents permission error handling. This library fills that gap.

### 4.2 Core Capabilities

#### 4.2.1 Permission-Aware Error Handling

The library wraps controller-runtime client operations with permission-aware error handling. When a `Forbidden` error is returned:

1. The error is classified (missing verb, missing resource, missing namespace).
2. A structured `PermissionDenied` condition is set on the CR's status.
3. A Kubernetes event is emitted with the specific permission that is missing.
4. The reconciler returns a `RequeueAfter` result to retry when permissions may have changed.

```go
type MyReconciler struct {
    client.Client
    graceful *graceful.Handler
}

func NewMyReconciler(mgr ctrl.Manager) *MyReconciler {
    return &MyReconciler{
        Client:   mgr.GetClient(),
        graceful: graceful.NewHandler(mgr.GetEventRecorderFor("my-operator")),
    }
}

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
        return result, nil
    }

    // Permission was granted, proceed with secrets.Items
}
```

#### 4.2.2 Permission Discovery

At startup or on demand, the library performs `SelfSubjectAccessReview` checks to discover the operator's actual permissions. SSAR calls are rate-limited (default: 10 concurrent, configurable) to avoid overwhelming the API server during startup in clusters with many namespaces.

```go
report, err := graceful.DiscoverPermissions(ctx, client, graceful.PermissionSpec{
    Resources: []graceful.ResourceSpec{
        {Group: "", Resource: "secrets", Verbs: []string{"get", "list", "create"}},
        {Group: "", Resource: "configmaps", Verbs: []string{"get", "list"}},
    },
    Namespaces: []string{"notebooks", "model-registry"},
    MaxConcurrency: 10,
})

// report.Granted:  [{secrets, get, notebooks}, ...]
// report.Denied:   [{secrets, get, kube-system}, ...]
// report.Summary:  "8/10 permissions granted across 2 namespaces"
```

#### 4.2.3 Status Condition Management

The library manages structured status conditions on the CR that surface RBAC issues to users and monitoring systems:

| Condition Type | Status | Reason | Meaning |
|----------------|--------|--------|---------|
| `PermissionGranted` | `True` | `AllPermissionsAvailable` | All required permissions are available |
| `PermissionGranted` | `False` | `MissingPermissions` | One or more required permissions are denied |
| `Degraded` | `True` | `InsufficientRBAC` | Operator is running in degraded mode due to missing permissions |
| `Degraded` | `False` | `FullyOperational` | All permissions are available, operator is fully functional |

Status conditions follow the OpenShift conventions for operator status reporting (`Available`, `Progressing`, `Degraded`).

#### 4.2.4 Event Emission

The library emits Kubernetes events when permission changes are detected:

```
NAMESPACE   LAST SEEN   TYPE      REASON              OBJECT              MESSAGE
notebooks   2m          Warning   PermissionDenied    mycr/my-instance    Missing permission: list secrets in namespace "kube-system"
notebooks   1m          Normal    PermissionRestored  mycr/my-instance    Permission restored: list secrets in namespace "notebooks"
```

### 4.3 RBAC Requirements

The graceful degradation library requires zero RBAC write verbs. It needs:

| Permission | Purpose |
|------------|---------|
| `create` on `selfsubjectaccessreviews` | Permission discovery via SSAR (already granted to all authenticated SAs via `system:basic-user`; no explicit RBAC configuration needed) |
| `create` on `events` | Emitting permission-related events |
| `update` on the operator's CR status subresource | Setting status conditions |

The SSAR permission is granted to all authenticated service accounts by default. The events permission is standard. The third is a standard controller-runtime requirement.

### 4.4 Design Decisions

**Why SelfSubjectAccessReview instead of SelfSubjectRulesReview.** SSAR checks a specific permission (verb + resource + namespace) and returns a yes/no answer. SelfSubjectRulesReview returns all permissions for a namespace but is computationally expensive and can produce incomplete results (the API docs note that the result may be incomplete). SSAR is cheaper, more reliable, and sufficient for the use case.

**Why RequeueAfter instead of fail-fast.** When permissions are denied, the operator should retry because the admin may be in the process of updating RBAC. A hard failure forces the admin to manually restart the operator after fixing permissions. RequeueAfter lets the operator self-heal when permissions are restored. The default interval is 30 seconds, with configurable exponential backoff (30s, 60s, 120s, capped at 5 minutes) for repeated denials on the same permission. This balances recovery speed against API server load during prolonged permission gaps.

**Why structured conditions instead of log-only.** Logs are not observable by cluster monitoring systems. Status conditions are queryable via the Kubernetes API, can trigger alerts, and are visible in the OpenShift console. This aligns with the operator framework's status condition conventions.

**Why not wrap the controller-runtime client globally.** A global wrapper would intercept every API call, including those that should fail hard (e.g., getting the CR itself). The library provides explicit wrapping for operations that may be subject to admin-scoped RBAC, leaving the operator author in control of which operations degrade gracefully.

---

## 5. Component 2: RBAC Scoping Controller

### 5.1 Purpose

The RBAC Scoping Controller (`pkg/scoper`) is an admin-side component that dynamically manages namespace-scoped RoleBindings for target operator ServiceAccounts. When a Custom Resource appears in a namespace, the controller creates a RoleBinding granting the operator's SA access in that namespace. When the CR is deleted, the RoleBinding is cleaned up.

The controller runs with its own ServiceAccount, separate from the operators it manages. This is the core trust domain separation: compromising an operator's SA does not compromise RBAC management.

### 5.2 Delivery Options

The scoping controller is available as:

1. **Standalone binary** (`cmd/scoper`). Cluster admins deploy it as a separate Deployment with leader election enabled (recommended: 2 replicas). Suitable for clusters without an existing platform operator.
2. **Importable Go package** (`pkg/scoper`). Platform operators (e.g., the RHOAI operator, which already reconciles DSC/DSCI) embed the scoping logic into their existing reconciliation loop. Zero additional deployment friction. The embedded library inherits the host operator's leader election and HA configuration.

Both options use the same `pkg/scoper` library. The standalone binary is a thin wrapper that reads configuration from a ConfigMap and starts the controller.

**Security note on embedded mode:** When the scoping controller is embedded in a platform operator, it shares that operator's ServiceAccount. This collapses the trust domain separation (see section 7.3.1). The embedded mode trades trust domain separation for deployment convenience. Use the standalone binary when full trust domain separation is required.

### 5.3 How It Works

#### 5.3.1 Configuration

The controller is configured with a list of **scoping targets**, each specifying:

```go
type ScopingTarget struct {
    // The GVK of the Custom Resource to watch.
    // When a CR of this GVK appears in a namespace, a RoleBinding is created.
    WatchGVK schema.GroupVersionKind

    // The ServiceAccount to grant access to.
    TargetSA types.NamespacedName

    // The ClusterRole to reference in the RoleBinding.
    // This ClusterRole must be pre-deployed by the admin and MUST NOT
    // use aggregationRule (see section 5.4).
    ClusterRoleName string

    // The name to use for managed RoleBindings.
    // Deterministic naming enables drift detection and cleanup.
    ManagedRoleBindingName string

    // Optional: restrict which namespaces are watched.
    // If nil, all namespaces are watched. Required for multi-tenant clusters.
    NamespaceSelector *metav1.LabelSelector

    // Optional: create the RoleBinding in a different namespace than the CR.
    // If nil, the RoleBinding is created in the CR's namespace.
    // The target namespace is read from the specified field in the CR.
    // WARNING: This field value is untrusted input. The controller validates
    // it against NamespaceSelector and the deny-list before creating
    // RoleBindings. See section 5.3.5 for details.
    TargetNamespaceSource *NamespaceSource
}
```

For the standalone binary, this configuration is provided via a ConfigMap. The controller reads this ConfigMap at startup and **requires a restart** to pick up changes (hot-reload is not supported to avoid complexity in a security-critical component). The ConfigMap must reside in a privileged admin namespace with restricted access.

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
    - watchGVK:
        group: dashboard.opendatahub.io
        version: v1alpha1
        kind: OdhDashboardConfig
      targetSA:
        name: odh-dashboard
        namespace: redhat-ods-applications
      clusterRoleName: odh-dashboard-notebooks
      managedRoleBindingName: odh-dashboard-notebooks-binding
      targetNamespaceSource:
        fieldPath: ".spec.notebookController.notebookNamespace"
```

**Startup behavior:**
- If the ConfigMap is malformed, the controller fails fast at startup with a descriptive error. It does not start with empty configuration.
- If a referenced ClusterRole does not exist, the controller logs a warning and emits a Kubernetes event but continues to process other targets. RoleBindings referencing non-existent ClusterRoles are not created; the condition is re-checked on each reconciliation.
- If a configured GVK's CRD is not yet installed, the controller logs a warning and skips that target. The controller must be restarted after the CRD becomes available. Deploy the scoping controller after the target CRDs are installed (e.g., in the same Helm release or Kustomize overlay) to avoid this scenario.

#### 5.3.2 CR Lifecycle Flow

```
CR Created in namespace "foo"
    |
    v
Controller detects CR via watch
    |
    v
Does namespace "foo" match NamespaceSelector? (if configured)
    |
    +-- No --> No-op (namespace not in scope)
    +-- Yes (or no selector configured) -->
        |
        v
    Does the referenced ClusterRole exist?
        |
        +-- No --> Log warning, emit event, requeue
        +-- Yes -->
            |
            v
        Does RoleBinding "odh-dashboard-scoped-binding" exist in "foo"?
            |
            +-- No --> Create RoleBinding referencing static ClusterRole
            |          with OwnerReference pointing to the CR
            |
            +-- Yes --> Check if OwnerReference for this CR exists
                            |
                            +-- No --> Patch to add OwnerReference
                            +-- Yes --> No-op (DeepEqual skip)

CR Deleted in namespace "foo"
    |
    v
OwnerReference GC removes the CR from the RoleBinding's OwnerReferences
    |
    v
Are there remaining OwnerReferences?
    |
    +-- Yes --> RoleBinding persists (other CRs still need it)
    +-- No --> Kubernetes GC deletes the RoleBinding
```

#### 5.3.3 Multi-CR Ownership

Multiple CRs of the same or different GVKs can exist in the same namespace. The controller uses Kubernetes OwnerReferences to track which CRs require the RoleBinding. The RoleBinding is only deleted when no CRs remain in the namespace. OwnerReference updates use `patch` (strategic merge patch) to avoid conflicts with concurrent modifications.

#### 5.3.4 Cross-Namespace Grants

When an operator needs access to a namespace different from where its CR exists (e.g., the Dashboard CR is in `redhat-ods-applications` but needs access to `rhods-notebooks`), the controller supports cross-namespace targets via `TargetNamespaceSource`.

For cross-namespace RoleBindings, OwnerReferences cannot be used (Kubernetes does not allow cross-namespace OwnerReferences). The controller uses annotation-based ownership instead:

- Annotation key: `operator-rbac-toolkit.io/scoped-access-owners`
- Annotation value: comma-separated list of `namespace/name/uid` entries
- Kubernetes limits the total size of all annotations on an object to 256KB. The ownership annotation shares this budget with other annotations (e.g., `last-applied-configuration`, controller-runtime annotations). At ~60 bytes per entry and assuming a few KB of other annotations, this practically supports thousands of owner entries, well beyond any realistic scenario.
- Concurrent updates: handled via optimistic concurrency with retry-on-conflict (standard controller-runtime pattern).
- Malformed entries: skipped during parsing, not fatal. A warning is logged for each skipped entry.

#### 5.3.5 Cross-Namespace Input Validation

The `TargetNamespaceSource` field reads a namespace name from a CR field. This is untrusted input: a user who can create or modify the CR can set this field to any namespace (e.g., `kube-system`). The controller validates the target namespace before creating a RoleBinding:

1. **Deny-list check.** The target namespace is checked against a built-in deny-list. The default deny-list includes specific namespaces (`kube-system`, `kube-public`, `kube-node-lease`, `default`) and prefix patterns (`openshift-*` for OpenShift clusters). The deny-list also includes the scoping controller's own namespace (configurable, defaults to `rbac-scoper-system`). The deny-list is configurable to add platform-specific entries. This is enforced in the controller itself, independent of VAPs.
2. **NamespaceSelector check.** If a `NamespaceSelector` is configured on the target, the target namespace must match it.
3. **VAP enforcement.** The `deny-rolebinding-in-protected-namespaces` and `allow-rolebinding-in-labeled-namespaces` VAPs provide API-server-enforced validation as defense-in-depth.

### 5.4 Static ClusterRole Requirement

The scoping controller uses **bind mode only**. It creates RoleBindings that reference a pre-deployed static ClusterRole. It never creates or modifies Roles or ClusterRoles.

The static ClusterRole defines the permission ceiling. It must be deployed by the cluster admin as part of the operator's installation manifests (Helm chart, OLM CSV, Kustomize, or GitOps).

**Requirements for the static ClusterRole:**

1. **MUST NOT use `aggregationRule`.** If the ClusterRole uses aggregation, an attacker could inject additional rules by creating a ClusterRole with labels matching the aggregation selector, bypassing the static permission ceiling without modifying the ClusterRole directly. The scoping controller validates this at startup and refuses to reference an aggregated ClusterRole.
2. **Should be protected by the `protect-static-clusterrole` VAP** to prevent runtime modification.

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: odh-dashboard-scoped
  # No aggregationRule field
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get", "create", "update"]
  - apiGroups: [""]
    resources: ["configmaps"]
    verbs: ["get", "create", "update"]
  - apiGroups: [""]
    resources: ["persistentvolumeclaims"]
    verbs: ["create", "get"]
```

The permission ceiling is enforced by Kubernetes RBAC itself (the static ClusterRole is not modifiable by the operator or the scoping controller). A compromised operator SA can only use permissions defined in this ClusterRole, and only in namespaces where RoleBindings exist.

### 5.5 RBAC Requirements for the Scoping Controller

The scoping controller's ServiceAccount needs:

| Permission | Purpose |
|------------|---------|
| `get`, `list`, `watch` on target CRDs | Detecting CR creation and deletion |
| `get`, `list`, `watch`, `create`, `update`, `patch`, `delete` on `rolebindings` | Managing namespace-scoped RoleBindings (list/watch for cleanup and drift detection, patch for OwnerReference updates) |
| `bind` on the static ClusterRole (via `resourceNames`) | Creating RoleBindings that reference the static ClusterRole |
| `get` on `clusterroles` (via `resourceNames`) | Startup validation of static ClusterRole (no aggregationRule) |
| `get`, `list`, `watch` on `namespaces` | Namespace label watching (required when `NamespaceSelector` is configured) |

The `bind` verb is scoped to specific ClusterRole names via `resourceNames`, preventing the controller from binding arbitrary ClusterRoles.

The controller does NOT need:
- `escalate` verb
- `create`, `update`, or `delete` on `roles` or `clusterroles`
- Any permissions on secrets, configmaps, or other application resources

### 5.6 Drift Recovery

If a managed RoleBinding is deleted externally (by an admin, a GitOps tool, or a misconfigured cleanup process), the controller detects the absence on the next reconciliation cycle and recreates it. This is standard controller-runtime reconciliation behavior.

If a managed RoleBinding is modified externally (e.g., the ClusterRole reference is changed), the controller detects the drift via DeepEqual comparison and corrects it.

### 5.7 Garbage Collection

#### 5.7.1 Same-Namespace CRs

For CRs in the same namespace as the RoleBinding, Kubernetes OwnerReference garbage collection handles cleanup automatically. When the last CR with an OwnerReference on the RoleBinding is deleted, the RoleBinding is garbage collected.

#### 5.7.2 Cross-Namespace CRs

For cross-namespace RoleBindings (where the RoleBinding is in a different namespace than the CR), annotation-based ownership is used. The controller runs a cleanup reconciler that:

1. Lists all managed RoleBindings (identified by the deterministic name).
2. For each RoleBinding, parses the owner annotations.
3. For each owner entry, checks if the referenced CR still exists, if the CR's GVK matches a configured scoping target, and (for `TargetNamespaceSource` targets) if the CR's target namespace field still resolves to the namespace where this RoleBinding exists. An entry is treated as stale and removed if the CR no longer exists, if the GVK does not match any configured target, or if the CR's target namespace field has changed to point elsewhere.
4. Removes stale owner entries.
5. If no owners remain, deletes the RoleBinding.

This cleanup runs on a configurable interval (default: 5 minutes) and on every CR deletion event.

#### 5.7.3 Orphan Detection

On startup, the controller scans for managed RoleBindings whose owner CRs no longer exist. These orphans are cleaned up immediately. This handles the case where the controller was down when CRs were deleted.

#### 5.7.4 Namespace Deletion

When a namespace is deleted, Kubernetes terminates all resources in it concurrently. For same-namespace RoleBindings, both the CR and the RoleBinding are deleted as part of namespace termination; no action is needed. For cross-namespace RoleBindings, the CR in the deleted namespace triggers the cleanup reconciler. If the controller cannot read the CR (namespace already gone), it treats the owner entry as stale and removes it on the next periodic scan.

### 5.8 Namespace Label Watch

When a `NamespaceSelector` is configured, the scoping controller watches namespace label changes in addition to CR events. If a namespace label is removed such that the namespace no longer matches the `NamespaceSelector`, the controller deletes managed RoleBindings in that namespace. This ensures that admin actions to de-authorize a namespace take effect without manual RoleBinding cleanup.

The namespace label watch is implemented via a standard controller-runtime watch on Namespace resources with a label predicate matching the selector. The watch is only registered when `NamespaceSelector` is configured.

### 5.9 Multi-Tenancy

In multi-tenant clusters, the `NamespaceSelector` field on `ScopingTarget` restricts which namespaces the controller watches. Without a namespace selector, the controller watches all namespaces and creates RoleBindings for any CR of the configured GVK, which could cross tenant boundaries.

Recommended multi-tenant deployment:
- Configure `NamespaceSelector` with a tenant-specific label (e.g., `tenant: team-a`).
- Use the `allow-rolebinding-in-labeled-namespaces` VAP to enforce that RoleBindings are only created in labeled namespaces.
- Use the `protect-rbac-allowed-label` VAP to prevent non-admin label manipulation.
- Alternatively, deploy separate scoping controller instances per tenant.

### 5.10 CRD Version Changes

The scoping controller watches CRs by GVK. If the CRD is upgraded from v1alpha1 to v1beta1 or v1, the controller's configuration must be updated to reflect the new version. The controller does not automatically follow CRD version promotions.

When the CRD storage version changes:
1. Update the scoping controller's ConfigMap with the new GVK version.
2. Restart the controller.
3. Existing RoleBindings are preserved. The controller will re-reconcile them against the new GVK.

### 5.11 Day-2 Operator Upgrades

When the operator being scoped is upgraded and requires new permissions (e.g., a new feature needs `create` on `persistentvolumeclaims`), the upgrade workflow is:

1. **Update the static ClusterRole** to include the new rules. This must happen before the new operator version rolls out, or the operator will get `Forbidden` errors (which the graceful degradation library will surface as status conditions).
2. **Update the scoping controller configuration** if the GVK or namespace selector changed.
3. **Roll the new operator version.**

If step 1 is applied after step 3 (out-of-order), the graceful degradation library surfaces `Degraded` status conditions until the ClusterRole is updated. No data loss or corruption occurs; the operator simply cannot perform the new operations until permissions are granted.

### 5.12 Design Decisions

**Why bind mode only (no escalate mode).** The `escalate` verb allows creating Roles with rules that exceed the creator's own permissions, which is flagged as a privilege escalation risk by every security guide. Without `escalate`, a controller can only create Roles whose rules are a subset of its own permissions. Bind mode uses the `bind` verb scoped via `resourceNames`, which only allows referencing specific pre-deployed ClusterRoles. The permission ceiling is enforced by Kubernetes RBAC, not by application code. This is architecturally safer and passes SOC2/FedRAMP audits without exceptions.

**Why the controller manages RoleBindings but not Roles.** Using a pre-deployed static ClusterRole means the controller only needs the `bind` verb (scoped to specific ClusterRole names), not the `escalate` verb. The ClusterRole defines rules once; RoleBindings activate those rules in specific namespaces.

**Why OwnerReferences for same-namespace, annotations for cross-namespace.** Kubernetes does not support cross-namespace OwnerReferences. Annotations provide the same ownership semantics without requiring a custom finalizer on every CR. The annotation format is designed for corruption resilience: malformed entries are skipped, not fatal.

**Why a ConfigMap for standalone configuration, not a CRD.** A ConfigMap is simpler, requires no webhook or controller for validation, and avoids the bootstrapping problem of a CRD-based controller that needs permissions to watch its own CRD. For the importable package, configuration is programmatic and validated at construction time. The ConfigMap must be in an admin-controlled namespace; a `protect-scoper-config` VAP template is provided to restrict write access.

**Why no hot-reload.** Configuration changes to the scoping controller affect which RoleBindings exist and where. Hot-reloading introduces failure modes (partial config application, race between old and new targets) that are unacceptable in a security-critical component. A controller restart is a well-understood, atomic configuration transition.

---

## 6. Component 3: Defense-in-Depth Toolkit

### 6.1 Overview

The Defense-in-Depth Toolkit provides independent security mechanisms that complement the scoping controller and graceful degradation library. Each mechanism can be deployed independently. Admin-side components (impersonation guard) manage RBAC resources as part of their designated function in the admin trust domain (see design principle 2.2).

### 6.2 RBAC Audit (`pkg/audit`)

#### 6.2.1 Purpose

The RBAC audit package scans the cluster at startup to identify RBAC exposure risks. It produces structured findings that operators can surface via logs, events, or status conditions.

#### 6.2.2 Scan Categories

| Category | Severity | What It Detects |
|----------|----------|----------------|
| Impersonation grants | Critical | Any Role/ClusterRole granting `impersonate` on ServiceAccounts |
| TokenRequest exposure | Critical | Any Role/ClusterRole granting `create` on `serviceaccounts/token` |
| Aggregate-to-edit status | Warning | Whether `system:aggregate-to-edit` still includes the `impersonate` verb |
| Unused permissions | Info | Permissions in the SA's ClusterRole that do not match any API call pattern |
| Aggregation rules | Warning | Whether the static ClusterRole uses `aggregationRule` (see section 5.4) |

#### 6.2.3 Integration

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

### 6.3 SA Identity Protection (`pkg/saprotection`)

#### 6.3.1 Purpose

A ValidatingWebhook that prevents unauthorized use of an operator's ServiceAccount identity. It intercepts Pod `CREATE` and `UPDATE` requests and validates that only the operator's own workloads can use its ServiceAccount.

#### 6.3.2 Problem Addressed

Without SA protection, any user with `create pods` permission in the operator's namespace can create a pod that mounts the operator's ServiceAccount token. That pod then inherits the operator's full RBAC permissions. This is a privilege escalation path that bypasses RBAC restrictions on the user.

#### 6.3.3 Core Logic

```
Pod CREATE/UPDATE received
    |
    v
Is the pod using a protected ServiceAccount?
    |
    +-- No --> Allow
    +-- Yes --> Is the requesting user in the allowed-identities list?
                    |
                    +-- Yes --> Allow
                    +-- No --> Deny ("ServiceAccount is protected")
```

The allowed-identities list is configured at webhook registration time. It must include both the operator's own controller ServiceAccount and the Kubernetes system controllers that create Pods on the operator's behalf (e.g., `system:serviceaccount:kube-system:replicaset-controller` for Deployments, `system:serviceaccount:kube-system:job-controller` for Jobs). The webhook matches the `userInfo.username` field from the admission request against this list.

**System controller tradeoff:** Including system controllers in the allowed-identities list means any Deployment or Job in the operator's namespace can reference the protected SA. The webhook prevents direct Pod creation with the SA but does not prevent indirect creation via higher-level controllers. Compensating control: restrict `create` on Deployments, StatefulSets, and Jobs in the operator's namespace to authorized principals only.

The webhook uses namespace selectors to scope enforcement to the operator's namespace, avoiding cluster-wide webhook overhead.

#### 6.3.4 Design Decisions

**Name-only SA matching.** The webhook matches ServiceAccount names, not UIDs. This avoids the bootstrapping problem where the webhook needs to know the SA UID before the SA exists. Name-based matching is sufficient because SA names are unique within a namespace.

**Fail-secure with availability tradeoff.** If the webhook encounters an error evaluating a request, it denies the request (`failurePolicy: Fail`). This prevents attackers from exploiting webhook failures to bypass protection. However, if the webhook pod is down, all pod creation in the scoped namespace is blocked. To mitigate this, deploy the webhook in a separate namespace from the operator it protects, use a PriorityClass to ensure scheduling priority, and configure PodDisruptionBudgets.

**Update short-circuit.** Pod updates that do not change the ServiceAccount field are allowed without further validation. This avoids false positives from kubelet status updates and readiness probes.

#### 6.3.5 Limitations

**Ephemeral containers.** The `pods/ephemeralcontainers` subresource (used by `kubectl debug`) allows attaching a debug container to an existing pod. The debug container inherits the pod's ServiceAccount. This subresource does not trigger the SA protection webhook's Pod CREATE/UPDATE path. Mitigation: restrict `pods/ephemeralcontainers` access in the operator's namespace via RBAC. A VAP template (`restrict-ephemeral-containers-on-protected-pods`) is provided to restrict who can create ephemeral containers on pods using protected ServiceAccounts.

**TokenRequest API.** Any entity with `create` on `serviceaccounts/token` can mint new tokens for any SA, bypassing SA identity protection entirely. The RBAC audit component detects this exposure at startup. Mitigation requires the admin to restrict `serviceaccounts/token` access separately.

### 6.4 Impersonation Guard (`pkg/impersonation`)

#### 6.4.1 Purpose

A reconciler that closes the impersonation bypass in Kubernetes RBAC. The default `system:aggregate-to-edit` ClusterRole includes the `impersonate` verb for ServiceAccounts. This allows any namespace editor to impersonate any ServiceAccount in their namespace, inheriting that SA's full permissions.

#### 6.4.2 Approach

`system:aggregate-to-edit` is an aggregated ClusterRole. Its `rules` field is computed by the Kubernetes aggregation controller from component ClusterRoles matching the `rbac.authorization.kubernetes.io/aggregate-to-edit: "true"` label selector. The `impersonate` verb comes from one of these component ClusterRoles.

The impersonation guard takes a three-part approach:

1. **Component ClusterRole modification.** Identifies the component ClusterRole that contributes the `impersonate` verb for ServiceAccounts (the one with the `aggregate-to-edit` label) and removes the `impersonate` verb from it. This causes the aggregation controller to recompute `system:aggregate-to-edit` without the verb.
2. **Autoupdate annotation.** Sets `rbac.authorization.kubernetes.io/autoupdate: "false"` on the component ClusterRole to prevent the RBAC bootstrap reconciliation controller (which runs on API server startup) from resetting it to defaults.
3. **Continuous reconciliation.** Watches for drift and re-applies the fix. During Kubernetes upgrades, the bootstrap reconciliation may reset the component ClusterRole; the guard detects and corrects this.

The guard does NOT directly modify the `rules` field of `system:aggregate-to-edit` itself, as the aggregation controller would immediately overwrite any such change. Instead, it modifies the source (the component ClusterRole) so the aggregation controller computes the desired result.

This component operates in the admin trust domain and requires write access to RBAC ClusterRole resources, which is consistent with design principle 2.2 (admin-side components may manage RBAC resources).

#### 6.4.3 Why Webhooks Cannot Solve This

Impersonation headers (`Impersonate-User`, `Impersonate-Group`) are resolved during the authentication phase, and the authorization check for the `impersonate` verb happens at the authorization layer. Both occur before the request reaches the admission chain. By the time a ValidatingWebhook sees a Pod CREATE request, the caller's identity has already been swapped to the impersonated identity. The webhook cannot distinguish an impersonated request from a direct one, and cannot block the impersonation itself.

#### 6.4.4 Startup Race Window

Between the impersonation guard starting and completing its first reconciliation, the `impersonate` verb may be active in the component ClusterRole (and therefore in the aggregated `system:aggregate-to-edit`). This window is typically sub-second but is unbounded if the guard pod is pending (e.g., due to resource pressure). Mitigations:

- Deploy the impersonation guard with a high PriorityClass to ensure it schedules before operator workloads.
- Deploy the companion VAP (deny-impersonate-grants) which blocks attempts to re-add the `impersonate` verb via UPDATE operations on ClusterRoles. The VAP prevents re-addition after the guard removes the verb, but does not help during the initial startup window when the verb is already present in the component ClusterRole.
- Monitor for the `impersonate` verb via the RBAC audit component and alert if detected.

Note: during Kubernetes version upgrades, the API server's built-in role reconciliation may reset the component ClusterRole. The guard's continuous reconciliation detects and corrects this, but there is a brief window. The companion VAP prevents external actors from re-adding the verb during this window, but the API server's own bootstrap reconciliation is not subject to admission policies.

#### 6.4.5 Future: KEP-5284 Constrained Impersonation

[KEP-5284](https://github.com/kubernetes/enhancements/issues/5284) (Constrained Impersonation) restricts impersonation so that "an impersonating user cannot perform actions they themselves are not allowed to do." Target timeline should be verified against the current KEP status. When this KEP reaches GA, the impersonation guard becomes less critical but remains valuable as a belt-and-suspenders measure.

### 6.5 ValidatingAdmissionPolicy Templates

The toolkit provides VAP templates for cluster admins to deploy. These enforce RBAC invariants at the API server level, providing guarantees that a compromised SA cannot bypass.

| Template | Purpose | What It Prevents |
|----------|---------|-----------------|
| `deny-impersonate-grants.yaml` | Block impersonation privilege grants in any Role/ClusterRole | Impersonation bypass |
| `restrict-scoped-rolebinding-creation.yaml` | Only the scoping controller's SA can create managed RoleBindings | Unauthorized RoleBinding creation by compromised operator |
| `restrict-scoped-rolebinding-mutation.yaml` | Only the scoping controller's SA can update or delete managed RoleBindings | Unauthorized RoleBinding modification or deletion |
| `restrict-scoped-rolebinding-subjects.yaml` | Managed RoleBindings can only reference the target operator's SA | Subject manipulation to grant access to attacker-controlled SA |
| `deny-rolebinding-in-protected-namespaces.yaml` | Default deny-list for sensitive namespaces (kube-system, kube-public, etc.) | RoleBinding creation in system namespaces |
| `allow-rolebinding-in-labeled-namespaces.yaml` | Only admin-labeled namespaces can receive managed RoleBindings | RoleBinding creation in unauthorized namespaces |
| `protect-rbac-allowed-label.yaml` | Prevents non-admin label manipulation on namespaces | Label spoofing to bypass namespace restrictions |
| `protect-vap-enforcement-labels.yaml` | Prevents non-admin manipulation of labels used by VAP binding namespaceSelectors | Disabling VAP enforcement by removing enforcement labels |
| `protect-static-clusterrole.yaml` | Prevents modification of the static ClusterRole | Permission ceiling tampering |
| `deny-aggregated-static-clusterrole.yaml` | Blocks attempts to add an `aggregationRule` field to the static ClusterRole (defense-in-depth alongside `protect-static-clusterrole`) | Aggregation-based permission injection via ClusterRole modification |
| `protect-scoper-config.yaml` | Restricts write access to the scoping controller's ConfigMap | Configuration tampering |
| `restrict-ephemeral-containers-on-protected-pods.yaml` | Restricts who can create ephemeral containers on pods using protected SAs | SA token access via kubectl debug |

VAP templates are provided as YAML files in `config/vap/`. Cluster admins deploy them via Kustomize, Helm, or GitOps. Each template includes inline documentation explaining what it protects and how to configure it.

---

## 7. Threat Model

### 7.1 Assumptions

1. The Kubernetes API server is trusted and correctly enforces RBAC.
2. Node-level integrity is assumed. Container escapes to the node filesystem are out of scope (a compromised node can access all projected SA tokens for pods on that node, bypassing all API-level protections). Mitigation: use `automountServiceAccountToken: false` with explicit projected volumes using short-lived, audience-restricted bound tokens.
3. The static ClusterRole is deployed by the admin, does not use `aggregationRule`, and is protected by the `protect-static-clusterrole` VAP.
4. VAP templates are deployed by the admin and enforce invariants at the API server level.
5. **For standalone deployment:** the scoping controller's ServiceAccount is separate from the operator's ServiceAccount. For embedded deployment, see section 7.3.1.
6. Migration from legacy ClusterRoleBindings is complete (legacy ClusterRoleBindings have been removed). Before migration is complete, the scoping controller provides additive RoleBindings but does not reduce existing cluster-wide access.

### 7.2 Attack Chain Analysis

All residual risk assessments assume VAP integrity (see section 13.4 for VAP self-protection limitations).

| # | Attack Vector | Mitigated By | Residual Risk |
|---|---------------|-------------|---------------|
| 1 | **Compromised operator SA token reads secrets in kube-system** | Scoping controller (no RoleBinding in kube-system). Operator SA has no RBAC write verbs by design. | Bounded: requires scoping controller deployed AND legacy ClusterRoleBinding removed (assumption 6). Scoping controller availability and compromise risks per #8. |
| 2 | **Attacker creates pod with operator's SA in operator namespace** | SA protection webhook (denies unauthorized SA usage) | Webhook unavailability blocks all pod creation in scoped namespace. Deploy webhook in separate namespace with PriorityClass. |
| 3 | **Namespace editor impersonates operator's SA** | Impersonation guard (modifies component ClusterRole to remove impersonate verb) + deny-impersonate-grants VAP | Brief race window during guard startup or K8s upgrades. VAP prevents re-addition but does not help during initial startup when the verb already exists. |
| 4 | **Compromised operator SA creates RoleBinding in kube-system** | Operator SA has no RBAC write verbs by design (architectural prevention). VAPs provide defense-in-depth. | Mitigated by design. The operator SA cannot create RoleBindings. |
| 5 | **Compromised operator SA modifies static ClusterRole to add rules** | protect-static-clusterrole VAP + operator SA has no write verbs on ClusterRoles | Residual: VAP integrity (section 13.4). Does not cover aggregation-based injection (see #12). |
| 6 | **Attacker modifies managed RoleBinding to change subject** | restrict-scoped-rolebinding-subjects VAP + restrict-scoped-rolebinding-mutation VAP + scoping controller drift recovery | Residual: VAP integrity (section 13.4) |
| 7 | **Attacker labels namespace to allow RoleBinding creation** | protect-rbac-allowed-label VAP + protect-vap-enforcement-labels VAP | Admin compromise or VAP integrity compromise (section 13.4) |
| 8 | **Scoping controller SA is compromised (standalone)** | Controller SA only has bind on specific ClusterRoles (resourceNames). Cannot create arbitrary bindings. VAPs still enforce invariants. | Attacker can create RoleBindings in any namespace for the scoped ClusterRoles. Can forge annotation ownership to persist RoleBindings past cleanup (see 13.7). |
| 9 | **TokenRequest API used to mint SA token** | RBAC audit detects tokenrequest exposure at startup | Requires separate RBAC restriction on serviceaccounts/token |
| 10 | **Operator continues using existing broad ClusterRoleBinding** | Migration guide, RBAC audit warns about ClusterRoleBindings | Requires admin action to remove legacy bindings |
| 11 | **Attacker sets CR field to target kube-system via TargetNamespaceSource** | Controller-side deny-list (including openshift-* prefixes) + NamespaceSelector validation + deny-rolebinding-in-protected-namespaces VAP | Bounded: requires controller validation AND VAP. Deny-list must cover platform-specific namespaces. |
| 12 | **Attacker injects rules into static ClusterRole via aggregation** | Static ClusterRole MUST NOT use aggregationRule (validated at startup) + deny-aggregated-static-clusterrole VAP | Startup-only check. If ClusterRole is modified post-startup (protect-static-clusterrole VAP bypassed), aggregation may not be re-checked until restart. |
| 13 | **Attacker uses kubectl debug to access operator SA token** | restrict-ephemeral-containers-on-protected-pods VAP | Residual: VAP integrity (section 13.4) |
| 14 | **Any user with CR create permission triggers RoleBinding creation** | NamespaceSelector limits where RoleBindings are created. CRD-level RBAC restricts who can create watched CRs. | By design: CR creation triggers scoping. Restrict CRD create access to authorized users via standard RBAC. |
| 15 | **Namespace label removed after RoleBinding creation** | Scoping controller watches namespace label changes and revokes RoleBindings when namespace no longer matches NamespaceSelector | Brief window between label removal and next reconciliation cycle. See section 13.6. |

### 7.3 Trust Boundaries (Standalone Deployment)

```
+------------------------------------------+
|          Cluster Admin Trust Domain       |
|                                          |
|  - Static ClusterRole (defines ceiling)  |
|  - Scoping Controller SA                 |
|  - VAP Templates                         |
|  - Impersonation Guard                   |
+------------------------------------------+
          |
          | Creates/manages RoleBindings
          v
+------------------------------------------+
|          Operator Trust Domain            |
|                                          |
|  - Operator SA (RBAC consumer)           |
|  - Graceful Degradation Library          |
|  - Application logic                     |
+------------------------------------------+
```

A compromise in the operator trust domain cannot escalate into the admin trust domain because:
- The operator SA has no RBAC write verbs.
- The operator SA cannot modify the static ClusterRole (VAP enforced).
- The operator SA cannot create or delete RoleBindings (VAP enforced).
- The operator SA cannot modify the scoping controller's SA permissions.

#### 7.3.1 Trust Boundaries (Embedded Deployment)

When the scoping controller is embedded in a platform operator, the trust boundary is collapsed:

```
+------------------------------------------+
|   Platform Operator Trust Domain          |
|   (combines admin and operator concerns)  |
|                                          |
|  - Platform SA (shared)                  |
|  - Scoping logic (bind verb)             |
|  - Application logic                     |
+------------------------------------------+
```

In this mode, compromising the platform operator SA grants the attacker both operator capabilities AND the `bind` verb for scoped ClusterRoles. The attacker can create RoleBindings in any namespace (bounded by namespace selector and VAPs).

**What is preserved in embedded mode:**
- VAP enforcement still holds (API-server-level, independent of SA compromise).
- The static ClusterRole ceiling still holds.
- The operator SA has no `escalate` verb, so it cannot create Roles with arbitrary rules.

**What is lost in embedded mode:**
- Trust domain separation. A single SA compromise grants both operator and RBAC management capabilities.
- Attack chain #8 applies to the combined SA, increasing the blast radius of a compromise.

**Recommendation:** Use embedded mode when the platform operator is already highly privileged (e.g., RHOAI operator with cluster-admin-like permissions) and adding the scoping logic does not meaningfully increase its blast radius. Use standalone mode for operators where trust domain separation is a compliance requirement.

### 7.4 Blast Radius Quantification

Blast radius is measured by counting accessible resources before and after scoping:

**Measurement methodology:**
1. Mint a token for the operator's SA using `kubectl create token <sa-name> -n <namespace>`.
2. Attempt to list secrets in every namespace using `kubectl get secrets --all-namespaces --token=<token>`.
3. Count the namespaces where the request succeeds and the total secrets accessible.

**Example measurement (RHOAI Dashboard):**

| Scenario | Namespaces with secret access | Total secrets accessible |
|----------|-------------------------------|------------------------|
| ClusterRoleBinding (before) | All namespaces (including kube-system) | 43 in kube-system + all others |
| Namespace-scoped RoleBindings (after) | Only namespaces with active CRs | 5 in the CR namespace |

The reduction is not a percentage (which varies by cluster size) but an absolute confinement: access exists only where CRs exist. Kubernetes evaluates RBAC against current bindings on every API request, so removing the ClusterRoleBinding and adding namespace-scoped RoleBindings takes effect immediately for all existing tokens. No token rotation is required.

---

## 8. Key Architectural Tradeoffs

### 8.1 Separate Controller vs. Embedded Library

| Concern | Separate Controller (standalone binary) | Embedded Library (imported by platform operator) |
|---------|----------------------------------------|--------------------------------------------------|
| Deployment friction | Additional Deployment to install | Zero additional friction (code import) |
| Trust domain | Full separation (separate SA) | Collapsed (shared with platform operator's SA, see 7.3.1) |
| Upgrade path | Independent release cycle | Coupled to platform operator releases |
| HA | Leader election with 2 replicas | Inherits host operator's HA |
| Best for | Compliance-sensitive, multi-tenant, or untrusted operator environments | Clusters with an existing platform operator (e.g., RHOAI) where the platform operator is already highly privileged |

Both options use the same `pkg/scoper` library. The tradeoff is deployment model and security posture, not implementation.

### 8.2 Annotation-Based vs. Finalizer-Based Cross-Namespace GC

| Concern | Annotations | Finalizers |
|---------|-------------|------------|
| Deletion latency | Requires periodic scan | Immediate on CR deletion |
| Failure mode | Orphan persists until next scan (over-grant) | Stuck CR if controller is down (blocks namespace deletion) |
| Operational risk | Low (temporary over-grant) | High (stuck finalizer blocks namespace deletion) |

Annotations are chosen because stuck finalizers are operationally worse than temporary orphans. An orphan RoleBinding grants access that should be revoked; a stuck finalizer blocks namespace deletion and can cascade into cluster-wide issues.

### 8.3 ConfigMap vs. CRD for Controller Configuration

| Concern | ConfigMap | CRD |
|---------|-----------|-----|
| Bootstrapping | No bootstrapping problem | Controller needs CRD to exist before it can start |
| Validation | Startup validation only | Webhook validation on create/update |
| Schema evolution | Unversioned | Versioned with conversion webhooks |
| Integrity protection | VAP template provided | Standard RBAC on CRD resources |
| Simplicity | Simple to deploy and manage | Additional complexity (CRD, webhook, RBAC for the CRD) |

ConfigMap is chosen for simplicity. The scoping controller is a low-churn component; its configuration rarely changes after initial setup. If schema evolution becomes important, a CRD can be added in a future version without breaking the ConfigMap path.

### 8.4 SelfSubjectAccessReview vs. SelfSubjectRulesReview

| Concern | SSAR | SSRR |
|---------|------|------|
| Query model | "Can I do X?" (yes/no) | "What can I do in namespace Y?" (full list) |
| Cost | One API call per check | One API call per namespace, but may be incomplete |
| Accuracy | Authoritative | May be incomplete (API docs caveat) |
| Use case | Checking specific permissions | Discovering all permissions |

SSAR is used for graceful degradation checks (specific operations). SSRR could be added as an option for startup discovery reports if the completeness caveat is acceptable.

---

## 9. Observability

### 9.1 Scoping Controller Metrics

The scoping controller exports Prometheus metrics:

| Metric | Type | Description |
|--------|------|-------------|
| `rbac_scoper_rolebinding_created_total` | Counter | Total RoleBindings created, labeled by target SA and namespace |
| `rbac_scoper_rolebinding_deleted_total` | Counter | Total RoleBindings deleted (GC), labeled by target SA and namespace |
| `rbac_scoper_reconcile_duration_seconds` | Histogram | Reconciliation latency |
| `rbac_scoper_reconcile_errors_total` | Counter | Reconciliation errors, labeled by error type |
| `rbac_scoper_orphan_rolebindings` | Gauge | Current count of orphan RoleBindings pending cleanup |
| `rbac_scoper_clusterrole_missing` | Gauge | Whether a configured static ClusterRole is missing (0 = present, 1 = missing) |

### 9.2 Graceful Degradation Library Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `graceful_permission_denied_total` | Counter | Total Forbidden errors handled, labeled by resource and verb |
| `graceful_permission_restored_total` | Counter | Total permission restorations detected |
| `graceful_ssar_duration_seconds` | Histogram | SelfSubjectAccessReview call latency |
| `graceful_ssar_calls_total` | Counter | Total SSAR calls |

### 9.3 Recommended Alerts

| Alert | Condition | Severity |
|-------|-----------|----------|
| `RBACScoperReconcileErrors` | `rbac_scoper_reconcile_errors_total` increasing for 10m | Warning |
| `RBACScoperClusterRoleMissing` | `rbac_scoper_clusterrole_missing == 1` for 5m | Critical |
| `RBACScoperOrphanAccumulation` | `rbac_scoper_orphan_rolebindings > 10` for 15m | Warning |
| `OperatorPermissionDenied` | `graceful_permission_denied_total` increasing for 5m | Warning |
| `ImpersonateVerbDetected` | RBAC audit finding with category `aggregate-to-edit-impersonate` | Critical |

### 9.4 Kubernetes Audit Log Integration

The toolkit's detective controls are complemented by Kubernetes API server audit logging. Recommended audit policy rules:

- Log `rbac.authorization.k8s.io` resource mutations at `Request` level (captures who created/modified/deleted Roles and RoleBindings).
- Log `authentication.k8s.io/tokenreviews` and `authorization.k8s.io/subjectaccessreviews` at `Metadata` level.
- Log pod creation in the operator's namespace at `Request` level (captures SA usage attempts).

The RBAC audit component (`pkg/audit`) reads existing RBAC state but does not interact with the audit log. Correlation between audit log events and RBAC audit findings is an operational concern left to the cluster admin's SIEM/log aggregation tooling.

### 9.5 Structured Logging

All components use structured logging (JSON format) with consistent fields:

- `component`: which toolkit component emitted the log (scoper, graceful, audit, saprotection, impersonation)
- `target_sa`: the ServiceAccount being scoped or protected
- `namespace`: the namespace where the action occurred
- `rolebinding`: the managed RoleBinding name (scoper logs)
- `permission`: the specific permission being checked or denied (graceful logs)

---

## 10. Performance Characteristics

### 10.1 Graceful Degradation Library

The library adds negligible overhead to reconciliation:

| Operation | Cost | When |
|-----------|------|------|
| `SelfSubjectAccessReview` | 1 API call per check (rate-limited, default 10 concurrent) | Startup discovery, after Forbidden errors |
| Status condition update | 1 API call (patch) | When permission state changes |
| Event emission | 1 API call | When permission state changes |
| Forbidden handling | 0 additional API calls | Intercepts existing error, no new calls |

At steady state (permissions unchanged), the library adds zero API calls. Cost is incurred only on permission state transitions.

### 10.2 RBAC Scoping Controller

| Operation | Cost | When |
|-----------|------|------|
| RoleBinding creation | 1 API call | First CR in a new namespace |
| OwnerReference patch | 1 API call | Additional CR in existing namespace |
| Steady-state reconcile | 0 API calls | DeepEqual skip when no changes |
| Orphan scan | 1 list + N get calls | Startup + periodic interval |

The RoleBinding management logic is ported from operator-security-runtime v1 (bind mode path). The v1 bind mode was validated via 4-phase A/B testing on two OCP clusters (320 total trials). Those results provide a baseline, but v2's architecture differs (external controller vs. embedded library), so the numbers should be re-validated:

- v1 baseline p95 reconcile latency: +13-18% (~123ms absolute, one-time per namespace)
- v1 baseline steady-state cost: 0 additional API calls
- v1 baseline first-time provisioning: 2 API calls (1 RoleBinding create + 1 OwnerReference patch) per namespace

V2 adds namespace label watching (when `NamespaceSelector` is configured), cross-namespace cleanup scans, and CRD availability retries, which may increase API call volume compared to v1. Performance validation for v2 is planned before GA release.

### 10.3 Defense-in-Depth Components

SA protection webhook and impersonation guard have the same performance characteristics as in v1. The webhook adds ~2ms to pod admission decisions. The impersonation guard reconciler runs once and watches for drift.

---

## 11. Kubernetes Version Compatibility

| Component | Minimum K8s Version | Notes |
|-----------|--------------------|----- |
| Graceful Degradation Library | 1.25+ | Uses SelfSubjectAccessReview (stable since 1.0) |
| RBAC Scoping Controller | 1.25+ | Uses standard RBAC resources and controller-runtime |
| SA Protection Webhook | 1.25+ | ValidatingWebhookConfiguration (stable since 1.16) |
| Impersonation Guard | 1.25+ | Modifies standard ClusterRole resources |
| RBAC Audit | 1.25+ | Reads standard RBAC resources |
| VAP Templates | 1.30+ | ValidatingAdmissionPolicy GA in 1.30 |
| KEP-4601 (Authorization with Selectors) | 1.31+ (alpha) | Future direction, not current dependency |

**OpenShift version mapping:**

| OpenShift | Kubernetes | VAP Support |
|-----------|-----------|-------------|
| 4.14 | 1.27 | No |
| 4.15 | 1.28 | No |
| 4.16 | 1.29 | No |
| 4.17 | 1.30 | Yes (GA) |
| 4.18+ | 1.31+ | Yes |

On clusters without VAP support, deploy the core components (scoping controller, graceful degradation library, SA protection webhook, impersonation guard) and use the RBAC audit component to identify remaining exposure. The VAP templates provide defense-in-depth but are not required for the core scoping functionality.

---

## 12. Migration from operator-security-runtime v1

### 12.1 Component Mapping

| v1 Package | v2 Component | Migration |
|------------|-------------|-----------|
| `pkg/rbacscope` (operator-embedded) | `pkg/scoper` (external controller) | Move RBAC management from operator's reconciler to scoping controller |
| `pkg/rbacscope` (bind mode) | `pkg/scoper` (bind-only) | Direct port; scoping controller uses bind mode exclusively |
| `pkg/saprotection` | `pkg/saprotection` | No change; deploy as before |
| `pkg/impersonationguard` | `pkg/impersonation` | No change; deploy as before |
| `pkg/rbacaudit` | `pkg/audit` | No change; integrate as before |
| N/A | `pkg/graceful` | New component; add to operator reconciler |

### 12.2 Migration Steps

1. **Add graceful degradation library** to the operator. Replace hard failures on Forbidden with graceful degradation via `pkg/graceful`.
2. **Deploy the scoping controller** (or embed `pkg/scoper` in the platform operator). Configure it with the operator's SA and CR GVK.
3. **Deploy the static ClusterRole** with the scoped permissions (same rules the operator previously managed via escalate mode). Ensure it does not use `aggregationRule`.
4. **Remove RBAC management code** from the operator's reconciler. Remove the `escalate`/`bind` verb requirements from the operator's RBAC markers.
5. **Remove the scoped resources** from the operator's static ClusterRole and remove the legacy ClusterRoleBinding. The scoping controller now manages per-namespace access.
6. **Verify** by minting a token for the operator's SA and confirming it cannot access resources outside CR-bearing namespaces: `kubectl create token <sa> -n <ns> | kubectl get secrets -A --token=-`

### 12.3 Rollback Safety

Each migration step is independently reversible:

- Step 1 is additive (new library, no behavior change if permissions are available).
- Step 2 creates RoleBindings that coexist with any existing ClusterRoleBinding.
- Steps 3-5 can be reverted by re-adding the scoped resources to the operator's static ClusterRole and re-creating the ClusterRoleBinding.

---

## 13. Known Limitations

### 13.1 Scoping Controller Availability

If the scoping controller is down when a CR is created, the RoleBinding is not created until the controller recovers. During this window, the operator cannot access resources in the new namespace. The graceful degradation library handles this by surfacing status conditions and retrying.

### 13.2 Cross-Namespace Orphan Latency

Cross-namespace RoleBindings use annotation-based ownership with periodic cleanup. If a CR is deleted while the controller is down, the orphan RoleBinding persists until the next cleanup scan (default: 5 minutes). This is a temporary over-grant (access persists longer than needed) rather than an under-grant (access denied when needed). The graceful degradation library does not detect over-grants; it only surfaces under-grants (missing permissions).

### 13.3 Backup and Restore

After a cluster restore from backup (e.g., Velero), CRs may exist with different UIDs than when the backup was taken. Cross-namespace RoleBinding annotations reference CRs by `namespace/name/uid`. If the UID has changed, the annotation entry looks like an orphan. The scoping controller's orphan scan will remove the stale entry and re-create it with the correct UID on the next reconciliation cycle. There is a brief window (one reconciliation cycle) where the RoleBinding may be temporarily deleted and recreated.

### 13.4 VAP Self-Protection

ValidatingAdmissionPolicies cannot intercept operations on VAP resources themselves. A compromised SA with permissions to modify VAPs could disable the protection policies. Additionally, if a VAP binding uses `namespaceSelector` for enforcement, an attacker who can modify namespace labels could remove the enforcement label, disabling the VAP for that namespace without touching the VAP or its binding. Mitigations:
- Ensure no operator SA has write access to `validatingadmissionpolicies` or `validatingadmissionpolicybindings`.
- Deploy the `protect-vap-enforcement-labels` VAP to protect labels used by VAP binding namespaceSelectors.
- Use `matchPolicy: Exact` on VAP bindings where possible rather than label selectors.

### 13.5 CRD Not Yet Installed

If the scoping controller starts before the CRD for a configured GVK is installed, the controller logs a warning and skips that target. RoleBindings for that target are not created. The controller continues to process other configured targets. A controller restart is required after the CRD becomes available.

The CRD retry mechanism does not validate CRD provenance. If an attacker creates a CRD with the configured GVK before the legitimate operator's CRD is installed, the scoping controller would discover the attacker's CRD. Mitigation: deploy the scoping controller after the target CRDs are installed (e.g., in the same Helm release or Kustomize overlay), or use CRD-level RBAC to restrict who can create CRDs.

### 13.6 Namespace Label Revocation Latency

When a namespace label is removed and the namespace no longer matches a configured `NamespaceSelector`, the scoping controller deletes the managed RoleBinding. There is a brief window (typically one reconciliation cycle, under 10 seconds) between the label removal and the RoleBinding deletion during which the operator retains access in that namespace. The `allow-rolebinding-in-labeled-namespaces` VAP does not retroactively invalidate existing RoleBindings.

### 13.7 Annotation Ownership Forgery

If the scoping controller's SA is compromised (attack chain #8), the attacker can forge annotation-based ownership entries on cross-namespace RoleBindings. By referencing real, existing CRs in the annotation, the attacker can make malicious RoleBindings survive garbage collection. After SA rotation (revoking the compromise), these forged RoleBindings persist because the cleanup reconciler sees valid-looking owners.

Mitigation: after a suspected scoping controller SA compromise, audit all managed RoleBindings (identifiable by their deterministic names) and verify each annotation owner entry corresponds to a legitimate scoping trigger. Consider deploying a one-time cleanup job that re-validates all managed RoleBindings against the current scoping target configuration.

### 13.8 Per-Namespace Rule Differentiation

Bind mode uses a single static ClusterRole as the permission ceiling. If an operator needs different rule sets for different namespaces (e.g., read-only in namespace A, read-write in namespace B), a single static ClusterRole cannot express this. Workaround: define multiple static ClusterRoles and configure separate `ScopingTarget` entries for each, with different `NamespaceSelector` configurations to control which namespaces receive which permission set.

### 13.9 Network Isolation

RBAC scoping controls API-level access but does not provide network isolation. An operator scoped to specific namespaces at the RBAC level is still network-reachable from pods in other namespaces. Use NetworkPolicies for network-level isolation as a complementary control.
