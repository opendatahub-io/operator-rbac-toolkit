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
9. [Performance Characteristics](#9-performance-characteristics)
10. [Migration from operator-security-runtime v1](#10-migration-from-operator-security-runtime-v1)
11. [Known Limitations](#11-known-limitations)

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

The operator and the RBAC management authority must be separate entities with separate ServiceAccounts. Compromising the operator must not compromise RBAC management. This is the core architectural change from v1.

### 2.2 Operators Are RBAC Consumers, Not Producers

Operators should never create, modify, or delete Roles, ClusterRoles, RoleBindings, or ClusterRoleBindings for their own ServiceAccount. They should not require the `escalate`, `bind`, or any RBAC write verbs. Operators consume permissions granted by external authorities.

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

The three components are independent. They do not require each other and have no runtime dependencies between them:

- An operator can use the graceful degradation library without the scoping controller being deployed.
- The scoping controller can manage RBAC for operators that don't use the graceful degradation library.
- The defense-in-depth toolkit can be deployed without either of the other components.

When all three are deployed together, they provide complementary coverage:

1. The **scoping controller** ensures the operator only has permissions in namespaces with active CRs.
2. The **graceful degradation library** ensures the operator handles missing permissions cleanly during transitions (CR creation before RoleBinding provisioning, admin RBAC changes mid-reconcile).
3. The **defense-in-depth toolkit** provides additional protection layers (SA identity protection, impersonation hardening, permission auditing).

### 3.3 Alternatives Considered

| Approach | Pros | Cons | Decision |
|----------|------|------|----------|
| Operator self-manages RBAC (v1) | Zero-friction deployment, single binary | Violates trust domain separation, requires escalate/bind verbs, community consensus against it | Rejected as primary model; redesigned into separated components |
| Pure admission policies (VAPs/OPA) | No RBAC manipulation, uses existing K8s primitives | Admission policies do not intercept GET/LIST/WATCH requests; cannot restrict read access | Used as defense-in-depth complement, not primary mechanism |
| Authorization webhook (KEP-4601) | Works at authorization layer, intercepts all operations including reads | Adds latency to every API call, requires K8s 1.34+, complex to implement | Future direction, not current dependency |
| Kubectl plugin for static RBAC generation | Zero runtime components, admin-controlled | Does not dynamically adjust as CRs are created/deleted | Complementary tool, not primary mechanism |
| OLM OperatorGroups with scoped ServiceAccounts | Upstream-supported, admin-controlled | Only works with OLM-managed operators, does not handle dynamic namespace scoping | Supported as an alternative deployment model |

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
// Operator author's reconciler
func (r *MyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
    cr := &v1alpha1.MyCR{}
    if err := r.Get(ctx, req.NamespacedName, cr); err != nil {
        return ctrl.Result{}, client.IgnoreNotFound(err)
    }

    // Attempt to list secrets in the CR's namespace
    secrets := &corev1.SecretList{}
    result, err := graceful.Do(ctx, r.Client, cr, func() error {
        return r.List(ctx, secrets, client.InNamespace(cr.Namespace))
    })
    if err != nil {
        return result, err
    }
    if result.RequeueAfter > 0 {
        // Permission was denied, status condition is set, event emitted.
        // Reconciler will retry after the requeue interval.
        return result, nil
    }

    // Permission was granted, proceed with secrets.Items
    // ...
}
```

#### 4.2.2 Permission Discovery

At startup or on demand, the library performs `SelfSubjectAccessReview` checks to discover the operator's actual permissions. This produces a structured report of what the operator can and cannot do:

```go
// During operator startup
report, err := graceful.DiscoverPermissions(ctx, client, graceful.PermissionSpec{
    Resources: []graceful.ResourceSpec{
        {Group: "", Resource: "secrets", Verbs: []string{"get", "list", "create"}},
        {Group: "", Resource: "configmaps", Verbs: []string{"get", "list"}},
    },
    Namespaces: []string{"notebooks", "model-registry", "redhat-ods-applications"},
})

// report.Granted:  [{secrets, get, notebooks}, {secrets, list, notebooks}, ...]
// report.Denied:   [{secrets, get, kube-system}, {secrets, list, kube-system}, ...]
// report.Summary:  "12/18 permissions granted across 3 namespaces"
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
| `create` on `selfsubjectaccessreviews` | Permission discovery via SSAR |
| `create` on `events` | Emitting permission-related events |
| `update` on the operator's CR status subresource | Setting status conditions |

The first two are standard permissions that most operators already have. The third is a standard controller-runtime requirement.

### 4.4 Design Decisions

**Why SelfSubjectAccessReview instead of SelfSubjectRulesReview.** SSAR checks a specific permission (verb + resource + namespace) and returns a yes/no answer. SelfSubjectRulesReview returns all permissions for a namespace but is computationally expensive and can produce incomplete results (the API docs note that the result may be incomplete). SSAR is cheaper, more reliable, and sufficient for the use case.

**Why RequeueAfter instead of fail-fast.** When permissions are denied, the operator should retry because the admin may be in the process of updating RBAC. A hard failure forces the admin to manually restart the operator after fixing permissions. RequeueAfter lets the operator self-heal when permissions are restored.

**Why structured conditions instead of log-only.** Logs are not observable by cluster monitoring systems. Status conditions are queryable via the Kubernetes API, can trigger alerts, and are visible in the OpenShift console. This aligns with the operator framework's status condition conventions.

**Why not wrap the controller-runtime client globally.** A global wrapper would intercept every API call, including those that should fail hard (e.g., getting the CR itself). The library provides explicit wrapping for operations that may be subject to admin-scoped RBAC, leaving the operator author in control of which operations degrade gracefully.

---

## 5. Component 2: RBAC Scoping Controller

### 5.1 Purpose

The RBAC Scoping Controller (`pkg/scoper`) is an admin-side component that dynamically manages namespace-scoped RoleBindings for target operator ServiceAccounts. When a Custom Resource appears in a namespace, the controller creates a RoleBinding granting the operator's SA access in that namespace. When the CR is deleted, the RoleBinding is cleaned up.

The controller runs with its own ServiceAccount, separate from the operators it manages. This is the core trust domain separation: compromising an operator's SA does not compromise RBAC management.

### 5.2 Delivery Options

The scoping controller is available as:

1. **Standalone binary** (`cmd/scoper`). Cluster admins deploy it as a separate Deployment. Suitable for clusters without an existing platform operator.
2. **Importable Go package** (`pkg/scoper`). Platform operators (e.g., the RHOAI operator, which already reconciles DSC/DSCI) embed the scoping logic into their existing reconciliation loop. Zero additional deployment friction.

Both options use the same `pkg/scoper` library. The standalone binary is a thin wrapper that reads configuration from a ConfigMap and starts the controller.

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
    // This ClusterRole must be pre-deployed by the admin.
    ClusterRoleName string

    // The name to use for managed RoleBindings.
    // Deterministic naming enables drift detection and cleanup.
    ManagedRoleBindingName string
}
```

For the standalone binary, this configuration is provided via a ConfigMap:

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
```

For the importable package, configuration is provided programmatically:

```go
scoper, err := scoper.New(mgr, scoper.Config{
    Targets: []scoper.ScopingTarget{
        {
            WatchGVK:               schema.GroupVersionKind{Group: "dashboard.opendatahub.io", Version: "v1alpha1", Kind: "OdhDashboardConfig"},
            TargetSA:               types.NamespacedName{Name: "odh-dashboard", Namespace: "redhat-ods-applications"},
            ClusterRoleName:        "odh-dashboard-scoped",
            ManagedRoleBindingName: "odh-dashboard-scoped-binding",
        },
    },
})
```

#### 5.3.2 CR Lifecycle Flow

```
CR Created in namespace "foo"
    |
    v
Controller detects CR via watch
    |
    v
Does RoleBinding "odh-dashboard-scoped-binding" exist in "foo"?
    |
    +-- No --> Create RoleBinding referencing static ClusterRole
    |          with OwnerReference pointing to the CR
    |
    +-- Yes --> Check if OwnerReference for this CR exists
                    |
                    +-- No --> Add OwnerReference to existing RoleBinding
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

Multiple CRs of the same or different GVKs can exist in the same namespace. The controller uses Kubernetes OwnerReferences to track which CRs require the RoleBinding. The RoleBinding is only deleted when no CRs remain in the namespace.

#### 5.3.4 Cross-Namespace Grants

When an operator needs access to a namespace different from where its CR exists (e.g., the Dashboard CR is in `redhat-ods-applications` but needs access to `rhods-notebooks`), the controller supports cross-namespace targets:

```go
ScopingTarget{
    WatchGVK:               gvk,
    TargetSA:               types.NamespacedName{Name: "odh-dashboard", Namespace: "redhat-ods-applications"},
    ClusterRoleName:        "odh-dashboard-notebooks",
    ManagedRoleBindingName: "odh-dashboard-notebooks-binding",
    // TargetNamespaceSource specifies where to create the RoleBinding.
    // Instead of creating it in the CR's namespace, create it in the
    // namespace specified by a field in the CR or a DSC/DSCI field.
    TargetNamespaceSource: scoper.NamespaceFromField(".spec.notebookController.notebookNamespace"),
}
```

For cross-namespace RoleBindings, OwnerReferences cannot be used (Kubernetes does not allow cross-namespace OwnerReferences). The controller uses annotation-based ownership instead:

- Annotation key: `operator-rbac-toolkit.io/scoped-access-owners`
- Annotation value: comma-separated list of `namespace/name/uid` entries

This is the same proven approach used in operator-security-runtime v1.

### 5.4 Static ClusterRole Requirement

The scoping controller uses **bind mode only**. It creates RoleBindings that reference a pre-deployed static ClusterRole. It never creates or modifies Roles or ClusterRoles.

The static ClusterRole defines the permission ceiling. It must be deployed by the cluster admin as part of the operator's installation manifests (Helm chart, OLM CSV, Kustomize, or GitOps).

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: odh-dashboard-scoped
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

The permission ceiling is enforced by Kubernetes RBAC itself (the static ClusterRole is immutable at runtime, not modifiable by the operator or the scoping controller). A compromised operator SA can only use permissions defined in this ClusterRole, and only in namespaces where RoleBindings exist.

### 5.5 RBAC Requirements for the Scoping Controller

The scoping controller's ServiceAccount needs:

| Permission | Purpose |
|------------|---------|
| `get`, `list`, `watch` on target CRDs | Detecting CR creation and deletion |
| `get`, `create`, `update`, `delete` on `rolebindings` | Managing namespace-scoped RoleBindings |
| `bind` on the static ClusterRole (via `resourceNames`) | Creating RoleBindings that reference the static ClusterRole |

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
3. For each owner entry, checks if the referenced CR still exists.
4. Removes stale owner entries.
5. If no owners remain, deletes the RoleBinding.

This cleanup runs on a configurable interval (default: 5 minutes) and on every CR deletion event.

#### 5.7.3 Orphan Detection

On startup, the controller scans for managed RoleBindings whose owner CRs no longer exist. These orphans are cleaned up immediately. This handles the case where the controller was down when CRs were deleted.

### 5.8 Design Decisions

**Why bind mode only (no escalate mode).** The `escalate` verb allows creating Roles with arbitrary rules, which is flagged as a privilege escalation risk by every security guide. Bind mode uses the `bind` verb scoped via `resourceNames`, which only allows referencing specific pre-deployed ClusterRoles. The permission ceiling is enforced by Kubernetes RBAC, not by application code. This is architecturally safer and passes SOC2/FedRAMP audits without exceptions.

**Why the controller manages RoleBindings but not Roles.** Creating namespace-scoped Roles requires the `escalate` verb (to put rules into the Role) or the controller must already possess all permissions it grants. Using a pre-deployed static ClusterRole avoids both issues. The ClusterRole defines rules once; RoleBindings activate those rules in specific namespaces.

**Why OwnerReferences for same-namespace, annotations for cross-namespace.** Kubernetes does not support cross-namespace OwnerReferences. Annotations provide the same ownership semantics without requiring a custom finalizer on every CR. The annotation format is designed for corruption resilience: malformed entries are skipped, not fatal.

**Why a ConfigMap for standalone configuration, not a CRD.** A ConfigMap is simpler, requires no webhook or controller for validation, and avoids the bootstrapping problem of a CRD-based controller that needs permissions to watch its own CRD. For the importable package, configuration is programmatic and validated at construction time.

---

## 6. Component 3: Defense-in-Depth Toolkit

### 6.1 Overview

The Defense-in-Depth Toolkit provides independent security mechanisms that complement the scoping controller and graceful degradation library. Each mechanism can be deployed independently. None require the operator to manage its own RBAC.

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
    +-- Yes --> Is the request from the operator's own controller?
                    |
                    +-- Yes --> Allow
                    +-- No --> Deny ("ServiceAccount is protected")
```

The webhook uses namespace selectors to scope enforcement to the operator's namespace, avoiding cluster-wide webhook overhead.

#### 6.3.4 Design Decisions

**Name-only SA matching.** The webhook matches ServiceAccount names, not UIDs. This avoids the bootstrapping problem where the webhook needs to know the SA UID before the SA exists. Name-based matching is sufficient because SA names are unique within a namespace.

**Fail-secure.** If the webhook encounters an error evaluating a request, it denies the request. This prevents attackers from exploiting webhook failures to bypass protection.

**Update short-circuit.** Pod updates that do not change the ServiceAccount field are allowed without further validation. This avoids false positives from kubelet status updates and readiness probes.

### 6.4 Impersonation Guard (`pkg/impersonation`)

#### 6.4.1 Purpose

A reconciler that closes the impersonation bypass in Kubernetes RBAC. The default `system:aggregate-to-edit` ClusterRole includes the `impersonate` verb for ServiceAccounts. This allows any namespace editor to impersonate any ServiceAccount in their namespace, inheriting that SA's full permissions.

#### 6.4.2 Approach

The impersonation guard reconciler:

1. Reads the `system:aggregate-to-edit` ClusterRole.
2. Strips the `impersonate` verb from ServiceAccount rules.
3. Sets `rbac.authorization.kubernetes.io/autoupdate: "false"` to prevent the API server from restoring the verb on restart.
4. Reconciles continuously to detect and correct drift.

#### 6.4.3 Why Webhooks Cannot Solve This

Impersonation is evaluated at the authentication layer, before admission webhooks are invoked. A ValidatingWebhook that denies impersonation requests would never see them because the API server resolves impersonation headers before routing the request to the admission chain.

#### 6.4.4 Companion VAP

A ValidatingAdmissionPolicy template is provided to prevent restoration of the `impersonate` verb in `system:aggregate-to-edit`:

```yaml
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: deny-impersonate-grants
spec:
  matchConstraints:
    resourceRules:
      - apiGroups: ["rbac.authorization.k8s.io"]
        resources: ["clusterroles"]
        operations: ["UPDATE"]
  validations:
    - expression: >-
        !object.rules.exists(r,
          r.resources.exists(res, res == 'serviceaccounts') &&
          r.verbs.exists(v, v == 'impersonate'))
      message: "ClusterRole must not grant impersonate on serviceaccounts"
```

#### 6.4.5 Future: KEP-5284 Constrained Impersonation

KEP-5284 (Constrained Impersonation, alpha in v1.35) restricts impersonation so that "an impersonating user cannot perform actions they themselves are not allowed to do." When this KEP reaches GA, the impersonation guard becomes less critical but remains valuable as a belt-and-suspenders measure.

### 6.5 ValidatingAdmissionPolicy Templates

The toolkit provides VAP templates for cluster admins to deploy. These enforce RBAC invariants at the API server level, providing guarantees that a compromised SA cannot bypass.

| Template | Purpose | What It Prevents |
|----------|---------|-----------------|
| `deny-impersonate-grants.yaml` | Block impersonation privilege grants in any Role/ClusterRole | Impersonation bypass |
| `restrict-scoped-rolebinding-creation.yaml` | Only the scoping controller's SA can create managed RoleBindings | Unauthorized RoleBinding creation by compromised operator |
| `restrict-scoped-rolebinding-subjects.yaml` | Managed RoleBindings can only reference the target operator's SA | Subject manipulation to grant access to attacker-controlled SA |
| `deny-rolebinding-in-protected-namespaces.yaml` | Default deny-list for sensitive namespaces (kube-system, kube-public, etc.) | RoleBinding creation in system namespaces |
| `allow-rolebinding-in-labeled-namespaces.yaml` | Only admin-labeled namespaces can receive managed RoleBindings | RoleBinding creation in unauthorized namespaces |
| `protect-rbac-allowed-label.yaml` | Prevents non-admin label manipulation on namespaces | Label spoofing to bypass namespace restrictions |
| `protect-static-clusterrole.yaml` | Prevents modification of the static ClusterRole | Permission ceiling tampering |

VAP templates are provided as YAML files in `config/vap/`. Cluster admins deploy them via Kustomize, Helm, or GitOps. Each template includes inline documentation explaining what it protects and how to configure it.

---

## 7. Threat Model

### 7.1 Assumptions

1. The Kubernetes API server is trusted and correctly enforces RBAC.
2. The scoping controller's ServiceAccount is separate from the operator's ServiceAccount.
3. The static ClusterRole is deployed by the admin and not modifiable by the operator at runtime.
4. VAP templates are deployed by the admin and enforce invariants at the API server level.

### 7.2 Attack Chain Analysis

| # | Attack Vector | Mitigated By | Residual Risk |
|---|---------------|-------------|---------------|
| 1 | **Compromised operator SA token reads secrets in kube-system** | Scoping controller (no RoleBinding in kube-system) | None if scoping controller is deployed |
| 2 | **Attacker creates pod with operator's SA in operator namespace** | SA protection webhook (denies unauthorized SA usage) | Webhook bypass if webhook is down or misconfigured |
| 3 | **Namespace editor impersonates operator's SA** | Impersonation guard (strips impersonate from aggregate-to-edit) + deny-impersonate-grants VAP | Race condition during guard startup |
| 4 | **Compromised operator SA creates RoleBinding in kube-system** | deny-rolebinding-in-protected-namespaces VAP + restrict-scoped-rolebinding-creation VAP | None if VAPs are deployed |
| 5 | **Compromised operator SA modifies static ClusterRole to add rules** | protect-static-clusterrole VAP + operator SA has no write verbs on ClusterRoles | None if VAP is deployed |
| 6 | **Attacker modifies managed RoleBinding to change subject** | restrict-scoped-rolebinding-subjects VAP + scoping controller drift recovery | None if VAP is deployed |
| 7 | **Attacker labels namespace to allow RoleBinding creation** | protect-rbac-allowed-label VAP (restricts who can set the label) | Admin compromise |
| 8 | **Scoping controller SA is compromised** | Controller SA only has bind on specific ClusterRoles (resourceNames). Cannot create arbitrary bindings. VAPs still enforce invariants. | Attacker can create RoleBindings in any namespace for the scoped ClusterRoles |
| 9 | **TokenRequest API used to mint SA token** | RBAC audit detects tokenrequest exposure at startup | Requires separate RBAC restriction on serviceaccounts/token |
| 10 | **Operator continues using existing broad ClusterRoleBinding** | Migration guide, RBAC audit warns about ClusterRoleBindings | Requires admin action to remove legacy bindings |

### 7.3 Trust Boundaries

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
- The operator SA cannot create RoleBindings (VAP enforced).
- The operator SA cannot modify the scoping controller's SA permissions.

### 7.4 Blast Radius Quantification

Blast radius is measured by counting accessible resources before and after scoping:

**Measurement methodology:**
1. Mint a token for the operator's SA.
2. Attempt to list secrets in every namespace.
3. Count the namespaces where the request succeeds and the total secrets accessible.

**Example measurement (RHOAI Dashboard):**

| Scenario | Namespaces with secret access | Total secrets accessible |
|----------|-------------------------------|------------------------|
| ClusterRoleBinding (before) | All namespaces (including kube-system) | 43 in kube-system + all others |
| Namespace-scoped RoleBindings (after) | Only namespaces with active CRs | 5 in the CR namespace |

The reduction is not a percentage (which varies by cluster size) but an absolute confinement: access exists only where CRs exist.

---

## 8. Key Architectural Tradeoffs

### 8.1 Separate Controller vs. Embedded Library

| Concern | Separate Controller (standalone binary) | Embedded Library (imported by platform operator) |
|---------|----------------------------------------|--------------------------------------------------|
| Deployment friction | Additional Deployment to install | Zero additional friction (code import) |
| Trust domain | Clear separation (separate SA) | Shared with platform operator's SA |
| Upgrade path | Independent release cycle | Coupled to platform operator releases |
| Best for | Clusters without an existing platform operator | Clusters with an existing platform operator (e.g., RHOAI) |

Both options use the same `pkg/scoper` library. The tradeoff is deployment model, not implementation.

### 8.2 Annotation-Based vs. Finalizer-Based Cross-Namespace GC

| Concern | Annotations | Finalizers |
|---------|-------------|------------|
| Deletion latency | Requires periodic scan | Immediate on CR deletion |
| Failure mode | Orphan persists until next scan | Stuck CR if controller is down |
| Operational risk | Low (orphan = extra RoleBinding) | High (stuck finalizer blocks namespace deletion) |

Annotations are chosen because stuck finalizers are operationally worse than temporary orphans. An orphan RoleBinding grants access that should be revoked; a stuck finalizer blocks namespace deletion and can cascade into cluster-wide issues.

### 8.3 ConfigMap vs. CRD for Controller Configuration

| Concern | ConfigMap | CRD |
|---------|-----------|-----|
| Bootstrapping | No bootstrapping problem | Controller needs CRD to exist before it can start |
| Validation | Startup validation only | Webhook validation on create/update |
| Schema evolution | Unversioned | Versioned with conversion webhooks |
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

## 9. Performance Characteristics

### 9.1 Graceful Degradation Library

The library adds negligible overhead to reconciliation:

| Operation | Cost | When |
|-----------|------|------|
| `SelfSubjectAccessReview` | 1 API call per check | Startup discovery, after Forbidden errors |
| Status condition update | 1 API call (patch) | When permission state changes |
| Event emission | 1 API call | When permission state changes |
| Forbidden handling | 0 additional API calls | Intercepts existing error, no new calls |

At steady state (permissions unchanged), the library adds zero API calls. Cost is incurred only on permission state transitions.

### 9.2 RBAC Scoping Controller

| Operation | Cost | When |
|-----------|------|------|
| RoleBinding creation | 1 API call | First CR in a new namespace |
| OwnerReference update | 1 API call | Additional CR in existing namespace |
| Steady-state reconcile | 0 API calls | DeepEqual skip when no changes |
| Orphan scan | 1 list + N get calls | Startup + periodic interval |

Performance characteristics are inherited from operator-security-runtime v1, which was validated via 4-phase A/B testing on two OCP clusters (320 total trials):

- p95 reconcile latency: +13-18% (~123ms absolute, one-time per namespace)
- Steady-state cost: 0 additional API calls
- First-time provisioning: 2 API calls (1 RoleBinding create + 1 OwnerReference update) per namespace

### 9.3 Defense-in-Depth Components

SA protection webhook and impersonation guard have the same performance characteristics as in v1. The webhook adds ~2ms to pod admission decisions. The impersonation guard reconciler runs once and watches for drift.

---

## 10. Migration from operator-security-runtime v1

### 10.1 Component Mapping

| v1 Package | v2 Component | Migration |
|------------|-------------|-----------|
| `pkg/rbacscope` (operator-embedded) | `pkg/scoper` (external controller) | Move RBAC management from operator's reconciler to scoping controller |
| `pkg/rbacscope` (bind mode) | `pkg/scoper` (bind-only) | Direct port; scoping controller uses bind mode exclusively |
| `pkg/saprotection` | `pkg/saprotection` | No change; deploy as before |
| `pkg/impersonationguard` | `pkg/impersonation` | No change; deploy as before |
| `pkg/rbacaudit` | `pkg/audit` | No change; integrate as before |
| N/A | `pkg/graceful` | New component; add to operator reconciler |

### 10.2 Migration Steps

1. **Add graceful degradation library** to the operator. Replace hard failures on Forbidden with graceful degradation via `pkg/graceful`.
2. **Deploy the scoping controller** (or embed `pkg/scoper` in the platform operator). Configure it with the operator's SA and CR GVK.
3. **Deploy the static ClusterRole** with the scoped permissions (same rules the operator previously managed via escalate mode).
4. **Remove RBAC management code** from the operator's reconciler. Remove the `escalate`/`bind` verb requirements.
5. **Remove the scoped resources** from the operator's static ClusterRole. The scoping controller now manages per-namespace access.
6. **Verify** by minting a token for the operator's SA and confirming it cannot access resources outside CR-bearing namespaces.

### 10.3 Rollback Safety

Each migration step is independently reversible:

- Step 1 is additive (new library, no behavior change if permissions are available).
- Step 2 creates RoleBindings that coexist with any existing ClusterRoleBinding.
- Steps 3-5 can be reverted by re-adding the scoped resources to the operator's static ClusterRole.

---

## 11. Known Limitations

### 11.1 Scoping Controller Availability

If the scoping controller is down when a CR is created, the RoleBinding is not created until the controller recovers. During this window, the operator cannot access resources in the new namespace. The graceful degradation library handles this by surfacing status conditions and retrying.

### 11.2 Cross-Namespace Orphan Latency

Cross-namespace RoleBindings use annotation-based ownership with periodic cleanup. If a CR is deleted while the controller is down, the orphan RoleBinding persists until the next cleanup scan. This is a temporary over-grant (access persists longer than needed) rather than an under-grant (access denied when needed).

### 11.3 Existing Tokens

Scoping permissions does not invalidate existing ServiceAccount tokens. If a token was minted before scoping was applied, it retains the permissions it had at minting time until it expires. This is a Kubernetes limitation, not a toolkit limitation.

### 11.4 TokenRequest API

The Kubernetes TokenRequest API allows any entity with `create` on `serviceaccounts/token` to mint new tokens for any SA. This bypasses SA identity protection. The RBAC audit component detects this exposure, but mitigation requires the admin to restrict `serviceaccounts/token` access separately.

### 11.5 Webhook Ordering

If multiple mutating admission webhooks run before the SA protection webhook, a mutating webhook could change the ServiceAccount of a pod after the SA protection webhook has validated it. This is a standard Kubernetes webhook ordering limitation. Mitigation: ensure the SA protection webhook runs last in the admission chain, or use a `reinvocationPolicy: IfNeeded` configuration.

### 11.6 VAP Self-Protection Limitation

ValidatingAdmissionPolicies cannot intercept operations on VAP resources themselves. This means a compromised SA with permissions to modify VAPs could disable the protection policies. This is a Kubernetes API limitation. Mitigation: ensure no operator SA has write access to `validatingadmissionpolicies` or `validatingadmissionpolicybindings`.
