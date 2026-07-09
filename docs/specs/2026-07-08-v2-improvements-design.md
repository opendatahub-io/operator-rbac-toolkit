# Operator RBAC Toolkit v2 Improvements Design

## Context

Production feedback from Luca Burgazzoli (RHOAI platform lead) identified critical gaps in the toolkit's approach to RBAC provisioning. The core issue: when a user creates a CR (e.g., a Workbench), there's a timing gap before the scoping controller creates the RoleBinding. During this gap, the module operator gets 403 errors. For components we control, we can handle this gracefully. For third-party components like KServe, we can't. The user experience of "create -> error -> resolves" is unacceptable, and RBAC issues in production are brutal to diagnose.

## 1. Provisioning Triggers

Three modes, configurable per ScopingTarget:

| Mode | Trigger | Timing Gap | Use Case |
|------|---------|-----------|----------|
| **Reactive** (current) | CR created -> controller reconciles -> RoleBinding created | Yes (~seconds) | Simple setups, backward compat |
| **Webhook** (new) | MutatingAdmissionWebhook intercepts CR creation, creates RoleBinding synchronously | Near-zero (sub-second, limited by API server informer propagation) | Same-namespace targets. Default for production. |
| **Namespace label** (new) | Namespace gets a matching label -> pre-create RoleBindings for all enabled components | Zero (pre-provisioned) | When namespace labeling is available. Belt and suspenders with webhook. |

Configuration:

```go
ScopingTarget{
    WatchGVK:               gvk,
    TargetSA:               sa,
    ClusterRoleName:        "...",
    ManagedRoleBindingName: "...",
    NamespaceSelector:      selector,
    TargetNamespaceSource:  nsSource,

    // New fields
    WebhookProvisioning:    true,                        // mode 2 (same-namespace targets only)
    NamespaceLabelTrigger:  &metav1.LabelSelector{...},  // mode 3
    // If neither is set, uses reactive mode (mode 1)
}
```

Modes 2 and 3 can be combined: label watch pre-provisions, webhook guarantees near-zero gap for CRs in unlabeled namespaces.

**Webhook scope limitation:** The webhook handles **same-namespace targets only** (CR namespace == RoleBinding namespace). Cross-namespace targets (`TargetNamespaceSource` set) are handled by the reactive scoper controller, which accepts the timing gap. This avoids the complexity of extracting field values from the CR body in the webhook, and avoids the ownership problem (the CR has no UID at webhook time, so annotation-based cross-namespace ownership can't be set). Cross-namespace targets should use the namespace label trigger for pre-provisioning when possible.

**Near-zero vs zero:** The webhook creates the RoleBinding before the CR is persisted. However, the API server's RBAC authorizer uses an informer cache with a propagation delay (typically sub-second, but can be longer on heavily loaded clusters). The module operator's first reconciliation may still hit a brief window where the RoleBinding is persisted in etcd but not yet visible to the authorizer. Module operators should handle a few retries with short exponential backoff (1s, 2s) during the propagation window. The graceful degradation library handles this automatically.

## 2. Webhook Architecture

The MutatingAdmissionWebhook intercepts CR creation for configured GVKs (same-namespace targets only):

```
User creates CR in namespace X
    |
    v
API Server routes to MutatingAdmissionWebhook
    |
    v
Webhook handler:
  1. Is namespace denied? (deny-list check) -> Allow CR, no RoleBinding
  1.5. Does namespace match NamespaceSelector? (if configured) -> If not, allow CR, no RoleBinding
  2. Does RoleBinding already exist? (direct API Get, not cached) -> Allow CR, skip creation
  3. Does ClusterRole exist? -> If not, allow CR but log warning and emit event. The reactive scoper will also fail, surfacing ClusterRoleMissing metric. No RoleBinding created.
  3.5. Is this a dry-run request? -> Allow CR, skip RoleBinding creation (validation in steps 1-3 still runs so dry-run catches config errors)
  4. Create RoleBinding in namespace X with ManagedLabel + pending-owner annotation (namespace/name/GVK/RFC3339-timestamp)
     - No OwnerReference set (CR has no UID yet at admission time, UID is assigned after persistence)
     - If AlreadyExists error: treat as success (concurrent create from another replica, scoper, or label trigger)
     - If other create error: Allow CR anyway, log the error. Reactive scoper creates the RoleBinding on next reconcile. Brief 403 window.
  5. Allow CR
    |
    v
CR persisted (now has UID) -> Scoper backfills OwnerReference on next reconcile -> Module operator reconciles
```

### Key design decisions

**Mutating, not validating.** Mutating webhooks run before validating ones in the admission chain. We need the RoleBinding to exist before any validating webhook or the final persistence step.

**Why a mutating webhook that doesn't mutate.** The webhook creates a RoleBinding as a side effect, not as a mutation of the admitted CR. This is an unusual pattern. The alternative (a validating webhook that checks "RoleBinding exists" relying on the reactive scoper) reintroduces the timing gap. The side-effect approach is chosen deliberately, with the following safeguards:

- **Dry-run handling.** The webhook checks `req.DryRun` and skips RoleBinding creation when true. `kubectl apply --dry-run=server` must not create real resources.
- **Reinvocation safety.** Set `reinvocationPolicy: Never` (the default) on the MutatingWebhookConfiguration. Reinvocation would only trigger a redundant RoleBinding create, which is safely handled by AlreadyExists tolerance but wastes a round trip.
- **AlreadyExists tolerance.** If the RoleBinding already exists (created by another webhook replica, the namespace label trigger, or the scoper), the create call returns `AlreadyExists`. The webhook treats this as success, not an error.
- **Idempotent.** Step 2 checks for existing RoleBinding via direct (uncached) API Get. If it exists, skip creation entirely.

**Fail policy: graduated approach.**

- **Phase 1 (initial release):** `failurePolicy: Ignore`. If the webhook is unavailable, CRs are admitted without the RoleBinding. The reactive scoper creates it on the next reconciliation cycle. This trades the near-zero gap guarantee for availability. No user-facing CR creation failures during webhook downtime or operator upgrades.
- **Phase 2 (after production validation):** Switch to `failurePolicy: Fail` for environments that prefer guaranteed provisioning over availability. Document the blast radius: all configured GVKs become uncreatable during webhook downtime.

This graduated approach avoids the "deploy fail-closed webhook on day one and block CR creation during the first operator upgrade" scenario.

**Transition mechanics:** The `failurePolicy` is a field on the MutatingWebhookConfiguration resource. Transitioning from Ignore to Fail is a live update (`kubectl patch` or operator reconciliation). The API server picks up the change within its informer resync (typically <1s). Rollback is the reverse update. The configuration mechanism is a field on the operator's CR (e.g., `spec.rbacScoping.webhookFailurePolicy: Ignore|Fail`) that the operator reconciles into the MutatingWebhookConfiguration. Per-GVK fail policies are not supported in v2; it's all-or-nothing.

**Scoped via webhook rules.** The MutatingWebhookConfiguration `rules` field lists only the GVKs from ScopingTargets that have `WebhookProvisioning: true`. Rules are generated at setup time from the Config.

### Ownership and cleanup

The webhook sets the `ManagedLabelKey` label and a `pending-owner` annotation (`operator-rbac-toolkit.io/pending-owner: namespace/name/GVK`) on created RoleBindings. The OwnerReference cannot be set at webhook time because the CR has no UID yet (the UID is assigned by the API server after the full admission chain completes).

**Ownership backfill:** The scoper controller reconciles webhook-created RoleBindings with `pending-owner` annotations. When the CR exists and has a UID, the scoper replaces the annotation with a proper OwnerReference.

**Orphan handling:** If the CR creation fails after the webhook (a validating webhook rejects it, quota exceeded, etcd write failure), the RoleBinding exists but the CR does not. Cleanup:

- **Scoper orphan scan.** The startup orphan scan and periodic cleanup (default 5 minutes) check whether the CR referenced in the `pending-owner` annotation exists. If it doesn't and the `pending-owner-since` timestamp exceeds the TTL (default 30 seconds), the RoleBinding is deleted. The `pending-owner` annotation format includes a timestamp: `namespace/name/GVK/RFC3339-timestamp`.

**Important: the backfill reconcile path (triggered by RoleBinding watch events) must NOT delete orphans.** When the backfill path sees a `pending-owner` annotation but the CR doesn't exist yet (NotFound), it requeues after 2 seconds. If the `pending-owner-since` timestamp is older than the pending-owner TTL (default 30 seconds), the backfill path stops requeueing and defers cleanup to the periodic orphan scan. This caps unnecessary requeues at ~15 per orphan instead of running indefinitely. Orphan deletion is exclusively the periodic scan's responsibility with TTL enforcement. This prevents the scoper from deleting a RoleBinding before the CR is persisted (the CR creation and RoleBinding creation are concurrent events).

### Webhook and scoper coordination

Both the webhook and the scoper can create the same RoleBinding. Coordination is via idempotent creates:

- The webhook creates RoleBindings with the deterministic `ManagedRoleBindingName`, `ManagedLabelKey` label, `pending-owner` annotation, and `created-by: webhook` annotation. No OwnerReference (CR has no UID at webhook time).
- The scoper reconciler checks if the RoleBinding exists before creating. If it exists (created by the webhook or label trigger), it verifies the spec (drift recovery) and backfills the OwnerReference when the CR exists and has a UID. The backfill sets the OwnerReference and removes the `pending-owner` annotation in a single Update call to avoid split-state.
- Both the webhook, scoper, and label trigger handle `AlreadyExists` as success.
- A `created-by` annotation (`operator-rbac-toolkit.io/created-by: webhook`, `scoper`, or `label-trigger`) aids debuggability.
- **Concurrent label-trigger + webhook:** If both fire simultaneously for the same namespace, one gets `AlreadyExists`. If the label trigger wins, no `pending-owner` annotation is set. The scoper sets OwnerReference when it processes the CR creation event (normal reconcile path, no pending-owner needed).

**Config validation:** `WebhookProvisioning: true` is rejected when `TargetNamespaceSource != nil`. The webhook handles same-namespace targets only. This is enforced in `validateTarget()`.

**Unknown GVK handling:** If the webhook receives a request for a GVK that doesn't match any configured ScopingTarget (possible during rolling updates), it allows the CR with no side effect and logs a warning.

### Webhook registration and integration

Since the toolkit is a Go library embedded in the host operator:

- **Webhook handler.** The library exposes a `ProvisioningWebhookHandler` that implements `admission.Handler`. The host operator registers it on its webhook server alongside the existing SA protection webhook.
- **Webhook path.** `/mutate-rbac-scoper` (distinct from the SA protection webhook path `/validate-sa-protection`).
- **TLS certificates.** The webhook uses the host operator's existing cert infrastructure (cert-manager, OpenShift service-ca, or manual). No additional cert management is needed since it runs on the same webhook server.
- **MutatingWebhookConfiguration.** Generated by the kubebuilder plugin or deployed via the operator's manifests. The `rules` field is static (generated from known ScopingTargets at build time). Runtime target addition is not supported in v2; targets are fixed at startup. The handler allows requests for unknown GVKs (logs a warning, no side effect).
- **ServiceAccount.** The webhook runs in the host operator process and shares the host operator's SA. For RHOAI, the operator SA already has `verbs=*` on all RBAC resources. No new permissions needed.

## 3. Graceful Degradation Improvements

Currently Handler.Do treats all 403s identically. Two changes:

### a) Distinguish "not yet provisioned" from "permanently denied"

When the webhook is enabled, a 403 after the near-zero propagation window indicates a real problem. The handler distinguishes:

```go
ReasonProvisioningPending  = "ProvisioningPending"   // transient, RoleBinding not yet visible
ReasonPermissionDenied     = "PermissionDenied"       // persistent, something is wrong
```

The handler does a direct (uncached) `Get` on the expected RoleBinding by `ManagedRoleBindingName` (not SSAR, which is indirect and expensive). If the RoleBinding exists but the permission is still denied, that's a ClusterRole content issue. If the RoleBinding doesn't exist, it's a provisioning issue. Different condition, different message, different debugging path.

This requires passing the `ManagedRoleBindingName` to the graceful handler, which is a new optional parameter.

### b) Suppress error visibility during provisioning window

For reactive mode (no webhook), the handler sets condition to `ProvisioningPending` instead of `Degraded` on the first 403. Status shows "Waiting for RBAC provisioning" instead of "Permission denied." Transitions to `Degraded` only after a configurable timeout (default 60s). The user sees "setting up" not "broken."

For webhook mode, 403s from informer propagation delay get `ProvisioningPending` with exponential backoff requeue (1s, 2s). If the 403 persists beyond 5 seconds (propagation is typically sub-second but can be longer under load), it transitions to `PermissionDenied`. This gives the authorizer cache multiple cycles to sync before escalating.

## 4. Prometheus Metrics

### Scoper metrics

| Metric | Type | Description |
|--------|------|-------------|
| `rbac_scoper_rolebinding_created_total` | Counter | RoleBindings created, by target SA, namespace, and source (scoper/webhook/label-trigger) |
| `rbac_scoper_rolebinding_deleted_total` | Counter | RoleBindings cleaned up |
| `rbac_scoper_reconcile_errors_total` | Counter | Reconciliation failures, by error type |
| `rbac_scoper_reconcile_duration_seconds` | Histogram | Reconciliation latency |
| `rbac_scoper_orphan_rolebindings` | Gauge | Orphan RoleBindings pending cleanup |
| `rbac_scoper_clusterrole_missing` | Gauge | Whether a configured ClusterRole doesn't exist (0/1) |

### Webhook metrics

| Metric | Type | Description |
|--------|------|-------------|
| `rbac_scoper_webhook_requests_total` | Counter | Webhook invocations, by GVK, result (allowed/rejected/skipped-dryrun), and rejection reason (clusterrole_missing/create_failed/none) |
| `rbac_scoper_webhook_duration_seconds` | Histogram | Webhook latency (should be <100ms) |
| `rbac_scoper_webhook_rolebinding_created_total` | Counter | RoleBindings created via webhook path |
| `rbac_scoper_webhook_already_exists_total` | Counter | AlreadyExists responses (concurrent create, not an error) |
| `rbac_scoper_webhook_errors_total` | Counter | Webhook failures, by error type |

### Graceful degradation metrics

| Metric | Type | Description |
|--------|------|-------------|
| `graceful_permission_denied_total` | Counter | 403s handled, by resource, verb, and reason (provisioning/denied) |
| `graceful_permission_restored_total` | Counter | Permission restorations detected |

## 5. High Availability and Infallibility

### Webhook HA

- 2+ replicas behind a Service (standard K8s webhook pattern)
- No leader election needed. Concurrent RoleBinding creation is handled via AlreadyExists tolerance (create-if-not-exists pattern). Two replicas handling the same namespace simultaneously both succeed.
- PriorityClass to survive node pressure (deployed with the webhook from day one)
- PodDisruptionBudget (minAvailable: 1) to survive voluntary disruptions (deployed with the webhook from day one)
- Deploy in the host operator's namespace (shares the operator's cert infrastructure)
- `timeoutSeconds: 10` on the webhook config
- `failurePolicy: Ignore` initially (graduated to `Fail` after production validation)

### Scoper controller HA

- 2 replicas with leader election (already supported)
- The webhook handles same-namespace provisioning synchronously, so scoper downtime only affects cleanup, drift recovery, cross-namespace provisioning, and namespace label pre-provisioning
- On startup: full resync (list all CRs, verify all RoleBindings, create missing ones, backfill OwnerReferences on webhook-created RoleBindings)

### Failure modes and recovery

| Failure | Impact | Recovery |
|---------|--------|----------|
| Webhook replicas down (failurePolicy: Ignore) | CRs admitted without RoleBinding. Reactive scoper creates it on next reconcile (~seconds). Brief 403 window. | Webhook pods reschedule. No user-visible failure. |
| Webhook replicas down (failurePolicy: Fail) | CR creation blocked for configured GVKs. Existing workloads unaffected. | Webhook pods reschedule. Auto-retrying controllers (KServe) resume on recovery. Document maximum acceptable downtime. |
| Scoper controller down | Webhook still provisions same-namespace RoleBindings. Cross-namespace provisioning paused. Cleanup paused (temporary over-grants). | Leader election failover or pod reschedule. Full resync on startup. |
| API server can't reach webhook | With Ignore: CRs admitted, reactive fallback. With Fail: CR creation blocked. | Standard K8s webhook availability pattern. |
| RoleBinding creation fails in webhook | CR admitted (webhook is always fail-open on create errors). Reactive scoper creates RoleBinding on next reconcile. Brief 403 window. | Admin checks scoper logs/events/metrics for the create error. |
| ClusterRole deleted at runtime | Webhook allows CR but skips RoleBinding creation (logs warning, emits ClusterRoleMissing event). Existing RoleBindings become non-functional. | RBAC audit detects at next scan. Metric `clusterrole_missing` fires alert. Admin redeploys the ClusterRole manifest. |
| Webhook TLS certificate expiry/rotation | API server can't TLS-handshake with webhook. Same as "can't reach webhook." | Use host operator's cert-manager or OpenShift service-ca for automatic rotation. Alert on cert expiry via webhook metric or cert-manager metrics. |
| etcd latency spike (>10s) | Webhook RoleBinding create times out. With Ignore: CR admitted, reactive fallback. With Fail: CR rejected. Possible orphan if write completes after timeout. | etcd recovers. Orphan cleaned by scoper on next scan. |
| Webhook config out-of-sync during rolling update | Old replica serves stale ScopingTarget config. May create RoleBinding with wrong ClusterRole. | Scoper drift recovery corrects on next reconcile. Keep rolling update maxUnavailable: 1 to minimize window. |
| Namespace deletion during webhook processing | RoleBinding creation may fail (namespace terminating). | Webhook handles NotFound/Forbidden on namespace as "allow CR, skip RoleBinding." The namespace is going away anyway. |
| Operator upgrade (rolling update) | Brief window with zero webhook replicas (between old pod termination and new pod readiness). With Ignore: reactive fallback. With Fail: CR creation blocked. | PDB minAvailable: 1 minimizes window. failurePolicy: Ignore eliminates user impact. |
| Auto-retrying controller (KServe) during webhook outage with Fail | Controller fills work queue with rejected creates. Alert storms from operator error metrics. Controllers with finite retry budgets may give up. | After recovery: controllers with exponential backoff resume automatically. For controllers that gave up: touch the parent resource to re-trigger reconciliation, or restart the controller pod. |
| Concurrent label trigger + webhook for same namespace | Both attempt to create the same RoleBinding simultaneously. One gets AlreadyExists. | AlreadyExists treated as success by both paths. If label trigger wins, no pending-owner annotation. Scoper sets OwnerReference when CR creation event triggers normal reconcile path. |

### Recovery from webhook outage (failurePolicy: Fail)

When the webhook recovers after an outage:
1. The webhook pods start and register with the API server.
2. CR creation resumes. Controllers with exponential backoff automatically retry.
3. The scoper runs a full resync, creating any RoleBindings that were missed.
4. Controllers that hit retry budget limits need manual intervention (restart the controller pod or update the parent resource to re-trigger reconciliation).

Document expected maximum webhook downtime for each deployment scenario (rolling update, node failure, cert rotation).

## 6. Debuggability

### Layer 1: Kubernetes Events (for admins and SREs)

The scoper and webhook emit events on every significant action:

```
NAMESPACE    TYPE      REASON                         MESSAGE
notebooks    Normal    RoleBindingCreated             Created RoleBinding odh-dashboard-notebooks-binding for SA odh-dashboard
notebooks    Normal    RoleBindingCreatedViaWebhook   Webhook provisioned RoleBinding for InferenceService creation
notebooks    Normal    RoleBindingAlreadyExists       RoleBinding already existed (concurrent create), no action needed
notebooks    Warning   RoleBindingCreationFailed      Failed to create RoleBinding: ClusterRole odh-dashboard-notebooks not found
notebooks    Warning   ClusterRoleMissing             Static ClusterRole odh-dashboard-notebooks does not exist
notebooks    Normal    RoleBindingDriftCorrected      RoleRef drift detected and corrected
notebooks    Normal    WebhookDryRunSkipped           Skipped RoleBinding creation (dry-run request)
```

### Layer 2: CR Status Conditions (for users via Dashboard UI)

```yaml
status:
  conditions:
    - type: PermissionGranted
      status: "False"
      reason: ProvisioningPending       # transient, will resolve
      message: "Waiting for RBAC provisioning in namespace notebooks"
    # vs:
    - type: PermissionGranted
      status: "False"
      reason: PermissionDenied          # persistent, needs admin attention
      message: "RoleBinding exists but permission denied. Check ClusterRole rules."
    # vs:
    - type: PermissionGranted
      status: "True"
      reason: AllPermissionsAvailable
```

### Layer 3: Prometheus Metrics (for monitoring/alerting)

Key alerts:
- `rbac_scoper_webhook_errors_total` increasing -> webhook is broken
- `rbac_scoper_clusterrole_missing == 1` -> static ClusterRole deleted
- `graceful_permission_denied_total{reason="denied"}` increasing with webhook enabled -> something is very wrong
- `rbac_scoper_webhook_duration_seconds` p99 > 500ms -> webhook latency degradation

### Layer 4: RBAC Health Check

The library exposes an `RBACHealthHandler(cfg Config) http.Handler` that the host operator registers on its debug/metrics server. Returns JSON:

```json
{
  "targets": [
    {
      "name": "odh-dashboard-notebooks",
      "clusterRoleExists": true,
      "managedRoleBindings": 3,
      "orphanRoleBindings": 0,
      "webhookProvisioning": true
    }
  ],
  "webhookRegistered": true,
  "lastFullResync": "2026-07-08T10:15:00Z"
}
```

For liveness probes, a simple `healthz.Checker` (pass/fail) is also exposed via `RBACHealthzCheck(cfg Config) healthz.Checker` for `mgr.AddHealthzCheck("rbac", ...)`.

## 7. Namespace Label Trigger

When enabled via `NamespaceLabelTrigger`, the scoper watches namespace events. When a namespace gets a matching label, it creates RoleBindings for all ScopingTargets that have `NamespaceLabelTrigger` configured.

**Validation:** The namespace label trigger applies the same three validation steps as the webhook and scoper: deny-list check, NamespaceSelector check (if configured), and the target namespace must not be in the deny-list. An attacker who labels `kube-system` does not get RoleBindings created there.

**AlreadyExists tolerance:** If the RoleBinding already exists (created by the webhook or scoper), the label trigger treats `AlreadyExists` as success.

**Lifecycle:** Label-trigger-created RoleBindings have no OwnerReference and no `pending-owner` annotation (there is no CR to own them). Their lifecycle is tied to the namespace label:

- **Label added:** RoleBindings created for all matching ScopingTargets, with `created-by: label-trigger` annotation.
- **Label removed:** The scoper watches namespace label changes. When a namespace no longer matches the `NamespaceLabelTrigger` selector, the scoper deletes all label-trigger-created RoleBindings in that namespace (identified by `created-by: label-trigger` annotation).
- **CR created later:** When a CR is created in a pre-provisioned namespace, the webhook or scoper finds the RoleBinding already exists (AlreadyExists tolerance). The RoleBinding stays label-managed (no OwnerReference added). This is intentional: if the CR is later deleted, the RoleBinding persists because the namespace is still labeled. The pre-provisioning guarantee is preserved across the full CR lifecycle.
- **No CR ever created:** The RoleBinding persists as long as the label is present. This is intentional: the namespace is marked as "AI related" and the permissions are pre-provisioned. Removing the label cleans up.
- **Label-managed vs CR-managed:** Label-trigger-created RoleBindings stay label-managed for their entire lifecycle. They are never converted to CR-managed via OwnerReference. This avoids the problem where CR deletion would GC the RoleBinding and leave the labeled namespace without pre-provisioned permissions until the next resync.

**Security note:** On clusters without the `protect-rbac-allowed-label` VAP, any user with `update namespaces` can trigger RoleBinding creation by labeling a namespace. The label trigger should not be used in multi-tenant environments without the VAP deployed.

**Metrics:** `rbac_scoper_label_trigger_evaluations_total` counter with labels `result` (created/already-exists/denied/selector-mismatch) tracks label trigger activity for observability.

## 8. What Doesn't Change

- Bind-mode only (no escalate verb)
- Static ClusterRoles deployed via operator manifests
- OwnerReference GC for same-namespace, annotation-based for cross-namespace
- Drift recovery and orphan cleanup
- SA protection webhook and impersonation guard
- RBAC audit package
- Cross-namespace provisioning via reactive scoper (webhook is same-namespace only)

## 9. Implementation Order

1. Webhook provisioning + HA hardening (PDB, PriorityClass, cert integration) together. The webhook is fail-open initially so HA matters less, but the manifests are trivial and should ship from day one.
2. Prometheus metrics (enables monitoring before switching to fail-closed)
3. Graceful degradation improvements (ProvisioningPending vs PermissionDenied, direct RoleBinding Get)
4. Namespace label trigger (pre-provisioning)
5. RBAC health check endpoint
6. Graduate to failurePolicy: Fail after production validation with metrics proving webhook reliability
