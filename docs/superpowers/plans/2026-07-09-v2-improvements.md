# V2 Improvements Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make RBAC provisioning infallible by adding webhook-based instant provisioning, Prometheus metrics, graceful degradation improvements, namespace label trigger, and RBAC health check.

**Architecture:** A MutatingAdmissionWebhook creates RoleBindings synchronously during CR admission (near-zero gap). The scoper controller backfills OwnerReferences and handles cleanup. A namespace label trigger pre-provisions RoleBindings. All three paths coordinate via idempotent creates (AlreadyExists tolerance).

**Tech Stack:** Go 1.25, controller-runtime v0.22, Kubernetes admission webhooks, Prometheus client_golang

## Global Constraints

- Webhook handles same-namespace targets only (`WebhookProvisioning: true` rejected with `TargetNamespaceSource != nil`)
- Webhook is always fail-open (never rejects CRs, always allows and falls back to reactive scoper)
- `failurePolicy: Ignore` in Phase 1 (graduated to Fail after production validation)
- Label-trigger RoleBindings stay label-managed (never converted to CR-managed via OwnerReference)
- `pending-owner` annotation format: `namespace/name/GVK/RFC3339-timestamp`
- All provisioning paths handle `AlreadyExists` as success
- No em dashes (-- or ---) in any generated content

---

### Task 1: Add New Types and Constants for Webhook + Label Trigger

**Files:**
- Modify: `pkg/scoper/types.go`
- Test: `pkg/scoper/scoper_test.go` (add validation tests)

**Interfaces:**
- Produces: `ScopingTarget.WebhookProvisioning`, `ScopingTarget.NamespaceLabelTrigger`, `PendingOwnerAnnotationKey`, `CreatedByAnnotationKey`, `CreatedByWebhook`, `CreatedByScoper`, `CreatedByLabelTrigger` constants

- [ ] **Step 1: Write failing test for WebhookProvisioning + TargetNamespaceSource rejection**

```go
func TestValidateTarget_RejectsWebhookWithTargetNamespaceSource(t *testing.T) {
	target := ScopingTarget{
		WatchGVK:            schema.GroupVersionKind{Kind: "Foo"},
		TargetSA:            types.NamespacedName{Name: "sa", Namespace: "ns"},
		ClusterRoleName:     "role",
		ManagedRoleBindingName: "binding",
		WebhookProvisioning: true,
		TargetNamespaceSource: &NamespaceSource{FieldPath: ".spec.namespace"},
	}
	err := validateTarget(target)
	if err == nil {
		t.Fatal("expected error for WebhookProvisioning + TargetNamespaceSource")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/ugogiordano/workdir/rhoai/operator-rbac-toolkit && go test ./pkg/scoper/ -run TestValidateTarget_RejectsWebhookWithTargetNamespaceSource -v`
Expected: FAIL (field doesn't exist yet)

- [ ] **Step 3: Add new fields to ScopingTarget and new constants**

In `pkg/scoper/types.go`, add to the `ScopingTarget` struct:

```go
type ScopingTarget struct {
	WatchGVK               schema.GroupVersionKind
	TargetSA               types.NamespacedName
	ClusterRoleName        string
	ManagedRoleBindingName string
	NamespaceSelector      *metav1.LabelSelector
	TargetNamespaceSource  *NamespaceSource

	// New: enable MutatingAdmissionWebhook provisioning (same-namespace only)
	WebhookProvisioning bool

	// New: pre-provision RoleBindings when namespaces match this label selector
	NamespaceLabelTrigger *metav1.LabelSelector
}
```

Add new constants:

```go
const (
	OwnerAnnotationKey = "operator-rbac-toolkit.io/scoped-access-owners"
	ManagedLabelKey    = "operator-rbac-toolkit.io/managed"
	ManagedLabelValue  = "true"

	PendingOwnerAnnotationKey = "operator-rbac-toolkit.io/pending-owner"
	CreatedByAnnotationKey    = "operator-rbac-toolkit.io/created-by"
	CreatedByWebhook          = "webhook"
	CreatedByScoper           = "scoper"
	CreatedByLabelTrigger     = "label-trigger"
)
```

Add validation in `validateTarget()`:

```go
if t.WebhookProvisioning && t.TargetNamespaceSource != nil {
	return fmt.Errorf("WebhookProvisioning cannot be used with TargetNamespaceSource (webhook is same-namespace only)")
}
```

- [ ] **Step 4: Run tests**

Run: `go test ./pkg/scoper/ -v`
Expected: All tests pass including new validation test

- [ ] **Step 5: Commit**

```bash
git add pkg/scoper/types.go pkg/scoper/scoper_test.go
git commit -m "feat(scoper): add webhook and label-trigger fields to ScopingTarget"
```

---

### Task 2: Implement Provisioning Webhook Handler

**Files:**
- Create: `pkg/scoper/webhook.go`
- Create: `pkg/scoper/webhook_test.go`

**Interfaces:**
- Consumes: `ScopingTarget`, `IsDenied()`, `ValidateClusterRole()`, `ManagedLabelKey`, `PendingOwnerAnnotationKey`, `CreatedByAnnotationKey` from Task 1
- Produces: `ProvisioningWebhookHandler` implementing `admission.Handler`

- [ ] **Step 1: Write failing test for webhook allowing non-matching GVK**

```go
func TestWebhook_NonMatchingGVK_Allowed(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = rbacv1.AddToScheme(scheme)

	handler := NewProvisioningWebhookHandler(
		fake.NewClientBuilder().WithScheme(scheme).Build(),
		[]ScopingTarget{{
			WatchGVK:            schema.GroupVersionKind{Group: "test", Version: "v1", Kind: "Foo"},
			TargetSA:            types.NamespacedName{Name: "sa", Namespace: "ns"},
			ClusterRoleName:     "role",
			ManagedRoleBindingName: "binding",
			WebhookProvisioning: true,
		}},
		DefaultDenyList("scoper-system"),
	)

	req := admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			Operation: admissionv1.Create,
			Resource:  metav1.GroupVersionResource{Group: "other", Version: "v1", Resource: "bars"},
			Namespace: "user-ns",
		},
	}
	resp := handler.Handle(context.Background(), req)
	if !resp.Allowed {
		t.Fatalf("expected allowed for non-matching GVK, got denied: %s", resp.Result.Message)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./pkg/scoper/ -run TestWebhook_NonMatchingGVK -v`
Expected: FAIL (NewProvisioningWebhookHandler not defined)

- [ ] **Step 3: Implement webhook handler**

Create `pkg/scoper/webhook.go`:

```go
package scoper

import (
	"context"
	"fmt"
	"time"

	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

type ProvisioningWebhookHandler struct {
	client   client.Client
	targets  map[schema.GroupVersionResource]ScopingTarget
	denyList DenyListConfig
	selectors map[schema.GroupVersionResource]labels.Selector
}

func NewProvisioningWebhookHandler(c client.Client, targets []ScopingTarget, denyList DenyListConfig) *ProvisioningWebhookHandler {
	targetMap := make(map[schema.GroupVersionResource]ScopingTarget)
	selectorMap := make(map[schema.GroupVersionResource]labels.Selector)
	for _, t := range targets {
		if !t.WebhookProvisioning {
			continue
		}
		gvr := schema.GroupVersionResource{
			Group:    t.WatchGVK.Group,
			Version:  t.WatchGVK.Version,
			Resource: pluralize(t.WatchGVK.Kind),
		}
		targetMap[gvr] = t
		if t.NamespaceSelector != nil {
			sel, err := metav1.LabelSelectorAsSelector(t.NamespaceSelector)
			if err == nil {
				selectorMap[gvr] = sel
			}
		}
	}
	return &ProvisioningWebhookHandler{
		client:    c,
		targets:   targetMap,
		denyList:  denyList,
		selectors: selectorMap,
	}
}

func (h *ProvisioningWebhookHandler) Handle(ctx context.Context, req admission.Request) admission.Response {
	logger := log.FromContext(ctx).WithValues("namespace", req.Namespace, "resource", req.Resource.String())

	target, found := h.targets[req.Resource]
	if !found {
		return admission.Allowed("no matching scoping target")
	}

	// Step 1: deny-list check
	if IsDenied(req.Namespace, h.denyList) {
		return admission.Allowed("namespace is in deny-list, skipping RoleBinding")
	}

	// Step 1.5: NamespaceSelector check
	if sel, ok := h.selectors[req.Resource]; ok {
		ns := &corev1.Namespace{}
		if err := h.client.Get(ctx, types.NamespacedName{Name: req.Namespace}, ns); err != nil {
			logger.Error(err, "failed to get namespace for selector check")
			return admission.Allowed("failed to check namespace selector, allowing CR")
		}
		if !sel.Matches(labels.Set(ns.Labels)) {
			return admission.Allowed("namespace does not match selector, skipping RoleBinding")
		}
	}

	// Step 2: check if RoleBinding already exists (direct API, not cached)
	rbName := types.NamespacedName{Name: target.ManagedRoleBindingName, Namespace: req.Namespace}
	existing := &rbacv1.RoleBinding{}
	if err := h.client.Get(ctx, rbName, existing); err == nil {
		return admission.Allowed("RoleBinding already exists")
	}

	// Step 3: validate ClusterRole exists
	if err := ValidateClusterRole(ctx, h.client, target.ClusterRoleName); err != nil {
		logger.Error(err, "ClusterRole validation failed, allowing CR without RoleBinding")
		return admission.Allowed(fmt.Sprintf("ClusterRole %s not found, skipping RoleBinding", target.ClusterRoleName))
	}

	// Step 3.5: dry-run check (after validation so dry-run catches config errors via logs)
	if req.DryRun != nil && *req.DryRun {
		return admission.Allowed("dry-run, skipping RoleBinding creation")
	}

	// Step 4: create RoleBinding
	rb := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      target.ManagedRoleBindingName,
			Namespace: req.Namespace,
			Labels: map[string]string{
				ManagedLabelKey: ManagedLabelValue,
			},
			Annotations: map[string]string{
				PendingOwnerAnnotationKey: fmt.Sprintf("%s/%s/%s/%s/%s/%s",
					req.Namespace, req.Name,
					target.WatchGVK.Group, target.WatchGVK.Version, target.WatchGVK.Kind,
					time.Now().UTC().Format(time.RFC3339)),
				CreatedByAnnotationKey: CreatedByWebhook,
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "ClusterRole",
			Name:     target.ClusterRoleName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      rbacv1.ServiceAccountKind,
				Name:      target.TargetSA.Name,
				Namespace: target.TargetSA.Namespace,
			},
		},
	}

	if err := h.client.Create(ctx, rb); err != nil {
		if apierrors.IsAlreadyExists(err) {
			return admission.Allowed("RoleBinding already exists (concurrent create)")
		}
		logger.Error(err, "failed to create RoleBinding, allowing CR anyway")
		return admission.Allowed("RoleBinding creation failed, reactive scoper will handle")
	}

	logger.Info("webhook provisioned RoleBinding", "roleBinding", rbName)
	return admission.Allowed("RoleBinding provisioned")
}

func pluralize(kind string) string {
	// Simple pluralization for common patterns
	k := strings.ToLower(kind)
	if strings.HasSuffix(k, "s") {
		return k + "es"
	}
	return k + "s"
}
```

Add the missing import for `corev1` and `strings` at the top.

- [ ] **Step 4: Write comprehensive tests**

Create `pkg/scoper/webhook_test.go` with tests for:
- Non-matching GVK -> allowed
- Denied namespace -> allowed, no RoleBinding
- NamespaceSelector mismatch -> allowed, no RoleBinding
- RoleBinding already exists -> allowed, skip
- ClusterRole missing -> allowed, no RoleBinding (fail-open)
- Dry-run -> allowed, no RoleBinding created
- Successful creation -> allowed, RoleBinding created with pending-owner annotation
- AlreadyExists on create -> allowed (concurrent)
- Create error -> allowed (fail-open)

- [ ] **Step 5: Run tests**

Run: `go test ./pkg/scoper/ -v`
Expected: All tests pass

- [ ] **Step 6: Commit**

```bash
git add pkg/scoper/webhook.go pkg/scoper/webhook_test.go
git commit -m "feat(scoper): implement provisioning webhook handler"
```

---

### Task 3: Implement Prometheus Metrics

**Files:**
- Create: `pkg/scoper/metrics.go`
- Create: `pkg/graceful/metrics.go`
- Modify: `pkg/scoper/reconciler.go` (add metric calls)
- Modify: `pkg/scoper/cleanup.go` (add metric calls)
- Modify: `pkg/scoper/webhook.go` (add metric calls)
- Modify: `pkg/graceful/graceful.go` (add metric calls)

**Interfaces:**
- Produces: `metrics.RoleBindingCreated`, `metrics.WebhookRequests`, `metrics.WebhookDuration`, `metrics.PermissionDenied`, etc.

- [ ] **Step 1: Create scoper metrics registry**

Create `pkg/scoper/metrics.go`:

```go
package scoper

import (
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

var (
	roleBindingCreatedTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "rbac_scoper_rolebinding_created_total",
			Help: "Total RoleBindings created",
		},
		[]string{"target_sa", "namespace", "source"},
	)

	roleBindingDeletedTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "rbac_scoper_rolebinding_deleted_total",
			Help: "Total RoleBindings deleted",
		},
		[]string{"target_sa", "namespace"},
	)

	reconcileErrorsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "rbac_scoper_reconcile_errors_total",
			Help: "Total reconciliation errors",
		},
		[]string{"error_type"},
	)

	reconcileDuration = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "rbac_scoper_reconcile_duration_seconds",
			Help:    "Reconciliation latency",
			Buckets: prometheus.DefBuckets,
		},
	)

	orphanRoleBindings = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "rbac_scoper_orphan_rolebindings",
			Help: "Current count of orphan RoleBindings pending cleanup",
		},
	)

	clusterRoleMissing = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "rbac_scoper_clusterrole_missing",
			Help: "Whether a configured ClusterRole does not exist (0=present, 1=missing)",
		},
		[]string{"clusterrole"},
	)

	webhookRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "rbac_scoper_webhook_requests_total",
			Help: "Webhook invocations",
		},
		[]string{"gvk", "result", "reason"},
	)

	webhookDuration = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "rbac_scoper_webhook_duration_seconds",
			Help:    "Webhook latency",
			Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0},
		},
	)

	webhookRoleBindingCreatedTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "rbac_scoper_webhook_rolebinding_created_total",
			Help: "RoleBindings created via webhook path",
		},
	)

	webhookAlreadyExistsTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "rbac_scoper_webhook_already_exists_total",
			Help: "AlreadyExists responses in webhook (concurrent create)",
		},
	)

	webhookErrorsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "rbac_scoper_webhook_errors_total",
			Help: "Webhook failures",
		},
		[]string{"error_type"},
	)

	labelTriggerEvaluationsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "rbac_scoper_label_trigger_evaluations_total",
			Help: "Label trigger evaluations",
		},
		[]string{"result"},
	)
)

func init() {
	metrics.Registry.MustRegister(
		roleBindingCreatedTotal,
		roleBindingDeletedTotal,
		reconcileErrorsTotal,
		reconcileDuration,
		orphanRoleBindings,
		clusterRoleMissing,
		webhookRequestsTotal,
		webhookDuration,
		webhookRoleBindingCreatedTotal,
		webhookAlreadyExistsTotal,
		webhookErrorsTotal,
		labelTriggerEvaluationsTotal,
	)
}
```

- [ ] **Step 2: Create graceful metrics**

Create `pkg/graceful/metrics.go`:

```go
package graceful

import (
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

var (
	permissionDeniedTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "graceful_permission_denied_total",
			Help: "403 errors handled",
		},
		[]string{"resource", "verb", "reason"},
	)

	permissionRestoredTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "graceful_permission_restored_total",
			Help: "Permission restorations detected",
		},
	)
)

func init() {
	metrics.Registry.MustRegister(
		permissionDeniedTotal,
		permissionRestoredTotal,
	)
}
```

- [ ] **Step 3: Add metric calls to webhook handler**

In `pkg/scoper/webhook.go` Handle method, add `time.Now()` at the start, `webhookDuration.Observe()` via defer, and increment `webhookRequestsTotal` with appropriate labels at each return point.

- [ ] **Step 4: Add metric calls to scoper reconciler**

In `pkg/scoper/reconciler.go`, add `reconcileDuration.Observe()` via defer in Reconcile, `roleBindingCreatedTotal.Inc()` in createRoleBinding, `clusterRoleMissing.Set()` in ValidateClusterRole check.

- [ ] **Step 5: Add metric calls to graceful handler**

In `pkg/graceful/graceful.go`, increment `permissionDeniedTotal` on Forbidden, `permissionRestoredTotal` on restoration.

- [ ] **Step 6: Add prometheus dependency**

Run: `go get github.com/prometheus/client_golang`

- [ ] **Step 7: Run tests**

Run: `go build ./... && go test ./... -v`
Expected: All pass

- [ ] **Step 8: Commit**

```bash
git add pkg/scoper/metrics.go pkg/graceful/metrics.go pkg/scoper/reconciler.go pkg/scoper/webhook.go pkg/graceful/graceful.go go.mod go.sum
git commit -m "feat: implement Prometheus metrics for scoper, webhook, and graceful"
```

---

### Task 4: Implement Graceful Degradation v2 (ProvisioningPending vs PermissionDenied)

**Files:**
- Modify: `pkg/graceful/types.go` (add new condition reasons, optional ManagedRoleBindingName)
- Modify: `pkg/graceful/graceful.go` (add RoleBinding existence check, provisioning window logic)
- Modify: `pkg/graceful/graceful_test.go` (add tests for new behavior)

**Interfaces:**
- Consumes: `ManagedRoleBindingName` from scoper types
- Produces: `ReasonProvisioningPending`, `ReasonPermissionDenied`, `WithManagedRoleBindingName()` option

- [ ] **Step 1: Add new types and option**

In `pkg/graceful/types.go`, add:

```go
const (
	ReasonProvisioningPending = "ProvisioningPending"
	ReasonPermissionDenied    = "PermissionDenied"
)
```

Add option:

```go
func WithManagedRoleBindingName(name string) Option {
	return func(o *Options) {
		o.ManagedRoleBindingName = name
	}
}
```

Add field to Options:

```go
type Options struct {
	RequeueAfter           time.Duration
	MaxRequeue             time.Duration
	BackoffFactor          float64
	ManagedRoleBindingName string
}
```

- [ ] **Step 2: Update Handler.Do to distinguish provisioning from denied**

In `pkg/graceful/graceful.go`, when a Forbidden error is detected and `ManagedRoleBindingName` is set, do a direct Get on the expected RoleBinding. If it doesn't exist, use `ReasonProvisioningPending`. If it exists but permission is denied, use `ReasonPermissionDenied`.

- [ ] **Step 3: Write tests for new behavior**

Test cases:
- Forbidden + no ManagedRoleBindingName -> uses existing behavior (MissingPermissions)
- Forbidden + ManagedRoleBindingName set + RoleBinding missing -> ProvisioningPending
- Forbidden + ManagedRoleBindingName set + RoleBinding exists -> PermissionDenied

- [ ] **Step 4: Run tests**

Run: `go test ./pkg/graceful/ -v`
Expected: All pass

- [ ] **Step 5: Commit**

```bash
git add pkg/graceful/
git commit -m "feat(graceful): distinguish ProvisioningPending from PermissionDenied"
```

---

### Task 5: Implement Pending-Owner Backfill in Scoper

**Files:**
- Modify: `pkg/scoper/reconciler.go` (add pending-owner backfill logic)
- Modify: `pkg/scoper/scoper_test.go` (add backfill tests)

**Interfaces:**
- Consumes: `PendingOwnerAnnotationKey`, `CreatedByAnnotationKey` from Task 1
- Produces: Backfill logic that sets OwnerReference and removes pending-owner annotation atomically

- [ ] **Step 1: Write failing test for pending-owner backfill**

```go
func TestPendingOwnerBackfill(t *testing.T) {
	// Create a RoleBinding with pending-owner annotation
	// Create the CR it references
	// Run reconciler
	// Verify OwnerReference is set and pending-owner annotation is removed
}
```

- [ ] **Step 2: Implement backfill in ensureRoleBinding**

After the existing RoleBinding existence check in `ensureRoleBinding`, check for the `PendingOwnerAnnotationKey` annotation. If present and the CR exists (has a UID), set the OwnerReference and remove the annotation in a single Update. If the CR doesn't exist and the timestamp is within the TTL (30s), requeue after 2s. If past TTL, stop requeueing (defer to periodic cleanup).

- [ ] **Step 3: Run tests**

Run: `go test ./pkg/scoper/ -v`
Expected: All pass

- [ ] **Step 4: Commit**

```bash
git add pkg/scoper/reconciler.go pkg/scoper/scoper_test.go
git commit -m "feat(scoper): implement pending-owner backfill with TTL-capped requeue"
```

---

### Task 6: Implement Namespace Label Trigger

**Files:**
- Create: `pkg/scoper/label_trigger.go`
- Create: `pkg/scoper/label_trigger_test.go`
- Modify: `pkg/scoper/scoper.go` (register label trigger controller)

**Interfaces:**
- Consumes: `ScopingTarget.NamespaceLabelTrigger`, `IsDenied()`, `ValidateClusterRole()`, `ManagedLabelKey`, `CreatedByAnnotationKey`
- Produces: `LabelTriggerReconciler` that watches namespace label events and creates/deletes RoleBindings

- [ ] **Step 1: Write failing test for label trigger creating RoleBinding**

- [ ] **Step 2: Implement LabelTriggerReconciler**

Create `pkg/scoper/label_trigger.go` with a reconciler that:
- Watches Namespace events
- When a namespace matches the label selector: create RoleBinding with `created-by: label-trigger` annotation, ManagedLabel, no OwnerReference, no pending-owner
- When a namespace no longer matches (label removed): delete RoleBindings with `created-by: label-trigger` in that namespace
- Apply deny-list and NamespaceSelector validation
- Handle AlreadyExists as success
- Increment `labelTriggerEvaluationsTotal` metric

- [ ] **Step 3: Register in Setup function**

In `pkg/scoper/scoper.go`, for each target with `NamespaceLabelTrigger != nil`, register a `LabelTriggerReconciler`.

- [ ] **Step 4: Write tests for label removal cleanup**

- [ ] **Step 5: Run tests**

Run: `go test ./pkg/scoper/ -v`
Expected: All pass

- [ ] **Step 6: Commit**

```bash
git add pkg/scoper/label_trigger.go pkg/scoper/label_trigger_test.go pkg/scoper/scoper.go
git commit -m "feat(scoper): implement namespace label trigger for pre-provisioning"
```

---

### Task 7: Implement RBAC Health Check Endpoint

**Files:**
- Create: `pkg/scoper/health.go`
- Create: `pkg/scoper/health_test.go`

**Interfaces:**
- Consumes: `Config`, `ValidateClusterRole()`, `ManagedLabelKey`
- Produces: `RBACHealthHandler(cfg Config, c client.Client) http.Handler` and `RBACHealthzCheck(cfg Config, c client.Client) healthz.Checker`

- [ ] **Step 1: Write failing test for health handler**

```go
func TestRBACHealthHandler_ReturnsJSON(t *testing.T) {
	// Create fake client with a ClusterRole and some RoleBindings
	// Call the handler
	// Verify JSON response with target status
}
```

- [ ] **Step 2: Implement health handler**

Create `pkg/scoper/health.go`:
- `RBACHealthHandler()` returns JSON with target status, ClusterRole existence, managed RoleBinding count, orphan count
- `RBACHealthzCheck()` returns pass/fail based on whether all ClusterRoles exist

- [ ] **Step 3: Write tests**

- [ ] **Step 4: Run tests**

Run: `go test ./pkg/scoper/ -v`
Expected: All pass

- [ ] **Step 5: Commit**

```bash
git add pkg/scoper/health.go pkg/scoper/health_test.go
git commit -m "feat(scoper): implement RBAC health check endpoint"
```

---

### Task 8: Integration Test and Final Verification

**Files:**
- Modify: `pkg/scoper/scoper.go` (wire webhook registration helper)
- Create: `pkg/scoper/webhook_registration.go` (MutatingWebhookConfiguration generation)

- [ ] **Step 1: Create webhook registration helper**

Create a function that generates the MutatingWebhookConfiguration resource from the Config's ScopingTargets.

- [ ] **Step 2: Full build and test**

Run: `go build ./... && go vet ./... && go test ./...`
Expected: All pass

- [ ] **Step 3: Commit and push**

```bash
git add -A
git commit -m "feat: complete v2 improvements (webhook, metrics, graceful v2, label trigger, health)"
git push origin main
```
