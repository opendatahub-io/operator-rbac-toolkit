package scoper

import (
	"context"
	"fmt"
	"strings"
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

func TestWebhook_NonMatchingGVK_Allowed(t *testing.T) {
	scheme := testScheme()

	handler := NewProvisioningWebhookHandler(
		fake.NewClientBuilder().WithScheme(scheme).Build(),
		[]ScopingTarget{{
			WatchGVK:               schema.GroupVersionKind{Group: "test", Version: "v1", Kind: "Foo"},
			TargetSA:               types.NamespacedName{Name: "sa", Namespace: "ns"},
			ClusterRoleName:        "role",
			ManagedRoleBindingName: "binding",
			WebhookProvisioning:    true,
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

func TestWebhook_DeniedNamespace_Allowed_NoRoleBinding(t *testing.T) {
	scheme := testScheme()
	c := fake.NewClientBuilder().WithScheme(scheme).Build()

	handler := NewProvisioningWebhookHandler(
		c,
		[]ScopingTarget{{
			WatchGVK:               schema.GroupVersionKind{Group: "test", Version: "v1", Kind: "Foo"},
			TargetSA:               types.NamespacedName{Name: "sa", Namespace: "ns"},
			ClusterRoleName:        "role",
			ManagedRoleBindingName: "binding",
			WebhookProvisioning:    true,
		}},
		DefaultDenyList("scoper-system"),
	)

	req := admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			Operation: admissionv1.Create,
			Resource:  metav1.GroupVersionResource{Group: "test", Version: "v1", Resource: "foos"},
			Namespace: "kube-system", // denied
			Name:      "test-foo",
		},
	}
	resp := handler.Handle(context.Background(), req)
	if !resp.Allowed {
		t.Fatalf("expected allowed for denied namespace, got denied: %s", resp.Result.Message)
	}

	// Verify no RoleBinding was created
	rb := &rbacv1.RoleBinding{}
	err := c.Get(context.Background(), types.NamespacedName{Name: "binding", Namespace: "kube-system"}, rb)
	if !apierrors.IsNotFound(err) {
		t.Errorf("expected RoleBinding to not exist in denied namespace, got: %v", err)
	}
}

func TestWebhook_NamespaceSelectorMismatch_Allowed_NoRoleBinding(t *testing.T) {
	scheme := testScheme()

	// Create namespace without the required label
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "user-ns",
			Labels: map[string]string{"env": "prod"},
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(ns).Build()

	handler := NewProvisioningWebhookHandler(
		c,
		[]ScopingTarget{{
			WatchGVK:               schema.GroupVersionKind{Group: "test", Version: "v1", Kind: "Foo"},
			TargetSA:               types.NamespacedName{Name: "sa", Namespace: "ns"},
			ClusterRoleName:        "role",
			ManagedRoleBindingName: "binding",
			WebhookProvisioning:    true,
			NamespaceSelector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"env": "dev"}, // requires dev, namespace has prod
			},
		}},
		DefaultDenyList("scoper-system"),
	)

	req := admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			Operation: admissionv1.Create,
			Resource:  metav1.GroupVersionResource{Group: "test", Version: "v1", Resource: "foos"},
			Namespace: "user-ns",
			Name:      "test-foo",
		},
	}
	resp := handler.Handle(context.Background(), req)
	if !resp.Allowed {
		t.Fatalf("expected allowed for namespace selector mismatch, got denied: %s", resp.Result.Message)
	}

	// Verify no RoleBinding was created
	rb := &rbacv1.RoleBinding{}
	err := c.Get(context.Background(), types.NamespacedName{Name: "binding", Namespace: "user-ns"}, rb)
	if !apierrors.IsNotFound(err) {
		t.Errorf("expected RoleBinding to not exist when selector doesn't match, got: %v", err)
	}
}

func TestWebhook_NamespaceSelectorMatch_CreatesRoleBinding(t *testing.T) {
	scheme := testScheme()

	// Create namespace with matching label
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "user-ns",
			Labels: map[string]string{"env": "dev"},
		},
	}

	cr := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "role"},
		Rules:      []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}}},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(ns, cr).Build()

	handler := NewProvisioningWebhookHandler(
		c,
		[]ScopingTarget{{
			WatchGVK:               schema.GroupVersionKind{Group: "test", Version: "v1", Kind: "Foo"},
			TargetSA:               types.NamespacedName{Name: "sa", Namespace: "ns"},
			ClusterRoleName:        "role",
			ManagedRoleBindingName: "binding",
			WebhookProvisioning:    true,
			NamespaceSelector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"env": "dev"},
			},
		}},
		DefaultDenyList("scoper-system"),
	)

	req := admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			Operation: admissionv1.Create,
			Resource:  metav1.GroupVersionResource{Group: "test", Version: "v1", Resource: "foos"},
			Namespace: "user-ns",
			Name:      "test-foo",
		},
	}
	resp := handler.Handle(context.Background(), req)
	if !resp.Allowed {
		t.Fatalf("expected allowed, got denied: %s", resp.Result.Message)
	}

	// Verify RoleBinding was created
	rb := &rbacv1.RoleBinding{}
	if err := c.Get(context.Background(), types.NamespacedName{Name: "binding", Namespace: "user-ns"}, rb); err != nil {
		t.Fatalf("expected RoleBinding to exist when selector matches, got error: %v", err)
	}
}

func TestWebhook_RoleBindingAlreadyExists_Allowed_Skip(t *testing.T) {
	scheme := testScheme()

	existingRB := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "binding",
			Namespace: "user-ns",
		},
		RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "role"},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(existingRB).Build()

	handler := NewProvisioningWebhookHandler(
		c,
		[]ScopingTarget{{
			WatchGVK:               schema.GroupVersionKind{Group: "test", Version: "v1", Kind: "Foo"},
			TargetSA:               types.NamespacedName{Name: "sa", Namespace: "ns"},
			ClusterRoleName:        "role",
			ManagedRoleBindingName: "binding",
			WebhookProvisioning:    true,
		}},
		DefaultDenyList("scoper-system"),
	)

	req := admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			Operation: admissionv1.Create,
			Resource:  metav1.GroupVersionResource{Group: "test", Version: "v1", Resource: "foos"},
			Namespace: "user-ns",
			Name:      "test-foo",
		},
	}
	resp := handler.Handle(context.Background(), req)
	if !resp.Allowed {
		t.Fatalf("expected allowed when RoleBinding exists, got denied: %s", resp.Result.Message)
	}

	// Verify the existing RoleBinding was not modified
	rb := &rbacv1.RoleBinding{}
	if err := c.Get(context.Background(), types.NamespacedName{Name: "binding", Namespace: "user-ns"}, rb); err != nil {
		t.Fatalf("failed to get RoleBinding: %v", err)
	}
	// Original RoleBinding didn't have managed label, so it should still not have it
	if _, ok := rb.Labels[ManagedLabelKey]; ok {
		t.Error("expected existing RoleBinding to not be modified")
	}
}

func TestWebhook_ClusterRoleMissing_Allowed_NoRoleBinding(t *testing.T) {
	scheme := testScheme()
	c := fake.NewClientBuilder().WithScheme(scheme).Build()

	handler := NewProvisioningWebhookHandler(
		c,
		[]ScopingTarget{{
			WatchGVK:               schema.GroupVersionKind{Group: "test", Version: "v1", Kind: "Foo"},
			TargetSA:               types.NamespacedName{Name: "sa", Namespace: "ns"},
			ClusterRoleName:        "missing-role",
			ManagedRoleBindingName: "binding",
			WebhookProvisioning:    true,
		}},
		DefaultDenyList("scoper-system"),
	)

	req := admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			Operation: admissionv1.Create,
			Resource:  metav1.GroupVersionResource{Group: "test", Version: "v1", Resource: "foos"},
			Namespace: "user-ns",
			Name:      "test-foo",
		},
	}
	resp := handler.Handle(context.Background(), req)
	if !resp.Allowed {
		t.Fatalf("expected allowed for missing ClusterRole (fail-open), got denied: %s", resp.Result.Message)
	}

	// Verify no RoleBinding was created
	rb := &rbacv1.RoleBinding{}
	err := c.Get(context.Background(), types.NamespacedName{Name: "binding", Namespace: "user-ns"}, rb)
	if !apierrors.IsNotFound(err) {
		t.Errorf("expected RoleBinding to not exist when ClusterRole is missing, got: %v", err)
	}
}

func TestWebhook_DryRun_Allowed_NoRoleBinding(t *testing.T) {
	scheme := testScheme()

	cr := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "role"},
		Rules:      []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}}},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cr).Build()

	handler := NewProvisioningWebhookHandler(
		c,
		[]ScopingTarget{{
			WatchGVK:               schema.GroupVersionKind{Group: "test", Version: "v1", Kind: "Foo"},
			TargetSA:               types.NamespacedName{Name: "sa", Namespace: "ns"},
			ClusterRoleName:        "role",
			ManagedRoleBindingName: "binding",
			WebhookProvisioning:    true,
		}},
		DefaultDenyList("scoper-system"),
	)

	dryRun := true
	req := admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			Operation: admissionv1.Create,
			Resource:  metav1.GroupVersionResource{Group: "test", Version: "v1", Resource: "foos"},
			Namespace: "user-ns",
			Name:      "test-foo",
			DryRun:    &dryRun,
		},
	}
	resp := handler.Handle(context.Background(), req)
	if !resp.Allowed {
		t.Fatalf("expected allowed for dry-run, got denied: %s", resp.Result.Message)
	}

	// Verify no RoleBinding was created
	rb := &rbacv1.RoleBinding{}
	err := c.Get(context.Background(), types.NamespacedName{Name: "binding", Namespace: "user-ns"}, rb)
	if !apierrors.IsNotFound(err) {
		t.Errorf("expected RoleBinding to not exist on dry-run, got: %v", err)
	}
}

func TestWebhook_SuccessfulCreation_Allowed_RoleBindingWithAnnotations(t *testing.T) {
	scheme := testScheme()

	cr := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "role"},
		Rules:      []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}}},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cr).Build()

	handler := NewProvisioningWebhookHandler(
		c,
		[]ScopingTarget{{
			WatchGVK:               schema.GroupVersionKind{Group: "test.io", Version: "v1", Kind: "Foo"},
			TargetSA:               types.NamespacedName{Name: "sa", Namespace: "sa-ns"},
			ClusterRoleName:        "role",
			ManagedRoleBindingName: "binding",
			WebhookProvisioning:    true,
		}},
		DefaultDenyList("scoper-system"),
	)

	req := admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			Operation: admissionv1.Create,
			Resource:  metav1.GroupVersionResource{Group: "test.io", Version: "v1", Resource: "foos"},
			Namespace: "user-ns",
			Name:      "test-foo",
		},
	}
	resp := handler.Handle(context.Background(), req)
	if !resp.Allowed {
		t.Fatalf("expected allowed, got denied: %s", resp.Result.Message)
	}

	// Verify RoleBinding was created with correct annotations and labels
	rb := &rbacv1.RoleBinding{}
	if err := c.Get(context.Background(), types.NamespacedName{Name: "binding", Namespace: "user-ns"}, rb); err != nil {
		t.Fatalf("expected RoleBinding to exist, got error: %v", err)
	}

	// Check managed label
	if rb.Labels[ManagedLabelKey] != ManagedLabelValue {
		t.Errorf("expected managed label %s=%s, got %v", ManagedLabelKey, ManagedLabelValue, rb.Labels)
	}

	// Check created-by annotation
	if rb.Annotations[CreatedByAnnotationKey] != CreatedByWebhook {
		t.Errorf("expected created-by annotation %s=%s, got %v", CreatedByAnnotationKey, CreatedByWebhook, rb.Annotations)
	}

	// Check pending-owner annotation format: namespace/name/group/version/kind/timestamp
	pendingOwner := rb.Annotations[PendingOwnerAnnotationKey]
	if pendingOwner == "" {
		t.Fatal("expected pending-owner annotation to be set")
	}
	parts := strings.Split(pendingOwner, "/")
	if len(parts) != 6 {
		t.Fatalf("expected pending-owner to have 6 parts (namespace/name/group/version/kind/timestamp), got %d: %s", len(parts), pendingOwner)
	}
	if parts[0] != "user-ns" {
		t.Errorf("expected namespace 'user-ns' in pending-owner, got %s", parts[0])
	}
	if parts[1] != "test-foo" {
		t.Errorf("expected name 'test-foo' in pending-owner, got %s", parts[1])
	}
	if parts[2] != "test.io" {
		t.Errorf("expected group 'test.io' in pending-owner, got %s", parts[2])
	}
	if parts[3] != "v1" {
		t.Errorf("expected version 'v1' in pending-owner, got %s", parts[3])
	}
	if parts[4] != "Foo" {
		t.Errorf("expected kind 'Foo' in pending-owner, got %s", parts[4])
	}
	// parts[5] is timestamp, just check it's not empty
	if parts[5] == "" {
		t.Error("expected timestamp in pending-owner, got empty string")
	}

	// Check RoleRef
	if rb.RoleRef.Kind != "ClusterRole" || rb.RoleRef.Name != "role" {
		t.Errorf("expected RoleRef to ClusterRole 'role', got %v", rb.RoleRef)
	}

	// Check Subject
	if len(rb.Subjects) != 1 {
		t.Fatalf("expected 1 subject, got %d", len(rb.Subjects))
	}
	if rb.Subjects[0].Kind != rbacv1.ServiceAccountKind || rb.Subjects[0].Name != "sa" || rb.Subjects[0].Namespace != "sa-ns" {
		t.Errorf("expected ServiceAccount sa/sa-ns, got %v", rb.Subjects[0])
	}
}

func TestWebhook_AlreadyExistsOnCreate_Allowed(t *testing.T) {
	scheme := testScheme()

	cr := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "role"},
		Rules:      []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}}},
	}

	// Use a client interceptor to simulate AlreadyExists on Create
	// The fake client doesn't support this directly, so we'll use a custom client
	baseClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cr).Build()
	c := &clientWithCreateError{
		Client: baseClient,
		createErr: apierrors.NewAlreadyExists(
			schema.GroupResource{Group: "rbac.authorization.k8s.io", Resource: "rolebindings"},
			"binding",
		),
	}

	handler := NewProvisioningWebhookHandler(
		c,
		[]ScopingTarget{{
			WatchGVK:               schema.GroupVersionKind{Group: "test", Version: "v1", Kind: "Foo"},
			TargetSA:               types.NamespacedName{Name: "sa", Namespace: "ns"},
			ClusterRoleName:        "role",
			ManagedRoleBindingName: "binding",
			WebhookProvisioning:    true,
		}},
		DefaultDenyList("scoper-system"),
	)

	req := admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			Operation: admissionv1.Create,
			Resource:  metav1.GroupVersionResource{Group: "test", Version: "v1", Resource: "foos"},
			Namespace: "user-ns",
			Name:      "test-foo",
		},
	}
	resp := handler.Handle(context.Background(), req)
	if !resp.Allowed {
		t.Fatalf("expected allowed when concurrent create happens (AlreadyExists), got denied: %s", resp.Result.Message)
	}
}

func TestWebhook_CreateError_Allowed_FailOpen(t *testing.T) {
	scheme := testScheme()

	cr := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "role"},
		Rules:      []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}}},
	}

	// Simulate a generic create error (not AlreadyExists)
	baseClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cr).Build()
	c := &clientWithCreateError{
		Client:    baseClient,
		createErr: fmt.Errorf("simulated API server error"),
	}

	handler := NewProvisioningWebhookHandler(
		c,
		[]ScopingTarget{{
			WatchGVK:               schema.GroupVersionKind{Group: "test", Version: "v1", Kind: "Foo"},
			TargetSA:               types.NamespacedName{Name: "sa", Namespace: "ns"},
			ClusterRoleName:        "role",
			ManagedRoleBindingName: "binding",
			WebhookProvisioning:    true,
		}},
		DefaultDenyList("scoper-system"),
	)

	req := admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			Operation: admissionv1.Create,
			Resource:  metav1.GroupVersionResource{Group: "test", Version: "v1", Resource: "foos"},
			Namespace: "user-ns",
			Name:      "test-foo",
		},
	}
	resp := handler.Handle(context.Background(), req)
	if !resp.Allowed {
		t.Fatalf("expected allowed on create error (fail-open), got denied: %s", resp.Result.Message)
	}
}

func TestWebhook_WebhookProvisioningFalse_NotRegistered(t *testing.T) {
	scheme := testScheme()

	handler := NewProvisioningWebhookHandler(
		fake.NewClientBuilder().WithScheme(scheme).Build(),
		[]ScopingTarget{{
			WatchGVK:               schema.GroupVersionKind{Group: "test", Version: "v1", Kind: "Foo"},
			TargetSA:               types.NamespacedName{Name: "sa", Namespace: "ns"},
			ClusterRoleName:        "role",
			ManagedRoleBindingName: "binding",
			WebhookProvisioning:    false, // disabled
		}},
		DefaultDenyList("scoper-system"),
	)

	req := admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			Operation: admissionv1.Create,
			Resource:  metav1.GroupVersionResource{Group: "test", Version: "v1", Resource: "foos"},
			Namespace: "user-ns",
		},
	}
	resp := handler.Handle(context.Background(), req)
	if !resp.Allowed {
		t.Fatalf("expected allowed for non-registered target, got denied: %s", resp.Result.Message)
	}
	if !strings.Contains(resp.Result.Message, "no matching scoping target") {
		t.Errorf("expected 'no matching scoping target' message, got: %s", resp.Result.Message)
	}
}

func TestPluralize(t *testing.T) {
	tests := []struct {
		kind string
		want string
	}{
		{"Foo", "foos"},
		{"Bar", "bars"},
		{"Deployment", "deployments"},
		{"Service", "services"},
		{"Class", "classes"},
		{"Status", "statuses"},
		{"Ingress", "ingresses"},
	}

	for _, tt := range tests {
		t.Run(tt.kind, func(t *testing.T) {
			got := pluralize(tt.kind)
			if got != tt.want {
				t.Errorf("pluralize(%q) = %q, want %q", tt.kind, got, tt.want)
			}
		})
	}
}

// clientWithCreateError wraps a fake client and injects an error on Create calls
type clientWithCreateError struct {
	client.Client
	createErr error
}

func (c *clientWithCreateError) Create(ctx context.Context, obj client.Object, opts ...client.CreateOption) error {
	if c.createErr != nil {
		return c.createErr
	}
	return c.Client.Create(ctx, obj, opts...)
}
