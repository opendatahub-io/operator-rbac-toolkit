package graceful

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// testCR is a minimal CR that implements client.Object and StatusProvider.
type testCR struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Status            testCRStatus `json:"status,omitempty"`
}

type testCRStatus struct {
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

func (t *testCR) GetConditions() []metav1.Condition      { return t.Status.Conditions }
func (t *testCR) SetConditions(c []metav1.Condition)      { t.Status.Conditions = c }
func (t *testCR) DeepCopyObject() runtime.Object          { return t.deepCopy() }
func (t *testCR) GetObjectKind() schema.ObjectKind        { return &t.TypeMeta }

// testCRList is required for fake client scheme registration.
type testCRList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []testCR `json:"items"`
}

func (l *testCRList) DeepCopyObject() runtime.Object {
	out := *l
	if l.Items != nil {
		out.Items = make([]testCR, len(l.Items))
		for i := range l.Items {
			out.Items[i] = *l.Items[i].deepCopy()
		}
	}
	return &out
}

func (t *testCR) deepCopy() *testCR {
	out := *t
	out.ObjectMeta = *t.ObjectMeta.DeepCopy()
	if t.Status.Conditions != nil {
		out.Status.Conditions = make([]metav1.Condition, len(t.Status.Conditions))
		copy(out.Status.Conditions, t.Status.Conditions)
	}
	return &out
}

func newTestCR() *testCR {
	return &testCR{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "test.example.com/v1",
			Kind:       "TestCR",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-instance",
			Namespace: "test-ns",
			UID:       types.UID("test-uid-123"),
		},
	}
}

func TestSetPermissionGranted_Denied(t *testing.T) {
	cr := newTestCR()
	SetPermissionGranted(cr, false, "missing: list secrets in ns \"kube-system\"")

	if len(cr.Status.Conditions) != 2 {
		t.Fatalf("expected 2 conditions, got %d", len(cr.Status.Conditions))
	}

	pg := findCondition(cr, ConditionTypePermissionGranted)
	if pg == nil {
		t.Fatal("PermissionGranted condition not found")
	}
	if pg.Status != metav1.ConditionFalse {
		t.Errorf("PermissionGranted status = %s, want False", pg.Status)
	}
	if pg.Reason != ReasonMissingPermissions {
		t.Errorf("PermissionGranted reason = %s, want %s", pg.Reason, ReasonMissingPermissions)
	}

	deg := findCondition(cr, ConditionTypeDegraded)
	if deg == nil {
		t.Fatal("Degraded condition not found")
	}
	if deg.Status != metav1.ConditionTrue {
		t.Errorf("Degraded status = %s, want True", deg.Status)
	}
	if deg.Reason != ReasonInsufficientRBAC {
		t.Errorf("Degraded reason = %s, want %s", deg.Reason, ReasonInsufficientRBAC)
	}
}

func TestSetPermissionGranted_Granted(t *testing.T) {
	cr := newTestCR()
	SetPermissionGranted(cr, true, "all good")

	pg := findCondition(cr, ConditionTypePermissionGranted)
	if pg == nil {
		t.Fatal("PermissionGranted condition not found")
	}
	if pg.Status != metav1.ConditionTrue {
		t.Errorf("PermissionGranted status = %s, want True", pg.Status)
	}
	if pg.Reason != ReasonAllPermissionsAvailable {
		t.Errorf("PermissionGranted reason = %s, want %s", pg.Reason, ReasonAllPermissionsAvailable)
	}

	deg := findCondition(cr, ConditionTypeDegraded)
	if deg == nil {
		t.Fatal("Degraded condition not found")
	}
	if deg.Status != metav1.ConditionFalse {
		t.Errorf("Degraded status = %s, want False", deg.Status)
	}
}

func TestSetCondition_NoopOnSameValues(t *testing.T) {
	cr := newTestCR()
	SetPermissionGranted(cr, true, "all good")
	firstTime := cr.Status.Conditions[0].LastTransitionTime

	time.Sleep(2 * time.Millisecond)

	SetPermissionGranted(cr, true, "all good")
	secondTime := cr.Status.Conditions[0].LastTransitionTime

	if !firstTime.Equal(&secondTime) {
		t.Error("LastTransitionTime changed when condition values did not change")
	}
}

func TestSetCondition_TransitionUpdatesTime(t *testing.T) {
	cr := newTestCR()
	SetPermissionGranted(cr, true, "all good")
	firstTime := cr.Status.Conditions[0].LastTransitionTime

	time.Sleep(2 * time.Millisecond)

	SetPermissionGranted(cr, false, "denied")
	pg := findCondition(cr, ConditionTypePermissionGranted)
	if pg.LastTransitionTime.Equal(&firstTime) {
		t.Error("LastTransitionTime should update when condition status changes")
	}
}

func TestDo_Success(t *testing.T) {
	cr := newTestCR()
	recorder := record.NewFakeRecorder(10)
	handler := NewHandler(recorder)

	result, err := handler.Do(context.Background(), nil, cr, func() error {
		return nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.RequeueAfter != 0 {
		t.Errorf("RequeueAfter = %v, want 0", result.RequeueAfter)
	}
}

func TestDo_NonForbiddenError(t *testing.T) {
	cr := newTestCR()
	recorder := record.NewFakeRecorder(10)
	handler := NewHandler(recorder)

	expectedErr := fmt.Errorf("connection refused")
	result, err := handler.Do(context.Background(), nil, cr, func() error {
		return expectedErr
	})
	if err != expectedErr {
		t.Fatalf("err = %v, want %v", err, expectedErr)
	}
	if result.RequeueAfter != 0 {
		t.Errorf("RequeueAfter = %v, want 0", result.RequeueAfter)
	}
}

func TestDo_ForbiddenError_SetsConditionsAndEvents(t *testing.T) {
	cr := newTestCR()
	recorder := record.NewFakeRecorder(10)
	handler := NewHandler(recorder)

	forbiddenErr := errors.NewForbidden(
		schema.GroupResource{Group: "", Resource: "secrets"},
		"",
		fmt.Errorf("user cannot list secrets in namespace \"kube-system\""),
	)

	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	scheme.AddKnownTypeWithName(
		schema.GroupVersionKind{Group: "test.example.com", Version: "v1", Kind: "TestCR"},
		&testCR{},
	)
	scheme.AddKnownTypeWithName(
		schema.GroupVersionKind{Group: "test.example.com", Version: "v1", Kind: "TestCRList"},
		&testCRList{},
	)
	storedCR := cr.deepCopy()
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(storedCR).
		WithStatusSubresource(storedCR).
		Build()

	// Re-fetch the CR from the fake client so that resource version is populated,
	// matching what the status update path expects.
	fetchedCR := &testCR{}
	fetchedCR.SetGroupVersionKind(schema.GroupVersionKind{Group: "test.example.com", Version: "v1", Kind: "TestCR"})
	if err := fakeClient.Get(context.Background(), client.ObjectKeyFromObject(cr), fetchedCR); err != nil {
		t.Fatalf("failed to fetch CR from fake client: %v", err)
	}

	result, err := handler.Do(context.Background(), fakeClient, fetchedCR, func() error {
		return forbiddenErr
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.RequeueAfter != DefaultRequeueAfter {
		t.Errorf("RequeueAfter = %v, want %v", result.RequeueAfter, DefaultRequeueAfter)
	}

	pg := findCondition(fetchedCR, ConditionTypePermissionGranted)
	if pg == nil {
		t.Fatal("PermissionGranted condition not set after Forbidden error")
	}
	if pg.Status != metav1.ConditionFalse {
		t.Errorf("PermissionGranted = %s, want False", pg.Status)
	}

	deg := findCondition(fetchedCR, ConditionTypeDegraded)
	if deg == nil {
		t.Fatal("Degraded condition not set after Forbidden error")
	}
	if deg.Status != metav1.ConditionTrue {
		t.Errorf("Degraded = %s, want True", deg.Status)
	}

	select {
	case event := <-recorder.Events:
		if event == "" {
			t.Error("received empty event")
		}
	default:
		t.Error("no event emitted for Forbidden error")
	}
}

func TestDo_ForbiddenError_ExponentialBackoff(t *testing.T) {
	cr := newTestCR()
	recorder := record.NewFakeRecorder(100)

	handler := NewHandler(recorder)

	forbiddenErr := errors.NewForbidden(
		schema.GroupResource{Group: "", Resource: "secrets"},
		"",
		fmt.Errorf("denied"),
	)

	expectedDurations := []time.Duration{
		30 * time.Second,
		60 * time.Second,
		120 * time.Second,
		240 * time.Second,
		5 * time.Minute, // capped
		5 * time.Minute, // stays capped
	}

	for i, expected := range expectedDurations {
		result, err := handler.Do(context.Background(), nil, cr, func() error {
			return forbiddenErr
		})
		if err != nil {
			t.Fatalf("iteration %d: unexpected error: %v", i, err)
		}
		if result.RequeueAfter != expected {
			t.Errorf("iteration %d: RequeueAfter = %v, want %v", i, result.RequeueAfter, expected)
		}
	}
}

func TestDo_ForbiddenError_CustomOptions(t *testing.T) {
	cr := newTestCR()
	recorder := record.NewFakeRecorder(10)
	handler := NewHandler(recorder, WithRequeueAfter(10*time.Second), WithMaxRequeue(1*time.Minute))

	result, err := handler.Do(context.Background(), nil, cr, func() error {
		return errors.NewForbidden(
			schema.GroupResource{Group: "", Resource: "configmaps"},
			"",
			fmt.Errorf("denied"),
		)
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.RequeueAfter != 10*time.Second {
		t.Errorf("RequeueAfter = %v, want 10s", result.RequeueAfter)
	}
}

func TestDo_PermissionRestored_EmitsEvent(t *testing.T) {
	cr := newTestCR()
	SetPermissionGranted(cr, false, "was denied before")

	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	scheme.AddKnownTypeWithName(
		schema.GroupVersionKind{Group: "test.example.com", Version: "v1", Kind: "TestCR"},
		&testCR{},
	)
	scheme.AddKnownTypeWithName(
		schema.GroupVersionKind{Group: "test.example.com", Version: "v1", Kind: "TestCRList"},
		&testCRList{},
	)

	storedCR := cr.deepCopy()
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(storedCR).
		WithStatusSubresource(storedCR).
		Build()

	// Re-fetch so resource version is populated
	fetchedCR := &testCR{}
	fetchedCR.SetGroupVersionKind(schema.GroupVersionKind{Group: "test.example.com", Version: "v1", Kind: "TestCR"})
	if err := fakeClient.Get(context.Background(), client.ObjectKeyFromObject(cr), fetchedCR); err != nil {
		t.Fatalf("failed to fetch CR from fake client: %v", err)
	}
	// Re-apply the denied condition on the fetched CR so Do() sees the transition
	SetPermissionGranted(fetchedCR, false, "was denied before")

	recorder := record.NewFakeRecorder(10)
	handler := NewHandler(recorder)
	result, err := handler.Do(context.Background(), fakeClient, fetchedCR, func() error {
		return nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.RequeueAfter != 0 {
		t.Errorf("RequeueAfter = %v, want 0", result.RequeueAfter)
	}

	pg := findCondition(fetchedCR, ConditionTypePermissionGranted)
	if pg == nil {
		t.Fatal("PermissionGranted condition should be set")
	}
	if pg.Status != metav1.ConditionTrue {
		t.Errorf("PermissionGranted = %s, want True (restored)", pg.Status)
	}

	// Drain and verify the PermissionRestored event was emitted
	select {
	case event := <-recorder.Events:
		if event == "" {
			t.Error("received empty event")
		}
		if !strings.Contains(event, EventReasonPermissionRestored) {
			t.Errorf("expected event with reason %s, got %s", EventReasonPermissionRestored, event)
		}
	default:
		t.Error("no PermissionRestored event emitted")
	}
}

func TestBackoffTracker(t *testing.T) {
	bt := newBackoffTracker()

	if c := bt.increment("key1"); c != 1 {
		t.Errorf("first increment = %d, want 1", c)
	}
	if c := bt.increment("key1"); c != 2 {
		t.Errorf("second increment = %d, want 2", c)
	}
	if c := bt.increment("key2"); c != 1 {
		t.Errorf("different key first = %d, want 1", c)
	}

	bt.reset("key1")
	if c := bt.increment("key1"); c != 1 {
		t.Errorf("after reset = %d, want 1", c)
	}
}

func TestCalculateBackoff(t *testing.T) {
	h := NewHandler(record.NewFakeRecorder(1))

	tests := []struct {
		count    int
		expected time.Duration
	}{
		{1, 30 * time.Second},
		{2, 60 * time.Second},
		{3, 120 * time.Second},
		{4, 240 * time.Second},
		{5, 5 * time.Minute},
		{10, 5 * time.Minute},
	}

	for _, tt := range tests {
		got := h.calculateBackoff(tt.count)
		if got != tt.expected {
			t.Errorf("calculateBackoff(%d) = %v, want %v", tt.count, got, tt.expected)
		}
	}
}

func TestParseForbiddenMessage(t *testing.T) {
	err := errors.NewForbidden(
		schema.GroupResource{Group: "", Resource: "secrets"},
		"my-secret",
		fmt.Errorf("user cannot get secrets"),
	)
	msg := parseForbiddenMessage(err)
	if msg == "" {
		t.Error("parseForbiddenMessage returned empty string")
	}
}

func TestPermissionDeniedMessage(t *testing.T) {
	msg := permissionDeniedMessage("list", "secrets", "kube-system")
	expected := `Missing permission: list secrets in namespace "kube-system"`
	if msg != expected {
		t.Errorf("got %q, want %q", msg, expected)
	}

	msg = permissionDeniedMessage("list", "nodes", "")
	expected = "Missing permission: list nodes (cluster-scoped)"
	if msg != expected {
		t.Errorf("got %q, want %q", msg, expected)
	}
}

func TestJoinMax(t *testing.T) {
	items := []string{"a", "b", "c", "d", "e"}
	result := joinMax(items, 3)
	if result != "a; b; c (and 2 more)" {
		t.Errorf("got %q", result)
	}

	result = joinMax(items[:2], 3)
	if result != "a; b" {
		t.Errorf("got %q", result)
	}
}

func TestDefaultOptions(t *testing.T) {
	opts := defaultOptions()
	if opts.RequeueAfter != DefaultRequeueAfter {
		t.Errorf("RequeueAfter = %v, want %v", opts.RequeueAfter, DefaultRequeueAfter)
	}
	if opts.MaxRequeue != DefaultMaxRequeue {
		t.Errorf("MaxRequeue = %v, want %v", opts.MaxRequeue, DefaultMaxRequeue)
	}
	if opts.BackoffFactor != 2.0 {
		t.Errorf("BackoffFactor = %v, want 2.0", opts.BackoffFactor)
	}
}

func TestOptionFunctions(t *testing.T) {
	opts := defaultOptions()
	WithRequeueAfter(10 * time.Second)(&opts)
	WithMaxRequeue(1 * time.Minute)(&opts)
	WithBackoffFactor(3.0)(&opts)

	if opts.RequeueAfter != 10*time.Second {
		t.Errorf("RequeueAfter = %v, want 10s", opts.RequeueAfter)
	}
	if opts.MaxRequeue != 1*time.Minute {
		t.Errorf("MaxRequeue = %v, want 1m", opts.MaxRequeue)
	}
	if opts.BackoffFactor != 3.0 {
		t.Errorf("BackoffFactor = %v, want 3.0", opts.BackoffFactor)
	}
}

// Verify StatusProvider interface is correctly implemented by testCR
var _ StatusProvider = &testCR{}
var _ client.Object = &testCR{}

func TestDo_ForbiddenError_NoManagedRoleBindingName(t *testing.T) {
	cr := newTestCR()
	recorder := record.NewFakeRecorder(10)
	handler := NewHandler(recorder)

	forbiddenErr := errors.NewForbidden(
		schema.GroupResource{Group: "", Resource: "secrets"},
		"",
		fmt.Errorf("user cannot list secrets in namespace \"test-ns\""),
	)

	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = rbacv1.AddToScheme(scheme)
	scheme.AddKnownTypeWithName(
		schema.GroupVersionKind{Group: "test.example.com", Version: "v1", Kind: "TestCR"},
		&testCR{},
	)
	scheme.AddKnownTypeWithName(
		schema.GroupVersionKind{Group: "test.example.com", Version: "v1", Kind: "TestCRList"},
		&testCRList{},
	)
	storedCR := cr.deepCopy()
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(storedCR).
		WithStatusSubresource(storedCR).
		Build()

	fetchedCR := &testCR{}
	fetchedCR.SetGroupVersionKind(schema.GroupVersionKind{Group: "test.example.com", Version: "v1", Kind: "TestCR"})
	if err := fakeClient.Get(context.Background(), client.ObjectKeyFromObject(cr), fetchedCR); err != nil {
		t.Fatalf("failed to fetch CR from fake client: %v", err)
	}

	result, err := handler.Do(context.Background(), fakeClient, fetchedCR, func() error {
		return forbiddenErr
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.RequeueAfter != DefaultRequeueAfter {
		t.Errorf("RequeueAfter = %v, want %v", result.RequeueAfter, DefaultRequeueAfter)
	}

	pg := findCondition(fetchedCR, ConditionTypePermissionGranted)
	if pg == nil {
		t.Fatal("PermissionGranted condition not set after Forbidden error")
	}
	if pg.Status != metav1.ConditionFalse {
		t.Errorf("PermissionGranted = %s, want False", pg.Status)
	}
	if pg.Reason != ReasonMissingPermissions {
		t.Errorf("PermissionGranted reason = %s, want %s", pg.Reason, ReasonMissingPermissions)
	}

	deg := findCondition(fetchedCR, ConditionTypeDegraded)
	if deg == nil {
		t.Fatal("Degraded condition not set after Forbidden error")
	}
	if deg.Status != metav1.ConditionTrue {
		t.Errorf("Degraded status = %s, want True", deg.Status)
	}
	if deg.Reason != ReasonInsufficientRBAC {
		t.Errorf("Degraded reason = %s, want %s", deg.Reason, ReasonInsufficientRBAC)
	}
}

func TestDo_ForbiddenError_ManagedRoleBindingName_RoleBindingMissing(t *testing.T) {
	cr := newTestCR()
	recorder := record.NewFakeRecorder(10)
	handler := NewHandler(recorder, WithManagedRoleBindingName("test-rolebinding"))

	forbiddenErr := errors.NewForbidden(
		schema.GroupResource{Group: "", Resource: "secrets"},
		"",
		fmt.Errorf("user cannot list secrets in namespace \"test-ns\""),
	)

	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = rbacv1.AddToScheme(scheme)
	scheme.AddKnownTypeWithName(
		schema.GroupVersionKind{Group: "test.example.com", Version: "v1", Kind: "TestCR"},
		&testCR{},
	)
	scheme.AddKnownTypeWithName(
		schema.GroupVersionKind{Group: "test.example.com", Version: "v1", Kind: "TestCRList"},
		&testCRList{},
	)
	storedCR := cr.deepCopy()
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(storedCR).
		WithStatusSubresource(storedCR).
		Build()

	fetchedCR := &testCR{}
	fetchedCR.SetGroupVersionKind(schema.GroupVersionKind{Group: "test.example.com", Version: "v1", Kind: "TestCR"})
	if err := fakeClient.Get(context.Background(), client.ObjectKeyFromObject(cr), fetchedCR); err != nil {
		t.Fatalf("failed to fetch CR from fake client: %v", err)
	}

	result, err := handler.Do(context.Background(), fakeClient, fetchedCR, func() error {
		return forbiddenErr
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.RequeueAfter != DefaultRequeueAfter {
		t.Errorf("RequeueAfter = %v, want %v", result.RequeueAfter, DefaultRequeueAfter)
	}

	pg := findCondition(fetchedCR, ConditionTypePermissionGranted)
	if pg == nil {
		t.Fatal("PermissionGranted condition not set after Forbidden error")
	}
	if pg.Status != metav1.ConditionFalse {
		t.Errorf("PermissionGranted = %s, want False", pg.Status)
	}
	if pg.Reason != ReasonProvisioningPending {
		t.Errorf("PermissionGranted reason = %s, want %s", pg.Reason, ReasonProvisioningPending)
	}

	deg := findCondition(fetchedCR, ConditionTypeDegraded)
	if deg == nil {
		t.Fatal("Degraded condition not set after Forbidden error")
	}
	if deg.Status != metav1.ConditionFalse {
		t.Errorf("Degraded status = %s, want False (provisioning pending should not be degraded)", deg.Status)
	}
	if deg.Reason != ReasonProvisioningInProgress {
		t.Errorf("Degraded reason = %s, want %s", deg.Reason, ReasonProvisioningInProgress)
	}
}

func TestDo_ForbiddenError_ManagedRoleBindingName_RoleBindingExists(t *testing.T) {
	cr := newTestCR()
	recorder := record.NewFakeRecorder(10)
	handler := NewHandler(recorder, WithManagedRoleBindingName("test-rolebinding"))

	forbiddenErr := errors.NewForbidden(
		schema.GroupResource{Group: "", Resource: "secrets"},
		"",
		fmt.Errorf("user cannot list secrets in namespace \"test-ns\""),
	)

	// Create the RoleBinding in the fake client
	rb := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-rolebinding",
			Namespace: "test-ns",
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     "test-role",
		},
	}

	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = rbacv1.AddToScheme(scheme)
	scheme.AddKnownTypeWithName(
		schema.GroupVersionKind{Group: "test.example.com", Version: "v1", Kind: "TestCR"},
		&testCR{},
	)
	scheme.AddKnownTypeWithName(
		schema.GroupVersionKind{Group: "test.example.com", Version: "v1", Kind: "TestCRList"},
		&testCRList{},
	)
	storedCR := cr.deepCopy()
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(storedCR, rb).
		WithStatusSubresource(storedCR).
		Build()

	fetchedCR := &testCR{}
	fetchedCR.SetGroupVersionKind(schema.GroupVersionKind{Group: "test.example.com", Version: "v1", Kind: "TestCR"})
	if err := fakeClient.Get(context.Background(), client.ObjectKeyFromObject(cr), fetchedCR); err != nil {
		t.Fatalf("failed to fetch CR from fake client: %v", err)
	}

	result, err := handler.Do(context.Background(), fakeClient, fetchedCR, func() error {
		return forbiddenErr
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.RequeueAfter != DefaultRequeueAfter {
		t.Errorf("RequeueAfter = %v, want %v", result.RequeueAfter, DefaultRequeueAfter)
	}

	pg := findCondition(fetchedCR, ConditionTypePermissionGranted)
	if pg == nil {
		t.Fatal("PermissionGranted condition not set after Forbidden error")
	}
	if pg.Status != metav1.ConditionFalse {
		t.Errorf("PermissionGranted = %s, want False", pg.Status)
	}
	if pg.Reason != ReasonPermissionDenied {
		t.Errorf("PermissionGranted reason = %s, want %s", pg.Reason, ReasonPermissionDenied)
	}

	deg := findCondition(fetchedCR, ConditionTypeDegraded)
	if deg == nil {
		t.Fatal("Degraded condition not set after Forbidden error")
	}
	if deg.Status != metav1.ConditionTrue {
		t.Errorf("Degraded status = %s, want True (permission denied should be degraded)", deg.Status)
	}
	if deg.Reason != ReasonInsufficientRBAC {
		t.Errorf("Degraded reason = %s, want %s", deg.Reason, ReasonInsufficientRBAC)
	}
}

// ---------------------------------------------------------------------------
// extractVerbFromMessage tests (MINOR 11)
// ---------------------------------------------------------------------------

func TestExtractVerbFromMessage(t *testing.T) {
	tests := []struct {
		name string
		msg  string
		want string
	}{
		{"standard get", "User cannot get resource \"secrets\" in namespace \"kube-system\"", "get"},
		{"standard list", "User cannot list resource \"pods\" in namespace \"default\"", "list"},
		{"standard create", "User cannot create resource \"configmaps\" in namespace \"test\"", "create"},
		{"standard update", "User cannot update resource \"deployments\" in namespace \"prod\"", "update"},
		{"standard delete", "User cannot delete resource \"pods\" in namespace \"test\"", "delete"},
		{"standard patch", "User cannot patch resource \"services\" in namespace \"default\"", "patch"},
		{"standard watch", "User cannot watch resource \"events\" in namespace \"kube-system\"", "watch"},
		{"deletecollection", "User cannot deletecollection resource \"pods\" in namespace \"test\"", "deletecollection"},
		{"unusual casing", "USER CANNOT GET resource \"secrets\"", "get"},
		{"no cannot pattern", "access denied for resource secrets", "unknown"},
		{"empty message", "", "unknown"},
		{"partial match no space", "cannot getx resource", "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractVerbFromMessage(tt.msg)
			if got != tt.want {
				t.Errorf("extractVerbFromMessage(%q) = %q, want %q", tt.msg, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// WithDirectReader tests (MINOR 14)
// ---------------------------------------------------------------------------

func TestDo_ForbiddenError_DirectReader_RoleBindingMissing(t *testing.T) {
	cr := newTestCR()
	recorder := record.NewFakeRecorder(10)

	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = rbacv1.AddToScheme(scheme)
	scheme.AddKnownTypeWithName(
		schema.GroupVersionKind{Group: "test.example.com", Version: "v1", Kind: "TestCR"},
		&testCR{},
	)
	scheme.AddKnownTypeWithName(
		schema.GroupVersionKind{Group: "test.example.com", Version: "v1", Kind: "TestCRList"},
		&testCRList{},
	)

	storedCR := cr.deepCopy()
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(storedCR).
		WithStatusSubresource(storedCR).
		Build()

	// DirectReader has no RoleBinding, so it should return NotFound -> ProvisioningPending
	directReader := fake.NewClientBuilder().WithScheme(scheme).Build()

	handler := NewHandler(recorder,
		WithManagedRoleBindingName("test-rolebinding"),
		WithDirectReader(directReader),
	)

	forbiddenErr := errors.NewForbidden(
		schema.GroupResource{Group: "", Resource: "secrets"},
		"",
		fmt.Errorf("user cannot list secrets in namespace \"test-ns\""),
	)

	fetchedCR := &testCR{}
	fetchedCR.SetGroupVersionKind(schema.GroupVersionKind{Group: "test.example.com", Version: "v1", Kind: "TestCR"})
	if err := fakeClient.Get(context.Background(), client.ObjectKeyFromObject(cr), fetchedCR); err != nil {
		t.Fatalf("failed to fetch CR: %v", err)
	}

	result, err := handler.Do(context.Background(), fakeClient, fetchedCR, func() error {
		return forbiddenErr
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.RequeueAfter != DefaultRequeueAfter {
		t.Errorf("RequeueAfter = %v, want %v", result.RequeueAfter, DefaultRequeueAfter)
	}

	pg := findCondition(fetchedCR, ConditionTypePermissionGranted)
	if pg == nil {
		t.Fatal("PermissionGranted condition not set")
	}
	if pg.Reason != ReasonProvisioningPending {
		t.Errorf("PermissionGranted reason = %s, want %s", pg.Reason, ReasonProvisioningPending)
	}
}

func TestDo_ForbiddenError_DirectReader_ReturnsError(t *testing.T) {
	cr := newTestCR()
	recorder := record.NewFakeRecorder(10)

	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = rbacv1.AddToScheme(scheme)
	scheme.AddKnownTypeWithName(
		schema.GroupVersionKind{Group: "test.example.com", Version: "v1", Kind: "TestCR"},
		&testCR{},
	)
	scheme.AddKnownTypeWithName(
		schema.GroupVersionKind{Group: "test.example.com", Version: "v1", Kind: "TestCRList"},
		&testCRList{},
	)

	storedCR := cr.deepCopy()
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(storedCR).
		WithStatusSubresource(storedCR).
		Build()

	// DirectReader that returns an error (simulating a Forbidden or other error)
	directReader := &errorReader{err: fmt.Errorf("simulated Get error")}

	handler := NewHandler(recorder,
		WithManagedRoleBindingName("test-rolebinding"),
		WithDirectReader(directReader),
	)

	forbiddenErr := errors.NewForbidden(
		schema.GroupResource{Group: "", Resource: "secrets"},
		"",
		fmt.Errorf("user cannot list secrets in namespace \"test-ns\""),
	)

	fetchedCR := &testCR{}
	fetchedCR.SetGroupVersionKind(schema.GroupVersionKind{Group: "test.example.com", Version: "v1", Kind: "TestCR"})
	if err := fakeClient.Get(context.Background(), client.ObjectKeyFromObject(cr), fetchedCR); err != nil {
		t.Fatalf("failed to fetch CR: %v", err)
	}

	result, err := handler.Do(context.Background(), fakeClient, fetchedCR, func() error {
		return forbiddenErr
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.RequeueAfter != DefaultRequeueAfter {
		t.Errorf("RequeueAfter = %v, want %v", result.RequeueAfter, DefaultRequeueAfter)
	}

	pg := findCondition(fetchedCR, ConditionTypePermissionGranted)
	if pg == nil {
		t.Fatal("PermissionGranted condition not set")
	}
	if pg.Reason != ReasonPermissionDenied {
		t.Errorf("PermissionGranted reason = %s, want %s (Get error should assume PermissionDenied)", pg.Reason, ReasonPermissionDenied)
	}
}

// errorReader is a client.Reader that always returns an error on Get and List.
type errorReader struct {
	err error
}

func (r *errorReader) Get(_ context.Context, _ client.ObjectKey, _ client.Object, _ ...client.GetOption) error {
	return r.err
}

func (r *errorReader) List(_ context.Context, _ client.ObjectList, _ ...client.ListOption) error {
	return r.err
}
