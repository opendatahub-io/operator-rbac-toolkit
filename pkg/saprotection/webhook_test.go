package saprotection

import (
	"context"
	"encoding/json"
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

func newScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	_ = corev1.AddToScheme(s)
	return s
}

func podJSON(t *testing.T, saName string) []byte {
	t.Helper()
	pod := &corev1.Pod{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "Pod",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pod",
			Namespace: "test-ns",
		},
		Spec: corev1.PodSpec{
			ServiceAccountName: saName,
			Containers: []corev1.Container{
				{Name: "app", Image: "busybox"},
			},
		},
	}
	raw, err := json.Marshal(pod)
	if err != nil {
		t.Fatalf("failed to marshal pod: %v", err)
	}
	return raw
}

func TestNonProtectedSA(t *testing.T) {
	wh := NewWebhook(WebhookConfig{
		ProtectedServiceAccounts: []string{"operator-sa"},
		AllowedIdentities:        []string{"system:serviceaccount:ns:controller"},
	}, newScheme())

	raw := podJSON(t, "some-other-sa")
	req := admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			UID:       "1",
			Operation: admissionv1.Create,
			Object:    runtime.RawExtension{Raw: raw},
			UserInfo:  authenticationv1.UserInfo{Username: "random-user"},
		},
	}

	resp := wh.Handle(context.Background(), req)
	if !resp.Allowed {
		t.Fatalf("expected allow for non-protected SA, got deny: %s", resp.Result.Message)
	}
}

func TestProtectedSAAllowedIdentity(t *testing.T) {
	wh := NewWebhook(WebhookConfig{
		ProtectedServiceAccounts: []string{"operator-sa"},
		AllowedIdentities:        []string{"system:serviceaccount:ns:controller"},
	}, newScheme())

	raw := podJSON(t, "operator-sa")
	req := admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			UID:       "2",
			Operation: admissionv1.Create,
			Object:    runtime.RawExtension{Raw: raw},
			UserInfo:  authenticationv1.UserInfo{Username: "system:serviceaccount:ns:controller"},
		},
	}

	resp := wh.Handle(context.Background(), req)
	if !resp.Allowed {
		t.Fatalf("expected allow for allowed identity, got deny: %s", resp.Result.Message)
	}
}

func TestProtectedSAUnauthorizedIdentity(t *testing.T) {
	wh := NewWebhook(WebhookConfig{
		ProtectedServiceAccounts: []string{"operator-sa"},
		AllowedIdentities:        []string{"system:serviceaccount:ns:controller"},
	}, newScheme())

	raw := podJSON(t, "operator-sa")
	req := admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			UID:       "3",
			Operation: admissionv1.Create,
			Object:    runtime.RawExtension{Raw: raw},
			UserInfo:  authenticationv1.UserInfo{Username: "attacker"},
		},
	}

	resp := wh.Handle(context.Background(), req)
	if resp.Allowed {
		t.Fatal("expected deny for unauthorized identity, got allow")
	}
	expected := "ServiceAccount operator-sa is protected"
	if resp.Result.Message != expected {
		t.Fatalf("expected message %q, got %q", expected, resp.Result.Message)
	}
}

func TestUpdateNotChangingSA(t *testing.T) {
	wh := NewWebhook(WebhookConfig{
		ProtectedServiceAccounts: []string{"operator-sa"},
		AllowedIdentities:        []string{"system:serviceaccount:ns:controller"},
	}, newScheme())

	raw := podJSON(t, "operator-sa")
	req := admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			UID:       "4",
			Operation: admissionv1.Update,
			Object:    runtime.RawExtension{Raw: raw},
			OldObject: runtime.RawExtension{Raw: raw},
			UserInfo:  authenticationv1.UserInfo{Username: "kubelet"},
		},
	}

	resp := wh.Handle(context.Background(), req)
	if !resp.Allowed {
		t.Fatalf("expected allow for update not changing SA, got deny: %s", resp.Result.Message)
	}
}

func TestUpdateChangingToProtectedSAUnauthorized(t *testing.T) {
	wh := NewWebhook(WebhookConfig{
		ProtectedServiceAccounts: []string{"operator-sa"},
		AllowedIdentities:        []string{"system:serviceaccount:ns:controller"},
	}, newScheme())

	oldRaw := podJSON(t, "default")
	newRaw := podJSON(t, "operator-sa")
	req := admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			UID:       "5",
			Operation: admissionv1.Update,
			Object:    runtime.RawExtension{Raw: newRaw},
			OldObject: runtime.RawExtension{Raw: oldRaw},
			UserInfo:  authenticationv1.UserInfo{Username: "attacker"},
		},
	}

	resp := wh.Handle(context.Background(), req)
	if resp.Allowed {
		t.Fatal("expected deny for update changing to protected SA from unauthorized identity, got allow")
	}
	expected := "ServiceAccount operator-sa is protected"
	if resp.Result.Message != expected {
		t.Fatalf("expected message %q, got %q", expected, resp.Result.Message)
	}
}
