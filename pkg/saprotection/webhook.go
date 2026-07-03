package saprotection

import (
	"context"
	"fmt"
	"net/http"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

type SAProtectionWebhook struct {
	config  WebhookConfig
	decoder admission.Decoder

	protectedSet map[string]struct{}
	allowedSet   map[string]struct{}
}

func NewWebhook(config WebhookConfig, scheme *runtime.Scheme) *SAProtectionWebhook {
	protectedSet := make(map[string]struct{}, len(config.ProtectedServiceAccounts))
	for _, sa := range config.ProtectedServiceAccounts {
		protectedSet[sa] = struct{}{}
	}

	allowedSet := make(map[string]struct{}, len(config.AllowedIdentities))
	for _, id := range config.AllowedIdentities {
		allowedSet[id] = struct{}{}
	}

	return &SAProtectionWebhook{
		config:       config,
		decoder:      admission.NewDecoder(scheme),
		protectedSet: protectedSet,
		allowedSet:   allowedSet,
	}
}

func (w *SAProtectionWebhook) Handle(ctx context.Context, req admission.Request) admission.Response {
	// Only CREATE and UPDATE can assign a ServiceAccount to a pod.
	// Allow all other operations (DELETE, CONNECT) to pass through without
	// decoding the object, which would fail for DELETE (empty object body)
	// and cause a 500 error.
	if req.Operation != admissionv1.Create && req.Operation != admissionv1.Update {
		return admission.Allowed("")
	}

	pod := &corev1.Pod{}
	if err := w.decoder.Decode(req, pod); err != nil {
		return admission.Errored(http.StatusInternalServerError, fmt.Errorf("failed to decode pod: %w", err))
	}

	if req.Operation == admissionv1.Update {
		oldPod := &corev1.Pod{}
		if err := w.decoder.DecodeRaw(req.OldObject, oldPod); err != nil {
			return admission.Errored(http.StatusInternalServerError, fmt.Errorf("failed to decode old pod: %w", err))
		}
		oldSA := serviceAccountName(oldPod)
		newSA := serviceAccountName(pod)

		// SA unchanged: nothing to protect.
		if newSA == oldSA {
			return admission.Allowed("")
		}

		// If EITHER the old or new SA is protected, require an allowed identity.
		// Checking both directions prevents an unauthorized user from both
		// assigning a protected SA (privilege escalation) and removing a
		// protected SA (stripping security context).
		if w.isProtected(oldSA) || w.isProtected(newSA) {
			if !w.isAllowed(req.UserInfo.Username) {
				protectedName := newSA
				if w.isProtected(oldSA) {
					protectedName = oldSA
				}
				return admission.Denied(fmt.Sprintf("ServiceAccount %s is protected", protectedName))
			}
		}

		return admission.Allowed("")
	}

	// CREATE path: only check the new SA.
	saName := serviceAccountName(pod)
	if !w.isProtected(saName) {
		return admission.Allowed("")
	}

	if !w.isAllowed(req.UserInfo.Username) {
		return admission.Denied(fmt.Sprintf("ServiceAccount %s is protected", saName))
	}

	return admission.Allowed("")
}

func (w *SAProtectionWebhook) isProtected(saName string) bool {
	_, ok := w.protectedSet[saName]
	return ok
}

func (w *SAProtectionWebhook) isAllowed(username string) bool {
	_, ok := w.allowedSet[username]
	return ok
}

func serviceAccountName(pod *corev1.Pod) string {
	if pod.Spec.ServiceAccountName != "" {
		return pod.Spec.ServiceAccountName
	}
	return "default"
}

// Verify SAProtectionWebhook implements admission.Handler.
var _ admission.Handler = (*SAProtectionWebhook)(nil)
