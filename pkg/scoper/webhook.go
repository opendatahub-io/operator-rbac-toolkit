package scoper

import (
	"context"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
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
	client    client.Client
	targets   map[schema.GroupVersionResource]ScopingTarget
	denyList  DenyListConfig
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
	start := time.Now()
	defer func() {
		webhookDuration.Observe(time.Since(start).Seconds())
	}()

	logger := log.FromContext(ctx).WithValues("namespace", req.Namespace, "resource", req.Resource.String())

	// Convert metav1.GroupVersionResource to schema.GroupVersionResource
	gvr := schema.GroupVersionResource{
		Group:    req.Resource.Group,
		Version:  req.Resource.Version,
		Resource: req.Resource.Resource,
	}

	target, found := h.targets[gvr]
	if !found {
		webhookRequestsTotal.WithLabelValues("unknown", "allowed", "no-target").Inc()
		return admission.Allowed("no matching scoping target")
	}

	gvk := fmt.Sprintf("%s/%s/%s", target.WatchGVK.Group, target.WatchGVK.Version, target.WatchGVK.Kind)

	// Step 1: deny-list check
	if IsDenied(req.Namespace, h.denyList) {
		webhookRequestsTotal.WithLabelValues(gvk, "allowed", "deny-list").Inc()
		return admission.Allowed("namespace is in deny-list, skipping RoleBinding")
	}

	// Step 1.5: NamespaceSelector check
	if sel, ok := h.selectors[gvr]; ok {
		ns := &corev1.Namespace{}
		if err := h.client.Get(ctx, types.NamespacedName{Name: req.Namespace}, ns); err != nil {
			logger.Error(err, "failed to get namespace for selector check")
			webhookRequestsTotal.WithLabelValues(gvk, "allowed", "selector-check-error").Inc()
			return admission.Allowed("failed to check namespace selector, allowing CR")
		}
		if !sel.Matches(labels.Set(ns.Labels)) {
			webhookRequestsTotal.WithLabelValues(gvk, "allowed", "selector-mismatch").Inc()
			return admission.Allowed("namespace does not match selector, skipping RoleBinding")
		}
	}

	// Step 2: check if RoleBinding already exists (direct API, not cached)
	rbName := types.NamespacedName{Name: target.ManagedRoleBindingName, Namespace: req.Namespace}
	existing := &rbacv1.RoleBinding{}
	if err := h.client.Get(ctx, rbName, existing); err == nil {
		webhookRequestsTotal.WithLabelValues(gvk, "allowed", "already-exists").Inc()
		webhookAlreadyExistsTotal.Inc()
		return admission.Allowed("RoleBinding already exists")
	}

	// Step 3: validate ClusterRole exists
	if err := ValidateClusterRole(ctx, h.client, target.ClusterRoleName); err != nil {
		logger.Error(err, "ClusterRole validation failed, allowing CR without RoleBinding")
		webhookRequestsTotal.WithLabelValues(gvk, "allowed", "clusterrole-missing").Inc()
		return admission.Allowed(fmt.Sprintf("ClusterRole %s not found, skipping RoleBinding", target.ClusterRoleName))
	}

	// Step 3.5: dry-run check (after validation so dry-run catches config errors via logs)
	if req.DryRun != nil && *req.DryRun {
		webhookRequestsTotal.WithLabelValues(gvk, "allowed", "dry-run").Inc()
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
			webhookRequestsTotal.WithLabelValues(gvk, "allowed", "concurrent-create").Inc()
			webhookAlreadyExistsTotal.Inc()
			return admission.Allowed("RoleBinding already exists (concurrent create)")
		}
		logger.Error(err, "failed to create RoleBinding, allowing CR anyway")
		webhookRequestsTotal.WithLabelValues(gvk, "allowed", "creation-failed").Inc()
		webhookErrorsTotal.WithLabelValues("create-failed").Inc()
		return admission.Allowed("RoleBinding creation failed, reactive scoper will handle")
	}

	logger.Info("webhook provisioned RoleBinding", "roleBinding", rbName)
	webhookRequestsTotal.WithLabelValues(gvk, "allowed", "provisioned").Inc()
	webhookRoleBindingCreatedTotal.Inc()
	return admission.Allowed("RoleBinding provisioned")
}

func pluralize(kind string) string {
	k := strings.ToLower(kind)
	if strings.HasSuffix(k, "s") {
		return k + "es"
	}
	return k + "s"
}
