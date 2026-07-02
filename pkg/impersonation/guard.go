package impersonation

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/labels"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

type Guard struct {
	client.Client
	Log    logr.Logger
	Config GuardConfig
}

func NewGuard(c client.Client, log logr.Logger, cfg GuardConfig) *Guard {
	return &Guard{
		Client: c,
		Log:    log.WithName("impersonation-guard"),
		Config: cfg,
	}
}

func (g *Guard) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := g.Log.WithValues("clusterrole", req.Name)

	var cr rbacv1.ClusterRole
	if err := g.Get(ctx, req.NamespacedName, &cr); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if cr.Labels[AggregateToEditLabel] != "true" {
		return ctrl.Result{}, nil
	}

	if !hasImpersonateVerb(cr.Rules) {
		log.V(1).Info("no impersonate verb found, nothing to do")
		return g.ensureAutoupdateAnnotation(ctx, &cr)
	}

	log.Info("found impersonate verb in component ClusterRole, removing it")
	cr.Rules = removeImpersonateVerb(cr.Rules)

	if err := g.Update(ctx, &cr); err != nil {
		return ctrl.Result{}, fmt.Errorf("removing impersonate verb from ClusterRole %s: %w", cr.Name, err)
	}

	return g.ensureAutoupdateAnnotation(ctx, &cr)
}

func (g *Guard) ensureAutoupdateAnnotation(ctx context.Context, cr *rbacv1.ClusterRole) (ctrl.Result, error) {
	if cr.Annotations[AutoupdateAnnotation] == "false" {
		return ctrl.Result{RequeueAfter: g.Config.RequeueAfter}, nil
	}

	if cr.Annotations == nil {
		cr.Annotations = make(map[string]string)
	}
	cr.Annotations[AutoupdateAnnotation] = "false"

	if err := g.Update(ctx, cr); err != nil {
		return ctrl.Result{}, fmt.Errorf("setting autoupdate annotation on ClusterRole %s: %w", cr.Name, err)
	}

	return ctrl.Result{RequeueAfter: g.Config.RequeueAfter}, nil
}

func (g *Guard) SetupWithManager(mgr ctrl.Manager) error {
	labelSelector, err := labels.Parse(AggregateToEditLabel + "=true")
	if err != nil {
		return fmt.Errorf("parsing label selector: %w", err)
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&rbacv1.ClusterRole{}).
		WithEventFilter(predicate.Funcs{
			CreateFunc: func(e event.CreateEvent) bool {
				return labelSelector.Matches(labels.Set(e.Object.GetLabels()))
			},
			UpdateFunc: func(e event.UpdateEvent) bool {
				return labelSelector.Matches(labels.Set(e.ObjectNew.GetLabels()))
			},
			DeleteFunc: func(_ event.DeleteEvent) bool {
				return false
			},
			GenericFunc: func(e event.GenericEvent) bool {
				return labelSelector.Matches(labels.Set(e.Object.GetLabels()))
			},
		}).
		WithOptions(controller.Options{MaxConcurrentReconciles: 1}).
		Complete(g)
}

func hasImpersonateVerb(rules []rbacv1.PolicyRule) bool {
	for _, rule := range rules {
		if !coversServiceAccounts(rule) {
			continue
		}
		for _, verb := range rule.Verbs {
			if verb == "impersonate" {
				return true
			}
		}
	}
	return false
}

func coversServiceAccounts(rule rbacv1.PolicyRule) bool {
	for _, res := range rule.Resources {
		if res == "serviceaccounts" {
			return true
		}
	}
	return false
}

func removeImpersonateVerb(rules []rbacv1.PolicyRule) []rbacv1.PolicyRule {
	var result []rbacv1.PolicyRule
	for _, rule := range rules {
		if !coversServiceAccounts(rule) {
			result = append(result, rule)
			continue
		}

		var filteredVerbs []string
		for _, verb := range rule.Verbs {
			if verb != "impersonate" {
				filteredVerbs = append(filteredVerbs, verb)
			}
		}

		if len(filteredVerbs) > 0 {
			rule.Verbs = filteredVerbs
			result = append(result, rule)
		}
		// If no verbs remain after removing impersonate, drop the rule entirely.
	}
	return result
}
