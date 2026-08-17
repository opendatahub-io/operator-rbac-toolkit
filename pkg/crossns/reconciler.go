// Package crossns provides a cross-namespace RBAC reconciler that creates
// Role+RoleBinding pairs in namespaces outside the operator's own namespace
// and garbage-collects stale ones when the desired set shrinks.
//
// Problem it solves: owner references cannot cascade across namespaces (a
// cluster-scoped CR's owner reference on a namespaced Role in a different
// namespace is silently ignored by the GC controller). When a user changes
// the target namespace in the CR spec, the old Role/RoleBinding would become
// permanently orphaned without an explicit cluster-wide sweep.
//
// Usage:
//
//	r := crossns.New(client, crossns.OwnerLabel{Key: "myop.io/component", Value: "dashboard"})
//	// On each reconcile:
//	err := r.Apply(ctx, subject, []crossns.RuleSet{{...}})
//	// On CR deletion / ManagementState=Removed:
//	err := r.Teardown(ctx)
package crossns

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"

	rbacv1 "k8s.io/api/rbac/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// Reconciler manages cross-namespace Role+RoleBinding pairs identified by
// ManagedLabelKey (and an optional owner label). It is safe to embed or
// compose in a controller reconciler.
type Reconciler struct {
	client client.Client
	owner  OwnerLabel
}

// New creates a Reconciler. owner narrows the label sweep to resources
// belonging to a specific operator component; pass a zero OwnerLabel if you
// want ManagedLabelKey alone to identify resources.
func New(c client.Client, owner OwnerLabel) *Reconciler {
	return &Reconciler{client: c, owner: owner}
}

// Apply creates or updates a Role and RoleBinding for each RuleSet in
// ruleSets, then garbage-collects any previously managed resources whose
// (namespace, roleName) pair is not present in ruleSets.
//
// Apply is the main per-reconcile entrypoint.
//
// Validation: RuleSet.RoleName and RuleSet.Namespace must be non-empty.
// SubjectRef.Name must be non-empty. Apply returns an error immediately if any
// of these are missing.
func (r *Reconciler) Apply(ctx context.Context, subject SubjectRef, ruleSets []RuleSet) error {
	if subject.Name == "" {
		return fmt.Errorf("crossns: SubjectRef.Name must not be empty")
	}
	for _, rs := range ruleSets {
		if rs.RoleName == "" {
			return fmt.Errorf("crossns: RuleSet.RoleName must not be empty (namespace: %s)", rs.Namespace)
		}
		if rs.Namespace == "" {
			return fmt.Errorf("crossns: RuleSet.Namespace must not be empty (role: %s)", rs.RoleName)
		}
	}

	desired := make(map[string]bool, len(ruleSets))
	for _, rs := range ruleSets {
		if err := r.applyOne(ctx, subject, rs); err != nil {
			return fmt.Errorf("applying crossns RBAC in namespace %s (role %s): %w", rs.Namespace, rs.RoleName, err)
		}
		desired[desiredKey(rs.Namespace, rs.RoleName)] = true
	}
	return r.gc(ctx, desired)
}

// desiredKey returns the composite GC key for a (namespace, roleName) pair.
func desiredKey(namespace, roleName string) string {
	return namespace + "/" + roleName
}

// Teardown deletes all managed Role and RoleBinding resources cluster-wide.
// Call this on CR deletion or ManagementState=Removed.
//
// WARNING: if no OwnerLabel is set, Teardown sweeps ALL resources carrying
// ManagedLabelKey in the entire cluster, including those created by other
// Reconciler instances. Always set a distinct OwnerLabel when multiple
// operators or controller instances share the same cluster.
func (r *Reconciler) Teardown(ctx context.Context) error {
	return r.gc(ctx, nil)
}

// gc removes managed resources whose (namespace, roleName) pair is not in
// desired. A nil or empty desired set causes all managed resources to be
// removed. The RoleBinding name is derived from the Role name using the same
// "-binding" suffix convention as applyRoleBinding.
func (r *Reconciler) gc(ctx context.Context, desired map[string]bool) error {
	logger := log.FromContext(ctx)
	matchLabels := r.listOptions()

	var errs []error

	var roleList rbacv1.RoleList
	if err := r.client.List(ctx, &roleList, matchLabels); err != nil {
		errs = append(errs, fmt.Errorf("listing crossns Roles: %w", err))
	} else {
		for i := range roleList.Items {
			ns := roleList.Items[i].Namespace
			name := roleList.Items[i].Name
			if desired[desiredKey(ns, name)] {
				continue
			}
			logger.Info("GC crossns Role", "name", name, "namespace", ns)
			if err := r.client.Delete(ctx, &roleList.Items[i]); client.IgnoreNotFound(err) != nil {
				errs = append(errs, fmt.Errorf("deleting crossns Role %s/%s: %w", ns, name, err))
			}
		}
	}

	var rbList rbacv1.RoleBindingList
	if err := r.client.List(ctx, &rbList, matchLabels); err != nil {
		errs = append(errs, fmt.Errorf("listing crossns RoleBindings: %w", err))
	} else {
		for i := range rbList.Items {
			ns := rbList.Items[i].Namespace
			// Derive the Role name from the RoleBinding name by stripping the "-binding" suffix.
			// Resources not following this convention are left alone to avoid accidental deletion.
			rbName := rbList.Items[i].Name
			roleName := strings.TrimSuffix(rbName, "-binding")
			if desired[desiredKey(ns, roleName)] {
				continue
			}
			logger.Info("GC crossns RoleBinding", "name", rbName, "namespace", ns)
			if err := r.client.Delete(ctx, &rbList.Items[i]); client.IgnoreNotFound(err) != nil {
				errs = append(errs, fmt.Errorf("deleting crossns RoleBinding %s/%s: %w", ns, rbName, err))
			}
		}
	}

	return errors.Join(errs...)
}

// applyOne creates or updates the Role and RoleBinding for a single RuleSet.
func (r *Reconciler) applyOne(ctx context.Context, subject SubjectRef, rs RuleSet) error {
	if err := r.applyRole(ctx, rs); err != nil {
		return err
	}
	return r.applyRoleBinding(ctx, subject, rs)
}

func (r *Reconciler) applyRole(ctx context.Context, rs RuleSet) error {
	desired := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      rs.RoleName,
			Namespace: rs.Namespace,
			Labels:    r.managedLabels(),
		},
		Rules: rs.Rules,
	}

	existing := &rbacv1.Role{}
	err := r.client.Get(ctx, client.ObjectKeyFromObject(desired), existing)
	if k8serrors.IsNotFound(err) {
		if createErr := r.client.Create(ctx, desired); createErr != nil && !k8serrors.IsAlreadyExists(createErr) {
			return fmt.Errorf("creating Role %s/%s: %w", rs.Namespace, rs.RoleName, createErr)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("getting Role %s/%s: %w", rs.Namespace, rs.RoleName, err)
	}

	updatedLabels := mergeLabels(existing.Labels, desired.Labels)
	if reflect.DeepEqual(existing.Rules, desired.Rules) && reflect.DeepEqual(existing.Labels, updatedLabels) {
		return nil
	}
	existing.Rules = desired.Rules
	existing.Labels = updatedLabels
	return r.client.Update(ctx, existing)
}

func (r *Reconciler) applyRoleBinding(ctx context.Context, subject SubjectRef, rs RuleSet) error {
	rbName := rs.RoleName + "-binding"
	desired := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      rbName,
			Namespace: rs.Namespace,
			Labels:    r.managedLabels(),
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "Role",
			Name:     rs.RoleName,
		},
		Subjects: []rbacv1.Subject{{
			Kind:      rbacv1.ServiceAccountKind,
			Name:      subject.Name,
			Namespace: subject.Namespace,
		}},
	}

	existing := &rbacv1.RoleBinding{}
	err := r.client.Get(ctx, client.ObjectKeyFromObject(desired), existing)
	if k8serrors.IsNotFound(err) {
		if createErr := r.client.Create(ctx, desired); createErr != nil && !k8serrors.IsAlreadyExists(createErr) {
			return fmt.Errorf("creating RoleBinding %s/%s: %w", rs.Namespace, rbName, createErr)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("getting RoleBinding %s/%s: %w", rs.Namespace, rbName, err)
	}

	// RoleRef is immutable in Kubernetes — if it drifted the binding must be
	// deleted and recreated. In practice this should not happen since the role
	// name comes from a constant in the operator, but we defend against it.
	if existing.RoleRef != desired.RoleRef {
		if err := r.client.Delete(ctx, existing); client.IgnoreNotFound(err) != nil {
			return fmt.Errorf("deleting drifted RoleBinding %s/%s: %w", rs.Namespace, rbName, err)
		}
		fresh := desired.DeepCopy()
		if err := r.client.Create(ctx, fresh); err != nil && !k8serrors.IsAlreadyExists(err) {
			return fmt.Errorf("recreating RoleBinding %s/%s: %w", rs.Namespace, rbName, err)
		}
		return nil
	}

	updatedLabels := mergeLabels(existing.Labels, desired.Labels)
	if reflect.DeepEqual(existing.Subjects, desired.Subjects) && reflect.DeepEqual(existing.Labels, updatedLabels) {
		return nil
	}
	existing.Subjects = desired.Subjects
	existing.Labels = updatedLabels
	return r.client.Update(ctx, existing)
}

// listOptions returns the MatchingLabels for cluster-wide list queries.
func (r *Reconciler) listOptions() client.MatchingLabels {
	labels := client.MatchingLabels{
		ManagedLabelKey: ManagedLabelValue,
	}
	if r.owner.Key != "" {
		labels[r.owner.Key] = r.owner.Value
	}
	return labels
}

// managedLabels returns the label map to stamp onto managed resources.
func (r *Reconciler) managedLabels() map[string]string {
	labels := map[string]string{
		ManagedLabelKey: ManagedLabelValue,
	}
	if r.owner.Key != "" {
		labels[r.owner.Key] = r.owner.Value
	}
	return labels
}

// mergeLabels merges existing and additional into a new map; additional wins on
// conflict so that managed labels always override pre-existing values. Neither
// input map is modified.
func mergeLabels(existing, additional map[string]string) map[string]string {
	out := make(map[string]string, len(existing)+len(additional))
	for k, v := range existing {
		out[k] = v
	}
	for k, v := range additional {
		out[k] = v
	}
	return out
}
