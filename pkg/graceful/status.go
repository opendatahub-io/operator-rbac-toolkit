package graceful

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func SetPermissionGranted(obj StatusProvider, granted bool, message string) {
	SetPermissionGrantedWithReason(obj, granted, message, "")
}

func SetPermissionGrantedWithReason(obj StatusProvider, granted bool, message string, customReason string) {
	if granted {
		setCondition(obj, metav1.Condition{
			Type:    ConditionTypePermissionGranted,
			Status:  metav1.ConditionTrue,
			Reason:  ReasonAllPermissionsAvailable,
			Message: message,
		})
		setCondition(obj, metav1.Condition{
			Type:    ConditionTypeDegraded,
			Status:  metav1.ConditionFalse,
			Reason:  ReasonFullyOperational,
			Message: message,
		})
	} else {
		reason := ReasonMissingPermissions
		if customReason != "" {
			reason = customReason
		}
		setCondition(obj, metav1.Condition{
			Type:    ConditionTypePermissionGranted,
			Status:  metav1.ConditionFalse,
			Reason:  reason,
			Message: message,
		})
		// When provisioning is still pending (RoleBinding not yet created),
		// the operator is not truly degraded: it is waiting for the RBAC
		// provisioner to act. Only mark Degraded=True for confirmed denials.
		if customReason == ReasonProvisioningPending {
			setCondition(obj, metav1.Condition{
				Type:    ConditionTypeDegraded,
				Status:  metav1.ConditionFalse,
				Reason:  ReasonProvisioningInProgress,
				Message: message,
			})
		} else {
			setCondition(obj, metav1.Condition{
				Type:    ConditionTypeDegraded,
				Status:  metav1.ConditionTrue,
				Reason:  ReasonInsufficientRBAC,
				Message: message,
			})
		}
	}
}

func UpdateStatus(ctx context.Context, c client.Client, obj client.Object) error {
	if c == nil {
		return nil
	}
	return c.Status().Update(ctx, obj)
}

func setCondition(obj StatusProvider, condition metav1.Condition) {
	now := metav1.Now()
	conditions := obj.GetConditions()

	for i, existing := range conditions {
		if existing.Type == condition.Type {
			if existing.Status == condition.Status &&
				existing.Reason == condition.Reason &&
				existing.Message == condition.Message {
				// Completely identical, no-op
				return
			}
			// Only update LastTransitionTime when the Status actually changes.
			// Reason/Message-only changes preserve the existing transition time.
			if existing.Status != condition.Status {
				condition.LastTransitionTime = now
			} else {
				condition.LastTransitionTime = existing.LastTransitionTime
			}
			conditions[i] = condition
			obj.SetConditions(conditions)
			return
		}
	}

	// New condition, set the transition time
	condition.LastTransitionTime = now
	conditions = append(conditions, condition)
	obj.SetConditions(conditions)
}

func findCondition(obj StatusProvider, conditionType string) *metav1.Condition {
	conditions := obj.GetConditions()
	for i := range conditions {
		if conditions[i].Type == conditionType {
			return &conditions[i]
		}
	}
	return nil
}

func permissionDeniedMessage(verb, resource, namespace string) string {
	if namespace != "" {
		return fmt.Sprintf("Missing permission: %s %s in namespace %q", verb, resource, namespace)
	}
	return fmt.Sprintf("Missing permission: %s %s (cluster-scoped)", verb, resource)
}
