package impersonation

import "time"

const (
	AggregateToEditLabel = "rbac.authorization.kubernetes.io/aggregate-to-edit"
	AutoupdateAnnotation = "rbac.authorization.kubernetes.io/autoupdate"

	DefaultRequeueAfter = 5 * time.Minute
)

type GuardConfig struct {
	RequeueAfter time.Duration
}

func DefaultGuardConfig() GuardConfig {
	return GuardConfig{
		RequeueAfter: DefaultRequeueAfter,
	}
}
