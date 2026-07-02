package impersonation

import "time"

const (
	aggregateToEditLabel = "rbac.authorization.kubernetes.io/aggregate-to-edit"
	autoupdateAnnotation = "rbac.authorization.kubernetes.io/autoupdate"

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
