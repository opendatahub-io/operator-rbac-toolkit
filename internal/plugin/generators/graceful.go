package generators

import (
	"github.com/opendatahub-io/operator-rbac-toolkit/internal/plugin/common"
)

// GenerateGraceful generates pkg/security/graceful_setup.go with the
// graceful.Handler factory and StatusProvider helper.
func GenerateGraceful(cfg common.PluginConfig) (common.GeneratorOutput, error) {
	rendered, err := renderTemplate("graceful_setup.go.tmpl", cfg)
	if err != nil {
		return nil, err
	}

	return common.GeneratorOutput{
		"pkg/security/graceful_setup.go": rendered,
	}, nil
}
