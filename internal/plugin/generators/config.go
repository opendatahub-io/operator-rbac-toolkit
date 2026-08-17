package generators

import (
	"github.com/opendatahub-io/operator-rbac-toolkit/internal/plugin/common"
)

// GenerateConfig generates pkg/security/config.go with OperatorIdentity,
// ProtectedIdentities, and getter functions. This file is user-owned and
// will not be overwritten on subsequent runs.
func GenerateConfig(cfg common.PluginConfig) (common.GeneratorOutput, error) {
	rendered, err := renderTemplate("config.go.tmpl", cfg)
	if err != nil {
		return nil, err
	}

	return common.GeneratorOutput{
		"pkg/security/config.go": rendered,
	}, nil
}
