package generators

import (
	"github.com/ugiordan/operator-rbac-toolkit/internal/plugin/common"
)

// GenerateAudit generates pkg/security/audit_setup.go with the RBAC audit
// startup integration.
func GenerateAudit(cfg common.PluginConfig) (common.GeneratorOutput, error) {
	rendered, err := renderTemplate("audit_setup.go.tmpl", cfg)
	if err != nil {
		return nil, err
	}

	return common.GeneratorOutput{
		"pkg/security/audit_setup.go": rendered,
	}, nil
}
