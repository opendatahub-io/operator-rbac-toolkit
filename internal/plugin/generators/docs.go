package generators

import (
	"github.com/opendatahub-io/operator-rbac-toolkit/internal/plugin/common"
)

// GenerateDocs generates SECURITY_INTEGRATION.md with correct library API calls
// and per-reconciler checklists.
func GenerateDocs(cfg common.PluginConfig) (common.GeneratorOutput, error) {
	rendered, err := renderTemplate("integration.md.tmpl", cfg)
	if err != nil {
		return nil, err
	}

	return common.GeneratorOutput{
		"SECURITY_INTEGRATION.md": rendered,
	}, nil
}
