package generators

import (
	"github.com/ugiordan/operator-rbac-toolkit/internal/plugin/common"
)

// GenerateWebhook creates the ValidatingWebhookConfiguration for SA protection.
func GenerateWebhook(cfg common.PluginConfig) (common.GeneratorOutput, error) {
	content, err := renderTemplate("validatingwebhookconfiguration.yaml.tmpl", cfg)
	if err != nil {
		return nil, err
	}
	return common.GeneratorOutput{
		"config/security/webhook/validatingwebhookconfiguration.yaml": content,
	}, nil
}
