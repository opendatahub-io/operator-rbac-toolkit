package plugin

import (
	"fmt"
	"sort"

	"github.com/opendatahub-io/operator-rbac-toolkit/internal/plugin/common"
	"github.com/opendatahub-io/operator-rbac-toolkit/internal/plugin/generators"
	"sigs.k8s.io/kubebuilder/v4/pkg/plugin/external"
)

const (
	PluginName     = "security.ort.io/v1"
	PluginVersion  = "0.1.0"
	ToolkitVersion = "0.1.0"

	configGoPath = "pkg/security/config.go"
)

func Handle(req external.PluginRequest) external.PluginResponse {
	resp := external.PluginResponse{
		APIVersion: req.APIVersion,
		Command:    req.Command,
	}

	switch req.Command {
	case "create security":
		return handleCreateSecurity(req, resp)
	default:
		resp.Error = true
		resp.ErrorMsgs = []string{
			fmt.Sprintf("unsupported command %q; this plugin only supports \"create security\"", req.Command),
		}
		return resp
	}
}

func handleCreateSecurity(req external.PluginRequest, resp external.PluginResponse) external.PluginResponse {
	resp.Metadata.Description = "Scaffold operator-rbac-toolkit integration (graceful degradation, SA protection webhook, RBAC audit)"
	resp.Metadata.Examples = "kubebuilder create security --plugins=security.ort.io/v1"

	cfg, err := ParseFlags(req.Args)
	if err != nil {
		resp.Error = true
		resp.ErrorMsgs = []string{err.Error()}
		return resp
	}

	projectYAML, ok := req.Universe["PROJECT"]
	if !ok {
		resp.Error = true
		resp.ErrorMsgs = []string{"must be run in a Kubebuilder project directory (no PROJECT file found)"}
		return resp
	}

	if err := DetectIdentity(&cfg, projectYAML, req.Universe); err != nil {
		resp.Error = true
		resp.ErrorMsgs = []string{err.Error()}
		return resp
	}

	if err := ValidateFlags(&cfg); err != nil {
		resp.Error = true
		resp.ErrorMsgs = []string{err.Error()}
		return resp
	}

	cfg.PluginVersion = PluginVersion
	cfg.ToolkitVersion = ToolkitVersion

	configExists := universeHas(req.Universe, configGoPath)

	if configExists && !cfg.Force {
		resp.Error = true
		resp.ErrorMsgs = []string{
			"security plugin already configured (pkg/security/ exists). Use --force to regenerate manifests and SECURITY_INTEGRATION.md, or delete pkg/security/ to start fresh. Note: config.go is never overwritten.",
		}
		return resp
	}

	cfg.DetectedReconcilers = DetectReconcilers(req.Universe)

	if roleYAML, ok := req.Universe["config/rbac/role.yaml"]; ok {
		cfg.ExistingRBACRules = ExtractPolicyRules(roleYAML)
	}

	output := make(common.GeneratorOutput)

	genTable := []struct {
		name string
		fn   func(common.PluginConfig) (common.GeneratorOutput, error)
		skip bool
	}{
		{"config.go", generators.GenerateConfig, configExists},
		{"graceful handler", generators.GenerateGraceful, false},
		{"webhook manifests", generators.GenerateWebhook, !cfg.SAProtection},
		{"RBAC audit", generators.GenerateAudit, !cfg.RBACAudit},
		{"SECURITY_INTEGRATION.md", generators.GenerateDocs, false},
	}

	for _, g := range genTable {
		if g.skip {
			continue
		}
		files, err := g.fn(cfg)
		if err != nil {
			resp.Error = true
			resp.ErrorMsgs = []string{fmt.Sprintf("generating %s: %v", g.name, err)}
			return resp
		}
		for k, v := range files {
			if _, exists := output[k]; exists {
				resp.Error = true
				resp.ErrorMsgs = []string{fmt.Sprintf("generator conflict: multiple generators produced %s", k)}
				return resp
			}
			output[k] = v
		}
	}

	stateFiles, warnings := WriteState(cfg, req.Universe)
	for k, v := range stateFiles {
		output[k] = v
	}

	// Surface drift warnings in metadata description (non-fatal)
	if len(warnings) > 0 {
		warnText := "\n\nDrift warnings:"
		for _, w := range warnings {
			warnText += "\n  [WARN] " + w
		}
		resp.Metadata.Description += warnText
	}

	if cfg.DryRun {
		keys := sortedKeys(output)
		resp.Metadata.Description = fmt.Sprintf("[dry-run] Would generate %d files", len(output))
		for _, path := range keys {
			resp.Metadata.Description += fmt.Sprintf("\n--- %s ---\n%s", path, output[path])
		}
		return resp
	}

	resp.Universe = make(map[string]string, len(req.Universe)+len(output))
	for k, v := range req.Universe {
		resp.Universe[k] = v
	}
	for k, v := range output {
		resp.Universe[k] = v
	}

	return resp
}

func universeHas(universe map[string]string, key string) bool {
	_, ok := universe[key]
	return ok
}

func sortedKeys(m common.GeneratorOutput) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
