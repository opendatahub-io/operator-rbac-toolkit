package plugin

import (
	"encoding/json"
	"fmt"

	"github.com/ugiordan/operator-rbac-toolkit/internal/plugin/common"
)

// PluginState is persisted to .ort-plugin-state.json.
type PluginState struct {
	PluginVersion  string     `json:"pluginVersion"`
	ToolkitVersion string     `json:"toolkitVersion"`
	Flags          StateFlags `json:"flags"`
}

// StateFlags records which flags were used.
type StateFlags struct {
	SAProtection bool `json:"saProtection"`
	RBACAudit    bool `json:"rbacAudit"`
}

// WriteState generates the state file and detects drift from a previous run.
func WriteState(cfg common.PluginConfig, universe map[string]string) (common.GeneratorOutput, []string) {
	var warnings []string

	// Drift detection runs whenever a previous state file exists
	if oldJSON, ok := universe[".ort-plugin-state.json"]; ok {
		var oldState PluginState
		if err := json.Unmarshal([]byte(oldJSON), &oldState); err == nil {
			warnings = append(warnings, detectDrift(oldState.Flags, cfg)...)
		}
	}

	newState := PluginState{
		PluginVersion:  cfg.PluginVersion,
		ToolkitVersion: cfg.ToolkitVersion,
		Flags: StateFlags{
			SAProtection: cfg.SAProtection,
			RBACAudit:    cfg.RBACAudit,
		},
	}

	b, err := json.MarshalIndent(newState, "", "  ")
	if err != nil {
		warnings = append(warnings, fmt.Sprintf("failed to marshal plugin state: %v", err))
		return common.GeneratorOutput{}, warnings
	}
	return common.GeneratorOutput{".ort-plugin-state.json": string(b) + "\n"}, warnings
}

// componentGuidance maps flag names to actionable guidance when newly enabled.
var componentGuidance = map[string]string{
	"sa-protection": "Register the SA protection webhook with the manager. See SECURITY_INTEGRATION.md.",
	"rbac-audit":    "Add audit.Scan() call at startup. See SECURITY_INTEGRATION.md.",
}

func detectDrift(old StateFlags, cfg common.PluginConfig) []string {
	var drifts []string
	check := func(name string, oldVal, newVal bool) {
		if oldVal != newVal {
			drifts = append(drifts, fmt.Sprintf("flag drift detected: previous run used --%s=%v, current run uses --%s=%v", name, oldVal, name, newVal))
			if newVal && !oldVal {
				guidance := componentGuidance[name]
				drifts = append(drifts, fmt.Sprintf("Component %s was not enabled during initial generation. Update pkg/security/config.go manually. %s", name, guidance))
			}
		}
	}
	check("sa-protection", old.SAProtection, cfg.SAProtection)
	check("rbac-audit", old.RBACAudit, cfg.RBACAudit)
	return drifts
}
