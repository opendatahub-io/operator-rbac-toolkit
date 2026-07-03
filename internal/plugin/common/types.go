package common

// PluginConfig holds parsed and validated configuration for code generation.
type PluginConfig struct {
	// Feature flags
	SAProtection bool
	RBACAudit    bool

	// Operator identity
	OperatorName string
	SAName       string
	SANamespace  string

	// Go module path (parsed from PROJECT file's "repo" field)
	ModulePath string

	// Modes
	DryRun bool
	Force  bool

	// Detected from Universe
	DetectedReconcilers []DetectedReconciler
	ExistingRBACRules   []string // Raw YAML rules from config/rbac/role.yaml

	// Plugin metadata
	PluginVersion  string
	ToolkitVersion string
}

// DetectedReconciler represents a reconciler found in internal/controller/.
type DetectedReconciler struct {
	Name     string // e.g., "MyResourceReconciler"
	FileName string // e.g., "internal/controller/myresource_controller.go"
}

// GeneratorOutput holds generated file contents keyed by path.
type GeneratorOutput map[string]string
