package plugin

import (
	"flag"
	"fmt"
	"regexp"
	"strings"

	"github.com/opendatahub-io/operator-rbac-toolkit/internal/plugin/common"
)

var dns1123Regex = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)

// ParseFlags parses CLI arguments into a PluginConfig.
func ParseFlags(args []string) (common.PluginConfig, error) {
	cfg := common.PluginConfig{
		SAProtection: true,
		RBACAudit:    true,
	}

	fs := flag.NewFlagSet("create security", flag.ContinueOnError)
	fs.StringVar(&cfg.OperatorName, "operator-name", "", "Operator name for resource naming")
	fs.StringVar(&cfg.SAName, "sa-name", "", "ServiceAccount name to protect")
	fs.StringVar(&cfg.SANamespace, "sa-namespace", "", "Namespace of the protected SA")
	fs.BoolVar(&cfg.SAProtection, "sa-protection", true, "Generate SA protection webhook configuration")
	fs.BoolVar(&cfg.RBACAudit, "rbac-audit", true, "Generate RBAC audit startup integration")
	fs.BoolVar(&cfg.DryRun, "dry-run", false, "Print generated files without writing")
	fs.BoolVar(&cfg.Force, "force", false, "Overwrite existing regenerable files")

	if err := fs.Parse(args); err != nil {
		return cfg, err
	}

	return cfg, nil
}

// ValidateFlags checks flag values.
func ValidateFlags(cfg *common.PluginConfig) error {
	if cfg.OperatorName == "" {
		return fmt.Errorf("operator name must not be empty")
	}
	if cfg.SAName == "" {
		return fmt.Errorf("SA name must not be empty")
	}
	if cfg.SANamespace == "" {
		return fmt.Errorf("SA namespace must not be empty")
	}

	if err := validateDNS1123("operator name", cfg.OperatorName); err != nil {
		return err
	}
	if err := validateDNS1123("SA name", cfg.SAName); err != nil {
		return err
	}
	if err := validateDNS1123("SA namespace", cfg.SANamespace); err != nil {
		return err
	}

	return nil
}

func validateDNS1123(field, name string) error {
	if name == "" {
		return nil
	}
	if len(name) > 253 {
		return fmt.Errorf("name '%s...' exceeds Kubernetes maximum of 253 characters", name[:min(20, len(name))])
	}
	if !dns1123Regex.MatchString(name) {
		for i, ch := range name {
			valid := (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-'
			if !valid {
				return fmt.Errorf("invalid %s '%s': character '%c' at position %d is not valid in a Kubernetes resource name (must match [a-z0-9]([-a-z0-9]*[a-z0-9]))", field, name, ch, i)
			}
		}
		if strings.HasPrefix(name, "-") || strings.HasSuffix(name, "-") {
			return fmt.Errorf("invalid %s '%s': must not start or end with a dash", field, name)
		}
		return fmt.Errorf("invalid %s '%s': must match DNS-1123 label format [a-z0-9]([-a-z0-9]*[a-z0-9])", field, name)
	}
	return nil
}
