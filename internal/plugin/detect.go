package plugin

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/ugiordan/operator-rbac-toolkit/internal/plugin/common"
	"sigs.k8s.io/yaml"
)

// DetectIdentity resolves operator identity from flags, manifests, and PROJECT file.
func DetectIdentity(cfg *common.PluginConfig, projectYAML string, universe map[string]string) error {
	var project map[string]interface{}
	if err := yaml.Unmarshal([]byte(projectYAML), &project); err != nil {
		return fmt.Errorf("cannot parse PROJECT file: %v", err)
	}

	projectName, _ := project["projectName"].(string)
	repoPath, _ := project["repo"].(string)

	// Manifest scan for SA name/namespace
	if cfg.SAName == "" || cfg.SANamespace == "" {
		if saYAML, ok := universe["config/rbac/service_account.yaml"]; ok {
			name, ns := extractSAFromYAML(saYAML)
			if cfg.SAName == "" && name != "" {
				cfg.SAName = name
			}
			if cfg.SANamespace == "" && ns != "" {
				cfg.SANamespace = ns
			}
		}
	}

	// Fall back to PROJECT file conventions
	if cfg.OperatorName == "" {
		if projectName == "" {
			return fmt.Errorf("PROJECT file does not contain 'projectName' field; specify --operator-name explicitly")
		}
		cfg.OperatorName = projectName
	}
	if cfg.SAName == "" {
		cfg.SAName = cfg.OperatorName + "-controller-manager"
	}
	if cfg.SANamespace == "" {
		cfg.SANamespace = cfg.OperatorName + "-system"
	}

	// Set Go module path from PROJECT file's "repo" field
	if cfg.ModulePath == "" {
		if repoPath != "" {
			cfg.ModulePath = repoPath
		} else {
			return fmt.Errorf("PROJECT file does not contain 'repo' field; cannot determine Go module path")
		}
	}

	return nil
}

func extractSAFromYAML(yamlContent string) (name, namespace string) {
	var sa struct {
		Metadata struct {
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
		} `json:"metadata"`
	}
	if err := yaml.Unmarshal([]byte(yamlContent), &sa); err != nil {
		return "", ""
	}
	return sa.Metadata.Name, sa.Metadata.Namespace
}

var reconcilerRegex = regexp.MustCompile(`type\s+(\w+Reconciler)\s+struct`)

// DetectReconcilers finds reconciler structs in internal/controller/ files.
func DetectReconcilers(universe map[string]string) []common.DetectedReconciler {
	var reconcilers []common.DetectedReconciler
	for path, content := range universe {
		if !strings.HasPrefix(path, "internal/controller/") {
			continue
		}
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		matches := reconcilerRegex.FindAllStringSubmatch(content, -1)
		for _, m := range matches {
			reconcilers = append(reconcilers, common.DetectedReconciler{
				Name:     m[1],
				FileName: path,
			})
		}
	}
	sort.Slice(reconcilers, func(i, j int) bool {
		return reconcilers[i].Name < reconcilers[j].Name
	})
	return reconcilers
}

// ExtractPolicyRules extracts RBAC rules from a role.yaml as raw YAML strings.
func ExtractPolicyRules(roleYAML string) []string {
	var role struct {
		Rules []map[string]interface{} `json:"rules"`
	}
	if err := yaml.Unmarshal([]byte(roleYAML), &role); err != nil {
		return nil
	}
	var rules []string
	for _, rule := range role.Rules {
		b, err := yaml.Marshal(rule)
		if err != nil {
			continue
		}
		rules = append(rules, string(b))
	}
	return rules
}
