package main

import (
	"fmt"
	"os"
	"time"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	pflag "github.com/spf13/pflag"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	sigsyaml "sigs.k8s.io/yaml"

	"github.com/ugiordan/operator-rbac-toolkit/pkg/scoper"
)

// fileConfig is the YAML-friendly representation of scoper.Config.
// We need this because schema.GroupVersionKind and types.NamespacedName
// don't carry YAML struct tags.
type fileConfig struct {
	ControllerNamespace string              `yaml:"controllerNamespace"`
	CleanupInterval     string              `yaml:"cleanupInterval"`
	DenyList            fileDenyListConfig   `yaml:"denyList"`
	Targets             []fileScopingTarget  `yaml:"targets"`
}

type fileDenyListConfig struct {
	Namespaces []string `yaml:"namespaces"`
	Prefixes   []string `yaml:"prefixes"`
}

type fileScopingTarget struct {
	WatchGVK               fileGVK              `yaml:"watchGVK"`
	TargetSA               fileNamespacedName    `yaml:"targetSA"`
	ClusterRoleName        string                `yaml:"clusterRoleName"`
	ManagedRoleBindingName string                `yaml:"managedRoleBindingName"`
	NamespaceSelector      *metav1.LabelSelector `yaml:"namespaceSelector,omitempty"`
	TargetNamespaceSource  *fileNamespaceSource  `yaml:"targetNamespaceSource,omitempty"`
}

type fileGVK struct {
	Group   string `yaml:"group"`
	Version string `yaml:"version"`
	Kind    string `yaml:"kind"`
}

type fileNamespacedName struct {
	Namespace string `yaml:"namespace"`
	Name      string `yaml:"name"`
}

type fileNamespaceSource struct {
	FieldPath string `yaml:"fieldPath"`
}

func main() {
	configPath := pflag.String("config", "/etc/rbac-scoper/config.yaml", "path to the scoper configuration file")
	pflag.Parse()

	ctrl.SetLogger(zap.New(zap.UseDevMode(false)))
	setupLog := ctrl.Log.WithName("setup")

	cfg, err := loadConfig(*configPath)
	if err != nil {
		setupLog.Error(err, "failed to load configuration", "path", *configPath)
		os.Exit(1)
	}

	restCfg := ctrl.GetConfigOrDie()

	// Intentionally minimal scheme: only core/v1 and rbac/v1 are registered
	// because the scoper only watches Namespaces, ServiceAccounts, RoleBindings,
	// and ClusterRoles. Adding more types here is unnecessary unless new GVKs
	// are introduced as watch targets.
	scheme := runtime.NewScheme()
	utilruntime.Must(corev1.AddToScheme(scheme))
	utilruntime.Must(rbacv1.AddToScheme(scheme))

	mgr, err := ctrl.NewManager(restCfg, ctrl.Options{
		Scheme:           scheme,
		LeaderElection:   true,
		LeaderElectionID: "rbac-scoper-leader",
	})
	if err != nil {
		setupLog.Error(err, "unable to create manager")
		os.Exit(1)
	}

	if err := scoper.Setup(mgr, cfg); err != nil {
		setupLog.Error(err, "unable to set up scoper controllers")
		os.Exit(1)
	}

	setupLog.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "manager exited with error")
		os.Exit(1)
	}
}

// loadConfig reads a YAML config file and converts it to a scoper.Config.
func loadConfig(path string) (scoper.Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return scoper.Config{}, fmt.Errorf("reading config file: %w", err)
	}

	var fc fileConfig
	if err := sigsyaml.UnmarshalStrict(data, &fc); err != nil {
		return scoper.Config{}, fmt.Errorf("parsing config file: %w", err)
	}

	return convertConfig(fc)
}

// convertConfig transforms the YAML-friendly fileConfig into the typed scoper.Config.
func convertConfig(fc fileConfig) (scoper.Config, error) {
	if fc.ControllerNamespace == "" {
		return scoper.Config{}, fmt.Errorf("controllerNamespace is required (empty value silently weakens the deny list)")
	}

	cfg := scoper.Config{
		ControllerNamespace: fc.ControllerNamespace,
		DenyList: scoper.DenyListConfig{
			Namespaces: fc.DenyList.Namespaces,
			Prefixes:   fc.DenyList.Prefixes,
		},
	}

	if fc.CleanupInterval != "" {
		d, err := time.ParseDuration(fc.CleanupInterval)
		if err != nil {
			return scoper.Config{}, fmt.Errorf("invalid cleanupInterval %q: %w", fc.CleanupInterval, err)
		}
		cfg.CleanupInterval = metav1.Duration{Duration: d}
	}

	for i, ft := range fc.Targets {
		target := scoper.ScopingTarget{
			WatchGVK: schema.GroupVersionKind{
				Group:   ft.WatchGVK.Group,
				Version: ft.WatchGVK.Version,
				Kind:    ft.WatchGVK.Kind,
			},
			TargetSA: types.NamespacedName{
				Namespace: ft.TargetSA.Namespace,
				Name:      ft.TargetSA.Name,
			},
			ClusterRoleName:        ft.ClusterRoleName,
			ManagedRoleBindingName: ft.ManagedRoleBindingName,
			NamespaceSelector:      ft.NamespaceSelector,
		}

		if ft.TargetNamespaceSource != nil {
			target.TargetNamespaceSource = &scoper.NamespaceSource{
				FieldPath: ft.TargetNamespaceSource.FieldPath,
			}
		}

		if target.WatchGVK.Kind == "" {
			return scoper.Config{}, fmt.Errorf("target %d: watchGVK.kind is required", i)
		}
		if target.TargetSA.Name == "" || target.TargetSA.Namespace == "" {
			return scoper.Config{}, fmt.Errorf("target %d: targetSA name and namespace are required", i)
		}
		if target.ClusterRoleName == "" {
			return scoper.Config{}, fmt.Errorf("target %d: clusterRoleName is required", i)
		}
		if target.ManagedRoleBindingName == "" {
			return scoper.Config{}, fmt.Errorf("target %d: managedRoleBindingName is required", i)
		}

		cfg.Targets = append(cfg.Targets, target)
	}

	return cfg, nil
}
