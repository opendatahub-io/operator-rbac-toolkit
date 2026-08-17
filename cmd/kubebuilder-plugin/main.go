package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/opendatahub-io/operator-rbac-toolkit/internal/plugin"
	"sigs.k8s.io/kubebuilder/v4/pkg/plugin/external"
)

func main() {
	var req external.PluginRequest
	if err := json.NewDecoder(os.Stdin).Decode(&req); err != nil {
		fmt.Fprintf(os.Stderr, "failed to decode PluginRequest: %v\n", err)
		os.Exit(1)
	}

	resp := plugin.Handle(req)

	if err := json.NewEncoder(os.Stdout).Encode(resp); err != nil {
		fmt.Fprintf(os.Stderr, "failed to encode PluginResponse: %v\n", err)
		os.Exit(1)
	}

	// Error signaling is done through the JSON response (resp.Error + resp.ErrorMsgs).
	// The Kubebuilder protocol handles errors via the payload, not exit codes.
}
