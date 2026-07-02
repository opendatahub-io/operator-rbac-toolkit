package saprotection

// WebhookConfig configures the SA protection webhook.
//
// ProtectedServiceAccounts uses name-only matching (not namespace-qualified).
// This is intentional: the webhook is scoped to the operator's namespace via
// namespaceSelector on the ValidatingWebhookConfiguration, so name-only
// matching within that scope is sufficient. Cross-namespace protection is
// handled by deploying separate webhook configurations per namespace.
type WebhookConfig struct {
	ProtectedServiceAccounts []string
	AllowedIdentities        []string
}
