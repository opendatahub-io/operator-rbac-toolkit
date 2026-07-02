package saprotection

type WebhookConfig struct {
	ProtectedServiceAccounts []string
	AllowedIdentities        []string
}
