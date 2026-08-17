# Adding SA Identity Protection

The SA protection webhook (`pkg/saprotection`) prevents unauthorized workloads from using your operator's ServiceAccount. Without this, any user with `create pods` permission in the operator's namespace can create a pod that inherits the operator's full RBAC permissions.

## Register the Webhook in main.go

```go
import (
    "github.com/opendatahub-io/operator-rbac-toolkit/pkg/saprotection"
    "sigs.k8s.io/controller-runtime/pkg/webhook"
)

func main() {
    mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
        Scheme: scheme,
        WebhookServer: webhook.NewServer(webhook.Options{
            Port:    9443,
            CertDir: "/tmp/k8s-webhook-server/serving-certs",
        }),
    })
    if err != nil {
        setupLog.Error(err, "unable to start manager")
        os.Exit(1)
    }

    saWebhook := saprotection.NewWebhook(
        saprotection.WebhookConfig{
            ProtectedServiceAccounts: []string{
                "my-operator",
                "my-operator-controller-manager",
            },
            AllowedIdentities: []string{
                // The operator's own controller SA
                "system:serviceaccount:my-operator-system:my-operator",
                // Kubernetes system controllers that create pods on behalf of Deployments/Jobs
                "system:serviceaccount:kube-system:replicaset-controller",
                "system:serviceaccount:kube-system:job-controller",
                "system:serviceaccount:kube-system:statefulset-controller",
                "system:serviceaccount:kube-system:daemon-set-controller",
            },
        },
        mgr.GetScheme(),
    )

    mgr.GetWebhookServer().Register("/validate-sa-protection", &webhook.Admission{Handler: saWebhook})

    // ... start manager ...
}
```

## Deploy the ValidatingWebhookConfiguration

```yaml
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: sa-protection
webhooks:
  - name: sa-protection.operator-rbac-toolkit.io
    admissionReviewVersions: ["v1"]
    clientConfig:
      service:
        name: my-operator-webhook-service
        namespace: my-operator-system
        path: /validate-sa-protection
    failurePolicy: Fail
    sideEffects: None
    rules:
      - apiGroups: [""]
        apiVersions: ["v1"]
        operations: ["CREATE", "UPDATE"]
        resources: ["pods"]
    namespaceSelector:
      matchLabels:
        operator-rbac-toolkit.io/sa-protection: "true"
```

## Label the Namespace to Enable Enforcement

```bash
kubectl label namespace my-operator-system operator-rbac-toolkit.io/sa-protection=true
```

## How It Works

The webhook intercepts Pod CREATE and UPDATE requests:

1. If the pod does not use a protected ServiceAccount, the request is allowed.
2. For UPDATE operations, if the ServiceAccount field has not changed, the request is allowed (avoids false positives from kubelet status updates).
3. If the requesting user is in the `AllowedIdentities` list, the request is allowed.
4. Otherwise, the request is denied with `"ServiceAccount <name> is protected"`.

## System Controller Tradeoff

Including system controllers (e.g., `replicaset-controller`) in `AllowedIdentities` means any Deployment in the operator's namespace can reference the protected SA. The webhook prevents *direct* Pod creation with the SA but does not prevent *indirect* creation via Deployments or Jobs.

**Compensating control:** restrict `create` on Deployments, StatefulSets, and Jobs in the operator's namespace to authorized principals via standard RBAC.

## Deployment Considerations

- Deploy the webhook in a **separate namespace** from the operator it protects. If the webhook pod is down and `failurePolicy: Fail` is set, all pod creation in the scoped namespace is blocked.
- Use a `PriorityClass` to ensure the webhook pod schedules before operator workloads.
- Configure `PodDisruptionBudgets` for high availability.
