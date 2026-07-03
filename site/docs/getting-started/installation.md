# Installation

## Install the Module

```bash
go get github.com/ugiordan/operator-rbac-toolkit@latest
```

## Packages

The toolkit is split into independent packages. Import only what you need.

| Package | Owner | Purpose |
|---------|-------|---------|
| `pkg/graceful` | Operator author | Permission-aware error handling, status conditions, permission discovery |
| `pkg/scoper` | Cluster admin | Dynamic namespace-scoped RoleBinding management |
| `pkg/saprotection` | Cluster admin | ValidatingWebhook protecting operator ServiceAccount identity |
| `pkg/impersonation` | Cluster admin | Closes the `impersonate` verb bypass in `system:aggregate-to-edit` |
| `pkg/audit` | Operator author or admin | Startup RBAC exposure scanning |

No package requires any other. The graceful degradation library (`pkg/graceful`) is the typical starting point for operator authors. The admin-side packages (`pkg/scoper`, `pkg/saprotection`, `pkg/impersonation`) are deployed by cluster administrators or platform operators.

## Prerequisites

| Requirement | Version | Notes |
|-------------|---------|-------|
| Go | 1.25+ | Required for building |
| Kubernetes | 1.25+ | Minimum cluster version for API compatibility |
| Kubernetes (for VAP templates) | 1.30+ | ValidatingAdmissionPolicy reached GA in 1.30 |
| controller-runtime | v0.22+ | Build dependency (requires k8s client-go v0.34+) |

Your operator must be built with [controller-runtime](https://github.com/kubernetes-sigs/controller-runtime) (Operator SDK, Kubebuilder, or equivalent).

**Note on version requirements.** The minimum cluster version (1.25+) refers to API compatibility. Build dependencies require controller-runtime v0.22+ (k8s client-go v0.34+). Kubernetes maintains backward API compatibility, so binaries built with newer client-go work against older clusters.

## What to Import

For most operator authors, the only import you need is `pkg/graceful`:

```go
import "github.com/ugiordan/operator-rbac-toolkit/pkg/graceful"
```

For cluster admins deploying the scoping controller as an embedded library:

```go
import "github.com/ugiordan/operator-rbac-toolkit/pkg/scoper"
```

For the standalone scoping controller binary, no import is needed. Deploy `cmd/scoper` as a separate Deployment.

## Next Steps

- **[Quick Start](quick-start.md)**: Add graceful degradation to an existing operator.
- **[Choose Your Deployment Model](choose-your-deployment.md)**: Standalone binary vs. embedded library for the scoping controller.
