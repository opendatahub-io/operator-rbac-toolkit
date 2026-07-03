# VAP Templates

## Overview

The toolkit provides ValidatingAdmissionPolicy (VAP) templates that enforce RBAC invariants at the API server level. These templates work independently of the toolkit's Go packages. Because enforcement happens inside the API server itself, a compromised ServiceAccount cannot bypass them.

VAP templates are provided as YAML files in `config/vap/`. Cluster admins deploy them via Kustomize, Helm, or GitOps. Each template includes inline documentation explaining what it protects and how to configure it.

## Requirements

- **Kubernetes 1.30+** (ValidatingAdmissionPolicy reached GA in 1.30)
- **OpenShift 4.17+** (ships Kubernetes 1.30)

On older clusters, see [Clusters Without VAP Support](#clusters-without-vap-support) below.

## Available Templates

| Template | Purpose | What It Prevents |
|----------|---------|-----------------|
| `deny-impersonate-grants` | Block impersonation privilege grants in any Role/ClusterRole | Impersonation bypass |
| `restrict-scoped-rolebinding-creation` | Only the scoping controller's SA can create managed RoleBindings | Unauthorized RoleBinding creation by compromised operator |
| `restrict-scoped-rolebinding-mutation` | Only the scoping controller's SA can update or delete managed RoleBindings | Unauthorized RoleBinding modification or deletion |
| `restrict-scoped-rolebinding-subjects` | Managed RoleBindings can only reference the target operator's SA | Subject manipulation to grant access to attacker-controlled SA |
| `deny-rolebinding-in-protected-namespaces` | Default deny-list for sensitive namespaces (kube-system, kube-public, etc.) | RoleBinding creation in system namespaces |
| `allow-rolebinding-in-labeled-namespaces` | Only admin-labeled namespaces can receive managed RoleBindings | RoleBinding creation in unauthorized namespaces |
| `protect-rbac-allowed-label` | Prevents non-admin label manipulation on namespaces | Label spoofing to bypass namespace restrictions |
| `protect-vap-enforcement-labels` | Prevents non-admin manipulation of labels used by VAP binding namespaceSelectors | Disabling VAP enforcement by removing enforcement labels |
| `protect-static-clusterrole` | Prevents modification of the static ClusterRole | Permission ceiling tampering |
| `deny-aggregated-static-clusterrole` | Blocks attempts to add an `aggregationRule` field to the static ClusterRole (defense-in-depth alongside `protect-static-clusterrole`) | Aggregation-based permission injection via ClusterRole modification |
| `protect-scoper-config` | Restricts write access to the scoping controller's ConfigMap | Configuration tampering |
| `restrict-ephemeral-containers-on-protected-pods` | Restricts who can create ephemeral containers on pods using protected SAs | SA token access via kubectl debug |

## Recommended Production Stack

Deploy these VAPs in order of priority.

### Tier 1: Critical (deploy immediately)

These templates protect the core security invariants. Deploy them as soon as the scoping controller is active.

| Template | What It Does |
|----------|-------------|
| `protect-static-clusterrole` | Prevents permission ceiling tampering |
| `deny-aggregated-static-clusterrole` | Prevents aggregation-based rule injection |
| `restrict-scoped-rolebinding-creation` | Only the scoping controller creates managed RoleBindings |
| `restrict-scoped-rolebinding-mutation` | Prevents unauthorized RoleBinding modification |
| `deny-impersonate-grants` | Companion to the impersonation guard |

### Tier 2: Namespace Protection (deploy with scoping controller)

These templates enforce namespace-level authorization. Deploy them alongside the scoping controller to control where RoleBindings can be created.

| Template | What It Does |
|----------|-------------|
| `deny-rolebinding-in-protected-namespaces` | Deny-list for sensitive namespaces |
| `allow-rolebinding-in-labeled-namespaces` | Allow-list for authorized namespaces |
| `protect-rbac-allowed-label` | Prevents namespace label spoofing |

### Tier 3: Defense in Depth (deploy when ready)

These templates add additional layers of protection. They are not required for the core scoping functionality but significantly harden the deployment.

| Template | What It Does |
|----------|-------------|
| `restrict-scoped-rolebinding-subjects` | Prevents subject manipulation |
| `protect-vap-enforcement-labels` | Prevents VAP bypass via label removal |
| `protect-scoper-config` | Protects scoping controller configuration |
| `restrict-ephemeral-containers-on-protected-pods` | Prevents SA token access via `kubectl debug` |

## Customization

Each VAP template needs to be customized for your environment before deployment. The fields you need to update depend on the template.

| Template | Fields to Update |
|----------|-----------------|
| `restrict-scoped-rolebinding-creation` | ServiceAccount name and namespace for the scoping controller's SA |
| `restrict-scoped-rolebinding-mutation` | ServiceAccount name and namespace for the scoping controller's SA |
| `restrict-scoped-rolebinding-subjects` | Target operator ServiceAccount name and namespace |
| `protect-static-clusterrole` | The name of the static ClusterRole to protect |
| `deny-aggregated-static-clusterrole` | The name of the static ClusterRole to protect |
| `deny-rolebinding-in-protected-namespaces` | Additional platform-specific namespace names (GKE, EKS, AKS system namespaces, etc.) |
| `allow-rolebinding-in-labeled-namespaces` | The admin-controlled label key that authorizes a namespace to receive managed RoleBindings |
| `protect-rbac-allowed-label` | The label key to protect, matching the key used in `allow-rolebinding-in-labeled-namespaces` |
| `protect-vap-enforcement-labels` | The label keys used by your VAP binding namespaceSelectors |
| `protect-scoper-config` | ConfigMap name, namespace, and allowed ServiceAccount identity |
| `restrict-ephemeral-containers-on-protected-pods` | Protected ServiceAccount names and allowed debug identities |

Each YAML template includes inline comments documenting the fields that need customization.

## Clusters Without VAP Support

On Kubernetes < 1.30 (OpenShift < 4.17), deploy the core components without VAPs:

1. **Scoping controller** for dynamic RoleBinding management
2. **Graceful degradation library** for permission-aware error handling
3. **SA protection webhook** for SA identity protection
4. **Impersonation guard** for impersonate verb removal
5. **RBAC audit** for exposure scanning

The VAP templates provide defense in depth but are not required for the core scoping functionality to work. The scoping controller enforces deny-lists and namespace selectors in its own code, and the SA protection webhook enforces SA identity protection via a ValidatingWebhookConfiguration (available since Kubernetes 1.16). The main gap without VAPs is the absence of API-server-enforced invariants on RoleBinding creation, ClusterRole protection, and label manipulation.
