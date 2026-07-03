# Key Architectural Tradeoffs

This page documents the major design decisions made during the Operator RBAC Toolkit's development, including the alternatives considered and the rationale for each choice. It also covers known limitations and their mitigations.

---

## Separate Controller vs. Embedded Library

The RBAC Scoping Controller can be deployed as a standalone binary or imported as a Go package into an existing platform operator. Both options use the same `pkg/scoper` library. The tradeoff is deployment model and security posture, not implementation.

| Concern | Separate Controller (standalone binary) | Embedded Library (imported by platform operator) |
|---------|----------------------------------------|--------------------------------------------------|
| Deployment friction | Additional Deployment to install | Zero additional friction (code import) |
| Trust domain | Full separation (separate SA) | Collapsed (shared with platform operator's SA) |
| Upgrade path | Independent release cycle | Coupled to platform operator releases |
| HA | Leader election with 2 replicas | Inherits host operator's HA |
| Best for | Compliance-sensitive, multi-tenant, or untrusted operator environments | Clusters with an existing platform operator (e.g., RHOAI) where the platform operator is already highly privileged |

**When to choose standalone:** compliance requirements demand trust domain separation, or the cluster runs operators from multiple vendors with different trust levels.

**When to choose embedded:** a platform operator (e.g., the RHOAI operator) already exists, is already highly privileged, and adding the scoping logic does not meaningfully increase its blast radius.

---

## Annotation-Based vs. Finalizer-Based Cross-Namespace GC

Cross-namespace RoleBindings cannot use Kubernetes OwnerReferences (K8s does not allow cross-namespace OwnerReferences). Two garbage collection strategies were evaluated.

| Concern | Annotations | Finalizers |
|---------|-------------|------------|
| Deletion latency | Requires periodic scan (default: 5 minutes) | Immediate on CR deletion |
| Failure mode | Orphan persists until next scan (over-grant) | Stuck CR if controller is down (blocks namespace deletion) |
| Operational risk | Low (temporary over-grant) | High (stuck finalizer blocks namespace deletion) |

**Decision: Annotations.** Stuck finalizers are operationally worse than temporary orphans. An orphan RoleBinding grants access that should be revoked, which is a temporary over-grant. A stuck finalizer blocks namespace deletion entirely and can cascade into cluster-wide issues. The periodic cleanup scan (configurable interval, default 5 minutes) bounds the over-grant window.

---

## ConfigMap vs. CRD for Controller Configuration

The standalone scoping controller reads its configuration from a YAML file, typically mounted from a ConfigMap. A CRD-based configuration model was also evaluated.

| Concern | ConfigMap | CRD |
|---------|-----------|-----|
| Bootstrapping | No bootstrapping problem | Controller needs CRD to exist before it can start |
| Validation | Startup validation only | Webhook validation on create/update |
| Schema evolution | Unversioned | Versioned with conversion webhooks |
| Integrity protection | VAP template provided (`protect-scoper-config`) | Standard RBAC on CRD resources |
| Simplicity | Simple to deploy and manage | Additional complexity (CRD, webhook, RBAC for the CRD) |

**Decision: ConfigMap.** The scoping controller is a low-churn component; its configuration rarely changes after initial setup. The ConfigMap must reside in a privileged admin namespace with restricted access. A `protect-scoper-config` VAP template is provided to restrict write access.

Hot-reload is intentionally not supported. Configuration changes to the scoping controller affect which RoleBindings exist and where. Hot-reloading introduces failure modes (partial config application, race between old and new targets) that are unacceptable in a security-critical component. A controller restart is a well-understood, atomic configuration transition.

If schema evolution becomes important, a CRD can be added in a future version without breaking the ConfigMap path.

---

## SelfSubjectAccessReview vs. SelfSubjectRulesReview

The graceful degradation library needs to discover what permissions the operator's ServiceAccount has. Two Kubernetes APIs are available for this.

| Concern | SSAR (SelfSubjectAccessReview) | SSRR (SelfSubjectRulesReview) |
|---------|------|------|
| Query model | "Can I do X?" (yes/no) | "What can I do in namespace Y?" (full list) |
| Cost | One API call per check | One API call per namespace, but may be incomplete |
| Accuracy | Authoritative | May be incomplete (API docs caveat) |
| Use case | Checking specific permissions | Discovering all permissions |

**Decision: SSAR.** The graceful degradation library checks specific operations ("can I list secrets in namespace X?"), making SSAR the natural fit. SSAR is cheaper per check, fully authoritative, and sufficient for the permission-aware error handling use case. SSRR could be added as an option for startup discovery reports if the completeness caveat is acceptable.

---

## Known Limitations

### Scoping controller availability

If the scoping controller is down when a CR is created, the RoleBinding is not created until the controller recovers. During this window, the operator cannot access resources in the new namespace. The graceful degradation library handles this by surfacing status conditions and retrying with exponential backoff.

**Mitigation:** Deploy the scoping controller with 2 replicas and leader election enabled.

### Cross-namespace orphan latency

Cross-namespace RoleBindings use annotation-based ownership with periodic cleanup. If a CR is deleted while the controller is down, the orphan RoleBinding persists until the next cleanup scan (default: 5 minutes). This is a temporary over-grant (access persists longer than needed), not an under-grant (access denied when needed).

The graceful degradation library does not detect over-grants; it only surfaces under-grants (missing permissions). Over-grant detection is the scoping controller's responsibility via its garbage collection mechanisms.

### Backup and restore

After a cluster restore from backup (e.g., Velero), CRs may exist with different UIDs than when the backup was taken. Cross-namespace RoleBinding annotations reference CRs by `namespace/name/uid`. If the UID has changed, the annotation entry looks like an orphan. The scoping controller's orphan scan will remove the stale entry and re-create it with the correct UID on the next reconciliation cycle.

There is a brief window (one reconciliation cycle) where the RoleBinding may be temporarily deleted and recreated.

### VAP self-protection

ValidatingAdmissionPolicies cannot intercept operations on VAP resources themselves. A compromised SA with permissions to modify VAPs could disable the protection policies. Additionally, if a VAP binding uses `namespaceSelector` for enforcement, an attacker who can modify namespace labels could remove the enforcement label, disabling the VAP for that namespace without touching the VAP or its binding.

**Mitigations:**

- Ensure no operator SA has write access to `validatingadmissionpolicies` or `validatingadmissionpolicybindings`.
- Deploy the `protect-vap-enforcement-labels` VAP to protect labels used by VAP binding namespaceSelectors.
- Use `matchPolicy: Exact` on VAP bindings where possible rather than label selectors.

### CRD not yet installed

If the scoping controller starts before the CRD for a configured GVK is installed, the controller logs a warning and skips that target. RoleBindings for that target are not created. The controller continues to process other configured targets. A controller restart is required after the CRD becomes available.

The CRD retry mechanism does not validate CRD provenance. If an attacker creates a CRD with the configured GVK before the legitimate operator's CRD is installed, the scoping controller would discover the attacker's CRD.

**Mitigation:** Deploy the scoping controller after the target CRDs are installed (e.g., in the same Helm release or Kustomize overlay), or use CRD-level RBAC to restrict who can create CRDs.

### Namespace label revocation latency

When a namespace label is removed and the namespace no longer matches a configured `NamespaceSelector`, the scoping controller deletes the managed RoleBinding. There is a brief window (typically one reconciliation cycle, under 10 seconds) between the label removal and the RoleBinding deletion during which the operator retains access in that namespace.

The `allow-rolebinding-in-labeled-namespaces` VAP does not retroactively invalidate existing RoleBindings.

### Annotation ownership forgery

If the scoping controller's SA is compromised, the attacker can forge annotation-based ownership entries on cross-namespace RoleBindings. By referencing real, existing CRs in the annotation, the attacker can make malicious RoleBindings survive garbage collection. After SA rotation (revoking the compromise), these forged RoleBindings persist because the cleanup reconciler sees valid-looking owners.

**Mitigation:** After a suspected scoping controller SA compromise, audit all managed RoleBindings (identifiable by their deterministic names) and verify each annotation owner entry corresponds to a legitimate scoping trigger. Consider deploying a one-time cleanup job that re-validates all managed RoleBindings against the current scoping target configuration.

### Per-namespace rule differentiation

Bind mode uses a single static ClusterRole as the permission ceiling. If an operator needs different rule sets for different namespaces (e.g., read-only in namespace A, read-write in namespace B), a single static ClusterRole cannot express this.

**Workaround:** Define multiple static ClusterRoles and configure separate `ScopingTarget` entries for each, with different `NamespaceSelector` configurations to control which namespaces receive which permission set.

### Network isolation

RBAC scoping controls API-level access but does not provide network isolation. An operator scoped to specific namespaces at the RBAC level is still network-reachable from pods in other namespaces.

**Mitigation:** Use NetworkPolicies for network-level isolation as a complementary control.
