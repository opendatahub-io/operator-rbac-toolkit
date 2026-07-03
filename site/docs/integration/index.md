# Integration Guide

This section covers the complete integration reference for operator authors and cluster admins.

## For Operator Authors

- **[Graceful Degradation](graceful-degradation.md)**: Handle `Forbidden` errors gracefully with status conditions, events, and exponential backoff retry.
- **[RBAC Audit](rbac-audit.md)**: Scan and report on RBAC permissions at startup and runtime.

## For Cluster Admins

- **[RBAC Scoping](rbac-scoping.md)**: Deploy the scoping controller (standalone binary or embedded library) to manage namespace-scoped RoleBindings.
- **[SA Protection](sa-protection.md)**: Webhook that prevents unauthorized use of operator ServiceAccounts.
- **[Impersonation Guard](impersonation-guard.md)**: Close impersonation bypass vectors on operator ServiceAccounts.

## Configuration and Operations

- **[Configuration](configuration.md)**: Configuration reference for the scoping controller and all components.
- **[Migration](migration.md)**: Step-by-step migration from operator-security-runtime v1.
- **[Troubleshooting](troubleshooting.md)**: Common issues and their solutions.
