# k8s-secret-rotator

A Python script for safely rotating Kubernetes secrets with zero-downtime workload restarts and automatic rollback on failures.

## Overview

This tool automatically discovers all Deployments and StatefulSets that reference a specific secret, updates the secret value, and performs rolling restarts with verification to ensure the new secret is properly propagated to all running pods.

## Features

- **Workload Discovery**: Automatically finds Deployments/StatefulSets that reference the target secret via environment variables, envFrom, or volume mounts
- **Zero-Downtime Updates**: Uses rolling update strategy with configurable maxSurge/maxUnavailable settings
- **Post-Rollout Verification**: Verifies that new secret values have propagated to running pods using hash comparison
- **Automatic Rollback**: Rolls back workloads on failure with clear error reporting
- **Retry Logic**: Implements exponential backoff for rollout operations
- **Flexible Input**: Accepts configuration via environment variables or interactive STDIN

## Parameters

| Parameter | Description | Required | Default |
|-----------|-------------|----------|---------|
| `SECRET_NAME` | Name of the Kubernetes secret to update | Yes | - |
| `NAMESPACE` | Kubernetes namespace | Yes | `default` |
| `NEW_SECRET_VALUE` | New secret value to set | Yes | - |
| `NEW_SECRET_KEY` | Secret key to update within the secret | Yes | - |

## How It Works

1. **Discovery Phase**: Scans all Deployments and StatefulSets in the specified namespace to find workloads that reference the target secret
2. **Secret Update**: Updates the secret with the new value using base64 encoding
3. **Rolling Update**: For each affected workload:
   - Configures rolling update strategy (40% maxSurge, 0% maxUnavailable)
   - Triggers rollout restart
   - Waits for successful completion with timeout and retries
4. **Verification**: Verifies that the new secret value has propagated to running pods
5. **Rollback**: Automatically rolls back on any failure

## Error Handling

Currently it is not in good condition, working on it

## Limitations

- Only supports Deployments and StatefulSets (can be extended for other workload types)
- Verification checks a sample pod rather than all pods (for performance in large clusters)
- Requires kubectl CLI tool

## Security Considerations

- Test in non-production environments, it's not production ready
- Ensure the script runs with minimal required permissions
- Consider using Kubernetes service accounts with RBAC

## License

MIT License - feel free to use and modify for your needs.