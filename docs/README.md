# sshmgr Documentation

SSH Certificate Management System - comprehensive documentation for design, installation, and usage.

## Documentation Index

| Document | Description |
|----------|-------------|
| [Architecture](architecture.md) | System design, components, and data flow |
| [Installation](installation.md) | Setup guide for development and production |
| [Configuration](configuration.md) | Environment variables and settings |
| [CLI Reference](cli-reference.md) | Command-line interface documentation |
| [API Reference](api-reference.md) | REST API endpoints and examples |
| [Testing](testing.md) | Test suite and testing guide |
| [Security](security.md) | Security model and best practices |

## Quick Links

- **Getting Started**: See [Installation](installation.md)
- **CLI Usage**: See [CLI Reference](cli-reference.md)
- **API Integration**: See [API Reference](api-reference.md)
- **Contributing**: See [Testing](testing.md)

## Overview

sshmgr is a multi-tenant SSH certificate management system that provides:

- **Certificate Authority Management**: Generate and manage user/host CAs per environment
- **Certificate Signing**: Issue short-lived SSH certificates for users and hosts
- **Key Rotation**: Rotate CA keys with configurable grace periods
- **Multi-tenancy**: Isolate customer environments with separate CAs
- **RBAC**: Role-based access control via Keycloak integration
- **Dual Interface**: Both CLI and REST API access

## Key Concepts

### Environments
An environment represents an isolated tenant (e.g., a customer or deployment stage). Each environment has:
- Separate User CA and Host CA keypairs
- Configurable default certificate validity periods
- Independent certificate serial numbering
- Access controlled via Keycloak groups

### Certificates
SSH certificates are signed by the environment's CA and include:
- **User certificates**: Allow users to authenticate to SSH servers
- **Host certificates**: Allow clients to verify server identity
- Configurable validity periods (default: 8h for users, 90d for hosts)
- Principal restrictions (usernames for users, hostnames for hosts)

### CA Rotation
CA keys can be rotated with a grace period:
1. New CA keypair is generated
2. Old CA remains valid during grace period
3. Both CAs should be trusted during transition
4. Old CA is automatically cleaned up after expiration
