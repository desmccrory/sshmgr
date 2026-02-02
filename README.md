# sshmgr

Multi-tenant SSH certificate management system using OpenSSH certificates.

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Overview

sshmgr provides centralized SSH certificate management with:

- **Multi-tenant environments** - Isolated Certificate Authorities per environment
- **Short-lived certificates** - Default 8-hour user certs, 90-day host certs
- **RBAC via Keycloak** - Role-based access control with OAuth 2.0
- **CLI and REST API** - Flexible interfaces for automation and interactive use
- **Audit logging** - Track all certificate operations
- **CA rotation** - Rotate CAs with configurable grace periods

## Features

- Sign user and host SSH certificates using OpenSSH's `ssh-keygen`
- Encrypted CA private key storage (Fernet encryption)
- Certificate revocation tracking
- Prometheus metrics endpoint
- JSON structured logging

## Quick Start

### Prerequisites

- Python 3.11+
- PostgreSQL 14+
- Keycloak 22+ (for authentication)
- OpenSSH (`ssh-keygen` in PATH)

### Installation

```bash
# Clone the repository
git clone https://github.com/yourorg/sshmgr.git
cd sshmgr

# Create virtual environment
python -m venv .venv
source .venv/bin/activate

# Install in development mode
make install-dev

# Start infrastructure (PostgreSQL + Keycloak)
make docker-up

# Wait for services, then set up Keycloak
make keycloak-setup

# Generate master encryption key
make generate-key
# Add the output to your .env file

# Run database migrations
make db-migrate

# Start the API server
make run-api
```

### Basic Usage

```bash
# Login (opens browser for Keycloak authentication)
sshmgr login

# Create an environment
sshmgr env init prod

# Sign a user certificate
sshmgr cert sign-user \
    -e prod \
    -k ~/.ssh/id_ed25519.pub \
    -n "deploy,admin" \
    -I "user@example.com" \
    -V 8h

# List certificates
sshmgr cert list -e prod

# Get CA public key (for server configuration)
sshmgr env get-ca prod --type user
```

## Architecture

```
src/sshmgr/
├── core/           # Certificate Authority (wraps ssh-keygen)
├── keys/           # Encrypted key storage
├── auth/           # Keycloak OIDC authentication
├── storage/        # PostgreSQL with SQLAlchemy 2.0 async
├── cli/            # Click-based CLI
└── api/            # FastAPI REST API
```

### Key Design Decisions

1. **OpenSSH for crypto** - All certificate operations use `ssh-keygen`, avoiding custom crypto
2. **Fernet encryption** - CA private keys encrypted at rest
3. **Multi-tenant** - Each environment has isolated user/host CAs
4. **Async everywhere** - SQLAlchemy 2.0 async, FastAPI async handlers

## Development

### Setup

```bash
# Install dev dependencies
make install-dev

# Run all checks (lint, typecheck, tests)
make check
```

### Testing

```bash
# Run unit tests
make test

# Run with coverage
make test-cov

# Run integration tests (requires PostgreSQL)
make test-integ

# Run all tests
make test-all
```

Tests use real `ssh-keygen` calls - no mocking of cryptographic operations.

### Code Quality

```bash
# Lint with ruff
make lint

# Format code
make format

# Type check with mypy
make typecheck
```

## Configuration

Configuration via environment variables (prefix: `SSHMGR_`):

| Variable | Required | Description |
|----------|----------|-------------|
| `SSHMGR_MASTER_KEY` | Yes | Fernet encryption key (44 chars) |
| `SSHMGR_DATABASE_URL` | Yes | PostgreSQL async connection URL |
| `SSHMGR_KEYCLOAK_URL` | No | Keycloak server URL |
| `SSHMGR_KEYCLOAK_REALM` | No | Keycloak realm (default: sshmgr) |

Generate a master key:
```bash
make generate-key
```

See [docs/configuration.md](docs/configuration.md) for complete reference.

## API

REST API available at `http://localhost:8000/api/v1/`:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/environments` | GET | List environments |
| `/environments` | POST | Create environment |
| `/environments/{name}/certs/user` | POST | Sign user certificate |
| `/environments/{name}/certs/host` | POST | Sign host certificate |

Interactive docs at `/api/docs` (Swagger UI) or `/api/redoc`.

See [docs/api-reference.md](docs/api-reference.md) for complete reference.

## CLI Reference

```bash
# Authentication
sshmgr login              # Browser-based OAuth login
sshmgr logout             # Clear credentials
sshmgr auth status        # Show login status
sshmgr auth whoami        # Show current user info

# Environments
sshmgr env init <name>    # Create environment with new CAs
sshmgr env list           # List all environments
sshmgr env show <name>    # Show environment details
sshmgr env get-ca <name>  # Get CA public key

# Certificates
sshmgr cert sign-user     # Sign user certificate
sshmgr cert sign-host     # Sign host certificate
sshmgr cert list -e ENV   # List certificates
sshmgr cert revoke        # Revoke certificate

# CA Rotation
sshmgr rotate ca          # Rotate CA with grace period
sshmgr rotate status      # Show rotation status
```

See [docs/cli-reference.md](docs/cli-reference.md) for complete reference.

## Documentation

- [Architecture](docs/architecture.md) - System design and components
- [Installation](docs/installation.md) - Detailed setup instructions
- [Configuration](docs/configuration.md) - Environment variables reference
- [CLI Reference](docs/cli-reference.md) - Complete CLI documentation
- [API Reference](docs/api-reference.md) - REST API documentation
- [Security](docs/security.md) - Security considerations
- [Testing](docs/testing.md) - Test suite documentation

## Docker

```bash
# Build image
make docker-build

# Start development infrastructure
make docker-up

# Start production stack
make docker-prod

# View logs
make docker-prod-logs
```

## Project Structure

```
sshmgr/
├── src/sshmgr/          # Main package
│   ├── api/             # FastAPI application
│   ├── auth/            # Authentication (Keycloak)
│   ├── cli/             # CLI commands
│   ├── core/            # CA and exceptions
│   ├── keys/            # Key storage
│   └── storage/         # Database models and repos
├── tests/
│   ├── unit/            # Unit tests
│   └── integration/     # Integration tests
├── docs/                # Documentation
├── scripts/             # Utility scripts
├── docker-compose.yml   # Dev infrastructure
├── Dockerfile           # Production image
└── Makefile             # Development commands
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Run checks (`make check`)
4. Commit changes (`git commit -m 'Add amazing feature'`)
5. Push to branch (`git push origin feature/amazing-feature`)
6. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
