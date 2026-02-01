# sshmgr

Multi-tenant SSH certificate management system for managing, expiring, revoking, and rotating SSH keys.

## Features

- **Certificate Authority Management**: Generate and manage user/host CAs per environment
- **Certificate Signing**: Issue short-lived SSH certificates for users and hosts
- **Key Rotation**: Rotate CA keys with configurable grace periods
- **Multi-tenancy**: Isolate customer environments with separate CAs
- **RBAC**: Role-based access control via Keycloak integration
- **Dual Interface**: Both CLI and REST API access
- **Monitoring**: Prometheus metrics and structured JSON logging

## Quick Start

### Prerequisites

- Python 3.11+
- OpenSSH (`ssh-keygen` in PATH)
- Docker & Docker Compose (for development infrastructure)

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

# Start PostgreSQL and Keycloak
make docker-up

# Generate master encryption key and create .env
make generate-key
# Copy the output to .env file (see Configuration below)

# Run database migrations
make db-migrate

# Verify installation
make test
```

### Configuration

Create a `.env` file in the project root:

```bash
SSHMGR_MASTER_KEY=<output-from-make-generate-key>
SSHMGR_DATABASE_URL=postgresql+asyncpg://sshmgr:sshmgr_dev_password@localhost:5432/sshmgr
SSHMGR_KEYCLOAK_URL=http://localhost:8080
SSHMGR_KEYCLOAK_REALM=sshmgr
```

See [Configuration Reference](docs/configuration.md) for all options.

## Usage

### CLI

```bash
# Login (browser-based authentication)
sshmgr login

# Initialize an environment
sshmgr env init production --user-validity 8h --host-validity 90d

# Sign a user certificate
sshmgr cert sign-user \
    -e production \
    -k ~/.ssh/id_ed25519.pub \
    -n admin,deploy \
    -I user@example.com

# Sign a host certificate
sshmgr cert sign-host \
    -e production \
    -k /etc/ssh/ssh_host_ed25519_key.pub \
    -n server.example.com,10.0.0.5

# List certificates
sshmgr cert list -e production

# Rotate CA
sshmgr rotate ca -e production --type user --grace-period 24h
```

### REST API

```bash
# Health check
curl http://localhost:8000/api/v1/health

# List environments (requires JWT)
curl -H "Authorization: Bearer $TOKEN" \
    http://localhost:8000/api/v1/environments

# Sign user certificate
curl -X POST \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"public_key": "ssh-ed25519 AAAA...", "principals": ["admin"], "key_id": "user@example.com"}' \
    http://localhost:8000/api/v1/environments/production/certs/user
```

API documentation available at `/api/docs` (Swagger UI) and `/api/redoc`.

## Development

```bash
# Run tests
make test           # Unit tests only
make test-integ     # Integration tests only
make test-all       # All tests
make test-cov       # With coverage report

# Code quality
make lint           # Run linter
make format         # Format code
make typecheck      # Type checking
make check          # All of the above

# Start API server (development)
make run-api
```

## Production Deployment

```bash
# Build Docker image
make docker-build

# Start production stack (requires .env with SSHMGR_MASTER_KEY)
make docker-prod

# View logs
make docker-prod-logs
```

See [Installation Guide](docs/installation.md) for detailed production setup.

## Documentation

| Document | Description |
|----------|-------------|
| [Architecture](docs/architecture.md) | System design and components |
| [Installation](docs/installation.md) | Setup guide |
| [Configuration](docs/configuration.md) | Environment variables |
| [CLI Reference](docs/cli-reference.md) | Command documentation |
| [API Reference](docs/api-reference.md) | REST API endpoints |
| [Testing](docs/testing.md) | Test suite guide |
| [Security](docs/security.md) | Security model |

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  CLI (sshmgr)              │  REST API (FastAPI)                │
│  - login                   │  /api/v1/environments              │
│  - env init/list/show      │  /api/v1/environments/{id}/certs   │
│  - cert sign-user/host     │  /api/v1/health, /ready, /metrics  │
│  - rotate ca               │                                    │
├─────────────────────────────────────────────────────────────────┤
│                   Authentication (Keycloak OIDC)                │
│  Device Authorization Flow │ JWT Validation │ RBAC              │
├─────────────────────────────────────────────────────────────────┤
│                      Core Library                               │
│  CertificateAuthority │ EnvironmentManager │ PolicyEngine       │
├─────────────────────────────────────────────────────────────────┤
│                      Storage Layer                              │
│  PostgreSQL + SQLAlchemy │ Fernet Encryption for CA Keys        │
└─────────────────────────────────────────────────────────────────┘
```

## License

MIT

Keycloak Setup Automation Complete                                                                                            
                                                                                                                                
  New Files                                                                                                                     
                                                                                                                                
  scripts/keycloak_setup.py - Automated Keycloak configuration script                                                           
                                                                                                                                
  Features                                                                                                                      
  ┌─────────────────┬───────────────────────────────────────────────────────────────────────────────────────┐                   
  │     Feature     │                                      Description                                      │                   
  ├─────────────────┼───────────────────────────────────────────────────────────────────────────────────────┤                   
  │ Realm creation  │ Creates sshmgr realm with security settings (brute force protection, token lifespans) │                   
  ├─────────────────┼───────────────────────────────────────────────────────────────────────────────────────┤                   
  │ Role creation   │ Creates admin, operator, viewer roles with descriptions                               │                   
  ├─────────────────┼───────────────────────────────────────────────────────────────────────────────────────┤                   
  │ API client      │ sshmgr-api - confidential client for JWT validation, auto-generates secret            │                   
  ├─────────────────┼───────────────────────────────────────────────────────────────────────────────────────┤                   
  │ CLI client      │ sshmgr-cli - public client with device authorization flow enabled                     │                   
  ├─────────────────┼───────────────────────────────────────────────────────────────────────────────────────┤                   
  │ Group structure │ Creates /environments parent group with child groups (dev, staging, prod)             │                   
  ├─────────────────┼───────────────────────────────────────────────────────────────────────────────────────┤                   
  │ Test user       │ Optional testadmin/testadmin user with admin role and all env access                  │                   
  ├─────────────────┼───────────────────────────────────────────────────────────────────────────────────────┤                   
  │ Health check    │ Waits for Keycloak to be ready before setup                                           │                   
  ├─────────────────┼───────────────────────────────────────────────────────────────────────────────────────┤                   
  │ Secret output   │ Can append configuration to .env file                                                 │                   
  └─────────────────┴───────────────────────────────────────────────────────────────────────────────────────┘                   
  Usage                                                                                                                         
                                                                                                                                
  # After starting Keycloak                                                                                                     
  make docker-up                                                                                                                
  make keycloak-setup          # Dev setup with test user                                                                       
                                                                                                                                
  # Or manually with options                                                                                                    
  python scripts/keycloak_setup.py --help                                                                                       
  python scripts/keycloak_setup.py --create-test-user --create-environments prod staging                                        
  python scripts/keycloak_setup.py --no-wait --output-env .env                                                                  
                                                                                                                                
  Environment Variables                                                                                                         
  ┌─────────────────────────┬───────────────────────┬─────────────────────┐                                                     
  │        Variable         │        Default        │     Description     │                                                     
  ├─────────────────────────┼───────────────────────┼─────────────────────┤                                                     
  │ KEYCLOAK_URL            │ http://localhost:8080 │ Keycloak server URL │                                                     
  ├─────────────────────────┼───────────────────────┼─────────────────────┤                                                     
  │ KEYCLOAK_ADMIN          │ admin                 │ Admin username      │                                                     
  ├─────────────────────────┼───────────────────────┼─────────────────────┤                                                     
  │ KEYCLOAK_ADMIN_PASSWORD │ admin                 │ Admin password      │                                                     
  ├─────────────────────────┼───────────────────────┼─────────────────────┤                                                     
  │ SSHMGR_KEYCLOAK_REALM   │ sshmgr                │ Realm name          │                                                     
  └─────────────────────────┴───────────────────────┴─────────────────────┘                                                     
  Makefile Targets                                                                                                              
                                                                                                                                
  make keycloak-setup        # Dev setup with test user                                                                         
  make keycloak-setup-prod   # Production setup (outputs to .env)                                                               
                                                                                                                                
  Output Example                                                                                                                
                                                                                                                                
  ============================================================                                                                  
  sshmgr Keycloak Setup                                                                                                         
  ============================================================                                                                  
  Keycloak URL: http://localhost:8080                                                                                           
  Realm: sshmgr                                                                                                                 
                                                                                                                                
  Waiting for Keycloak at http://localhost:8080...                                                                              
  Keycloak is ready!                                                                                                            
                                                                                                                                
  Creating realm...                                                                                                             
  Created realm 'sshmgr'                                                                                                        
                                                                                                                                
  Creating roles...                                                                                                             
    Created role 'admin'                                                                                                        
    Created role 'operator'                                                                                                     
    Created role 'viewer'                                                                                                       
                                                                                                                                
  Creating clients...                                                                                                           
    Created client 'sshmgr-api'                                                                                                 
    Created client 'sshmgr-cli'                                                                                                 
                                                                                                                                
  Creating groups...                                                                                                            
    Created group 'environments'                                                                                                
    Created group 'dev'                                                                                                         
    Created group 'staging'                                                                                                     
    Created group 'prod'                                                                                                        
                                                                                                                                
  ============================================================                                                                  
  Setup Complete!                                                                                                               
  ============================================================                                                                  
                                                                                                                                
  API Client Secret:                                                                                                            
    abc123...                                                                                                                   
                                                                                                                                
  Add to your .env file:                                                                                                        
    SSHMGR_KEYCLOAK_CLIENT_SECRET=abc123...   