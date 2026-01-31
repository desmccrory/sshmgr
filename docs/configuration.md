# Configuration Reference

sshmgr is configured via environment variables, with an optional `.env` file for local development.

## Environment Variables

All environment variables are prefixed with `SSHMGR_`.

### Required Settings

| Variable | Description | Example |
|----------|-------------|---------|
| `SSHMGR_MASTER_KEY` | Fernet encryption key for CA private keys (44 chars) | `dGVzdC1tYXN0ZXIta2V5Li4u...` |
| `SSHMGR_DATABASE_URL` | PostgreSQL connection URL (async) | `postgresql+asyncpg://user:pass@host:5432/db` |

### Keycloak Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `SSHMGR_KEYCLOAK_URL` | `http://localhost:8080` | Keycloak server URL |
| `SSHMGR_KEYCLOAK_REALM` | `sshmgr` | Keycloak realm name |
| `SSHMGR_KEYCLOAK_CLIENT_ID` | `sshmgr-api` | Client ID for API |
| `SSHMGR_KEYCLOAK_CLIENT_SECRET` | (empty) | Client secret (confidential client) |

### API Server Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `SSHMGR_API_HOST` | `0.0.0.0` | API server bind address |
| `SSHMGR_API_PORT` | `8000` | API server port |
| `SSHMGR_API_DEBUG` | `false` | Enable debug mode (auto-reload) |

### Certificate Defaults

| Variable | Default | Description |
|----------|---------|-------------|
| `SSHMGR_DEFAULT_USER_CERT_VALIDITY_HOURS` | `8` | Default user cert validity in hours |
| `SSHMGR_DEFAULT_HOST_CERT_VALIDITY_DAYS` | `90` | Default host cert validity in days |

### Database Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `SSHMGR_DATABASE_URL` | `postgresql+asyncpg://...` | PostgreSQL connection URL |
| `SSHMGR_DATABASE_ECHO` | `false` | Log SQL statements |

### Logging Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `SSHMGR_LOG_LEVEL` | `INFO` | Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL) |
| `SSHMGR_LOG_FORMAT` | `text` | Log format (`text` or `json`) |

## Configuration File (.env)

For local development, create a `.env` file in the project root:

```bash
# .env - Development configuration
SSHMGR_MASTER_KEY=dGVzdC1tYXN0ZXIta2V5LWZvci10ZXN0aW5nLW9ubHk=
SSHMGR_DATABASE_URL=postgresql+asyncpg://sshmgr:sshmgr_dev_password@localhost:5432/sshmgr
SSHMGR_KEYCLOAK_URL=http://localhost:8080
SSHMGR_KEYCLOAK_REALM=sshmgr
SSHMGR_LOG_LEVEL=DEBUG
SSHMGR_DATABASE_ECHO=true
```

The `.env` file is automatically loaded by pydantic-settings.

## Generating the Master Key

The master key must be a valid Fernet key (44 characters, base64 URL-safe encoded):

```bash
# Using make
make generate-key

# Using Python
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

# Example output:
# ZmVybmV0LWtleS1leGFtcGxlLTMyLWJ5dGVz...
```

**Important**:
- Store the master key securely
- Use a secrets manager in production
- Rotating the master key requires re-encrypting all CA private keys

## CLI Configuration

The CLI stores credentials in `~/.sshmgr/credentials.json`:

```json
{
  "access_token": "eyJ...",
  "refresh_token": "eyJ...",
  "token_type": "Bearer",
  "expires_at": 1704067200.0,
  "keycloak_url": "http://localhost:8080",
  "realm": "sshmgr"
}
```

This file is created automatically by `sshmgr login`.

### CLI Environment Variables

The CLI also respects these environment variables:

| Variable | Description |
|----------|-------------|
| `SSHMGR_ENVIRONMENT` | Default environment for commands (`-e` option) |

Example:
```bash
export SSHMGR_ENVIRONMENT=prod
sshmgr cert sign-user -k key.pub -n admin -I user@example.com
# Equivalent to: sshmgr cert sign-user -e prod ...
```

## Keycloak Configuration

### Required Realm Setup

1. **Realm**: `sshmgr` (or custom via `SSHMGR_KEYCLOAK_REALM`)

2. **Clients**:
   - `sshmgr-api`: Confidential client for API
   - `sshmgr-cli`: Public client with Device Flow enabled

3. **Realm Roles**:
   - `admin`: Full access
   - `operator`: Issue and revoke certificates
   - `viewer`: Read-only access

4. **Groups** (for environment access):
   - `/environments/{env-name}`: Users in this group can access the environment

### Client Configuration

**API Client (sshmgr-api)**:
```
Client ID: sshmgr-api
Client authentication: ON
Authorization: OFF
Valid redirect URIs: (not needed for API)
```

**CLI Client (sshmgr-cli)**:
```
Client ID: sshmgr-cli
Client authentication: OFF
OAuth 2.0 Device Authorization Grant: ENABLED
Device Authorization Grant Enabled: ON
```

## Database Configuration

### Connection URL Format

```
postgresql+asyncpg://username:password@hostname:port/database
```

Examples:
```bash
# Local development
SSHMGR_DATABASE_URL=postgresql+asyncpg://sshmgr:password@localhost:5432/sshmgr

# With SSL
SSHMGR_DATABASE_URL=postgresql+asyncpg://user:pass@host:5432/db?ssl=require

# AWS RDS
SSHMGR_DATABASE_URL=postgresql+asyncpg://user:pass@mydb.xxxxx.us-east-1.rds.amazonaws.com:5432/sshmgr
```

### Connection Pool Settings

Default pool settings (in `database.py`):
- `pool_size`: 5
- `max_overflow`: 10
- `pool_pre_ping`: True

## Production Configuration Example

```bash
# /etc/sshmgr/sshmgr.env

# Encryption (load from secrets manager in practice)
SSHMGR_MASTER_KEY=<production-fernet-key>

# Database
SSHMGR_DATABASE_URL=postgresql+asyncpg://sshmgr:${DB_PASSWORD}@db.internal:5432/sshmgr

# Keycloak
SSHMGR_KEYCLOAK_URL=https://keycloak.example.com
SSHMGR_KEYCLOAK_REALM=sshmgr
SSHMGR_KEYCLOAK_CLIENT_ID=sshmgr-api
SSHMGR_KEYCLOAK_CLIENT_SECRET=<client-secret>

# API
SSHMGR_API_HOST=127.0.0.1
SSHMGR_API_PORT=8000

# Logging
SSHMGR_LOG_LEVEL=INFO
SSHMGR_LOG_FORMAT=json

# Certificate defaults
SSHMGR_DEFAULT_USER_CERT_VALIDITY_HOURS=8
SSHMGR_DEFAULT_HOST_CERT_VALIDITY_DAYS=90
```

## Configuration Validation

The application validates configuration on startup:

```python
from sshmgr.config import get_settings

settings = get_settings()
# Raises ValidationError if required settings are missing or invalid
```

Common validation errors:
- `master_key must be a valid Fernet key (44 characters)`
- `database_url must start with postgresql+asyncpg://`
