# API Reference

REST API documentation for sshmgr.

## Overview

- **Base URL**: `/api/v1`
- **Authentication**: Bearer token (JWT from Keycloak)
- **Content-Type**: `application/json`
- **Documentation**: Swagger UI at `/api/docs`, ReDoc at `/api/redoc`

## Authentication

All endpoints except health checks require a valid JWT token:

```bash
curl -H "Authorization: Bearer <access_token>" \
     https://sshmgr.example.com/api/v1/environments
```

### Obtaining a Token

For API clients, use Keycloak's token endpoint:

```bash
# Client credentials grant (service account)
curl -X POST https://keycloak.example.com/realms/sshmgr/protocol/openid-connect/token \
     -d "grant_type=client_credentials" \
     -d "client_id=sshmgr-api" \
     -d "client_secret=<client-secret>"

# Response:
{
  "access_token": "eyJ...",
  "expires_in": 300,
  "token_type": "Bearer"
}
```

## Health Endpoints

### GET /api/v1/health

Basic health check.

**Response** `200 OK`:
```json
{
  "status": "healthy",
  "version": "0.1.0",
  "timestamp": "2024-01-21T10:30:00Z"
}
```

### GET /api/v1/ready

Readiness check (verifies database connectivity).

**Response** `200 OK`:
```json
{
  "status": "healthy",
  "database": "healthy",
  "keycloak": "configured"
}
```

**Response** `503 Service Unavailable`:
```json
{
  "status": "unhealthy",
  "database": "unavailable",
  "keycloak": "configured"
}
```

### GET /api/v1/version

Version information.

**Response** `200 OK`:
```json
{
  "version": "0.1.0",
  "api_version": "v1"
}
```

## Environment Endpoints

### GET /api/v1/environments

List all environments accessible to the user.

**Response** `200 OK`:
```json
{
  "environments": [
    {
      "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      "name": "prod",
      "user_ca_fingerprint": "SHA256:xxxx...",
      "host_ca_fingerprint": "SHA256:yyyy...",
      "default_user_cert_validity": "8h",
      "default_host_cert_validity": "90d",
      "created_at": "2024-01-15T10:30:00Z",
      "updated_at": null,
      "has_old_user_ca": false,
      "has_old_host_ca": false
    }
  ],
  "total": 1
}
```

### POST /api/v1/environments

Create a new environment. **Requires admin role.**

**Request**:
```json
{
  "name": "customer-prod",
  "key_type": "ed25519",
  "default_user_cert_validity": "8h",
  "default_host_cert_validity": "90d"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Environment name (lowercase, alphanumeric, hyphens) |
| `key_type` | string | No | Key type: `ed25519`, `rsa`, `ecdsa` (default: `ed25519`) |
| `default_user_cert_validity` | string | No | Default validity (default: `8h`) |
| `default_host_cert_validity` | string | No | Default validity (default: `90d`) |

**Response** `201 Created`:
```json
{
  "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "name": "customer-prod",
  "user_ca_fingerprint": "SHA256:xxxx...",
  "host_ca_fingerprint": "SHA256:yyyy...",
  "default_user_cert_validity": "8h",
  "default_host_cert_validity": "90d",
  "created_at": "2024-01-21T10:30:00Z",
  "updated_at": null,
  "has_old_user_ca": false,
  "has_old_host_ca": false
}
```

**Response** `409 Conflict`:
```json
{
  "detail": "Environment 'customer-prod' already exists"
}
```

### GET /api/v1/environments/{env_name}

Get environment details.

**Response** `200 OK`:
```json
{
  "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "name": "prod",
  "user_ca_fingerprint": "SHA256:xxxx...",
  "host_ca_fingerprint": "SHA256:yyyy...",
  "default_user_cert_validity": "8h",
  "default_host_cert_validity": "90d",
  "created_at": "2024-01-15T10:30:00Z",
  "updated_at": null,
  "has_old_user_ca": false,
  "has_old_host_ca": false
}
```

**Response** `404 Not Found`:
```json
{
  "detail": "Environment 'prod' not found"
}
```

### DELETE /api/v1/environments/{env_name}

Delete an environment. **Requires admin role.**

**Response** `204 No Content`

### GET /api/v1/environments/{env_name}/ca/{ca_type}

Get CA public key.

**Path Parameters**:
- `env_name`: Environment name
- `ca_type`: `user` or `host`

**Query Parameters**:
- `include_old`: Include old CA if rotation in progress (default: `false`)

**Response** `200 OK`:
```json
{
  "environment": "prod",
  "ca_type": "user",
  "public_key": "ssh-ed25519 AAAA... sshmgr-ca",
  "fingerprint": "SHA256:xxxx...",
  "old_public_key": null,
  "old_fingerprint": null,
  "old_expires_at": null
}
```

### POST /api/v1/environments/{env_name}/rotate

Rotate a CA key. **Requires admin role.**

**Request**:
```json
{
  "ca_type": "user",
  "grace_period": "7d",
  "key_type": "ed25519"
}
```

**Response** `200 OK`:
```json
{
  "environment": "prod",
  "user_ca": {
    "rotating": true,
    "fingerprint": "SHA256:yyyy...",
    "old_fingerprint": "SHA256:xxxx...",
    "old_expires_at": "2024-01-28T10:30:00Z"
  },
  "host_ca": {
    "rotating": false,
    "fingerprint": "SHA256:zzzz...",
    "old_fingerprint": null,
    "old_expires_at": null
  }
}
```

### GET /api/v1/environments/{env_name}/rotation-status

Get CA rotation status.

**Response** `200 OK`:
```json
{
  "environment": "prod",
  "user_ca": {
    "rotating": true,
    "fingerprint": "SHA256:yyyy...",
    "old_fingerprint": "SHA256:xxxx...",
    "old_expires_at": "2024-01-28T10:30:00Z"
  },
  "host_ca": {
    "rotating": false,
    "fingerprint": "SHA256:zzzz...",
    "old_fingerprint": null,
    "old_expires_at": null
  }
}
```

## Certificate Endpoints

### GET /api/v1/environments/{env_name}/certs

List certificates for an environment.

**Query Parameters**:
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `cert_type` | string | - | Filter by type: `user`, `host` |
| `include_expired` | boolean | `false` | Include expired certificates |
| `include_revoked` | boolean | `true` | Include revoked certificates |
| `limit` | integer | `100` | Max results (1-500) |
| `offset` | integer | `0` | Pagination offset |

**Response** `200 OK`:
```json
{
  "certificates": [
    {
      "id": "b2c3d4e5-f6a7-8901-bcde-f23456789012",
      "serial": 42,
      "cert_type": "user",
      "key_id": "alice@example.com",
      "principals": ["deploy", "admin"],
      "valid_after": "2024-01-21T10:25:00Z",
      "valid_before": "2024-01-21T18:30:00Z",
      "public_key_fingerprint": "SHA256:aaaa...",
      "issued_at": "2024-01-21T10:30:00Z",
      "issued_by": "alice",
      "revoked_at": null,
      "revoked_by": null,
      "revocation_reason": null
    }
  ],
  "total": 42
}
```

### POST /api/v1/environments/{env_name}/certs/user

Sign a user certificate. **Requires operator role.**

**Request**:
```json
{
  "public_key": "ssh-ed25519 AAAA... user@host",
  "principals": ["deploy", "admin"],
  "key_id": "alice@example.com",
  "validity": "8h",
  "force_command": null
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `public_key` | string | Yes | SSH public key (OpenSSH format) |
| `principals` | array | Yes | List of usernames |
| `key_id` | string | Yes | Key identifier (e.g., email) |
| `validity` | string | No | Validity period (default: env setting) |
| `force_command` | string | No | Force specific command |

**Response** `201 Created`:
```json
{
  "id": "b2c3d4e5-f6a7-8901-bcde-f23456789012",
  "serial": 42,
  "cert_type": "user",
  "key_id": "alice@example.com",
  "principals": ["deploy", "admin"],
  "valid_after": "2024-01-21T10:25:00Z",
  "valid_before": "2024-01-21T18:30:00Z",
  "public_key_fingerprint": "SHA256:aaaa...",
  "certificate": "ssh-ed25519-cert-v01@openssh.com AAAA...",
  "issued_at": "2024-01-21T10:30:00Z",
  "issued_by": "alice",
  "revoked_at": null,
  "revoked_by": null,
  "revocation_reason": null
}
```

**Response** `400 Bad Request`:
```json
{
  "detail": "Invalid public key: must start with ssh-ed25519, ssh-rsa, or ecdsa-sha2-"
}
```

### POST /api/v1/environments/{env_name}/certs/host

Sign a host certificate. **Requires operator role.**

**Request**:
```json
{
  "public_key": "ssh-ed25519 AAAA... root@server",
  "principals": ["server1.example.com", "10.0.0.5"],
  "validity": "90d"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `public_key` | string | Yes | SSH public key (OpenSSH format) |
| `principals` | array | Yes | List of hostnames/IPs |
| `validity` | string | No | Validity period (default: env setting) |

**Response** `201 Created`:
```json
{
  "id": "c3d4e5f6-a7b8-9012-cdef-345678901234",
  "serial": 43,
  "cert_type": "host",
  "key_id": "server1.example.com",
  "principals": ["server1.example.com", "10.0.0.5"],
  "valid_after": "2024-01-21T10:25:00Z",
  "valid_before": "2024-04-20T10:30:00Z",
  "public_key_fingerprint": "SHA256:bbbb...",
  "certificate": "ssh-ed25519-cert-v01@openssh.com AAAA...",
  "issued_at": "2024-01-21T10:30:00Z",
  "issued_by": "alice",
  "revoked_at": null,
  "revoked_by": null,
  "revocation_reason": null
}
```

### GET /api/v1/environments/{env_name}/certs/{serial}

Get certificate details by serial number.

**Response** `200 OK`:
```json
{
  "id": "b2c3d4e5-f6a7-8901-bcde-f23456789012",
  "serial": 42,
  "cert_type": "user",
  "key_id": "alice@example.com",
  "principals": ["deploy", "admin"],
  "valid_after": "2024-01-21T10:25:00Z",
  "valid_before": "2024-01-21T18:30:00Z",
  "public_key_fingerprint": "SHA256:aaaa...",
  "certificate": null,
  "issued_at": "2024-01-21T10:30:00Z",
  "issued_by": "alice",
  "revoked_at": null,
  "revoked_by": null,
  "revocation_reason": null
}
```

### DELETE /api/v1/environments/{env_name}/certs/{serial}

Revoke a certificate. **Requires operator role.**

**Request** (optional):
```json
{
  "reason": "User terminated"
}
```

**Response** `200 OK`:
```json
{
  "id": "b2c3d4e5-f6a7-8901-bcde-f23456789012",
  "serial": 42,
  "cert_type": "user",
  "key_id": "alice@example.com",
  "principals": ["deploy", "admin"],
  "valid_after": "2024-01-21T10:25:00Z",
  "valid_before": "2024-01-21T18:30:00Z",
  "public_key_fingerprint": "SHA256:aaaa...",
  "certificate": null,
  "issued_at": "2024-01-21T10:30:00Z",
  "issued_by": "alice",
  "revoked_at": "2024-01-21T12:00:00Z",
  "revoked_by": "bob",
  "revocation_reason": "User terminated"
}
```

**Response** `409 Conflict`:
```json
{
  "detail": "Certificate 42 is already revoked"
}
```

### GET /api/v1/environments/{env_name}/certs/by-key-id/{key_id}

Find certificates by key ID.

**Response** `200 OK`:
```json
{
  "certificates": [
    {
      "id": "b2c3d4e5-f6a7-8901-bcde-f23456789012",
      "serial": 42,
      "cert_type": "user",
      "key_id": "alice@example.com",
      ...
    }
  ],
  "total": 1
}
```

## Error Responses

### 400 Bad Request

Invalid request data:
```json
{
  "detail": "Invalid validity format: abc. Use format like '8h', '90d', '1w'"
}
```

### 401 Unauthorized

Missing or invalid token:
```json
{
  "detail": "Missing authorization header"
}
```

### 403 Forbidden

Insufficient permissions:
```json
{
  "detail": "Requires admin role or higher"
}
```

Or no access to environment:
```json
{
  "detail": "No access to environment: prod"
}
```

### 404 Not Found

Resource not found:
```json
{
  "detail": "Environment 'prod' not found"
}
```

### 409 Conflict

Resource already exists:
```json
{
  "detail": "Environment 'prod' already exists"
}
```

### 422 Unprocessable Entity

Validation error:
```json
{
  "detail": [
    {
      "loc": ["body", "name"],
      "msg": "String should match pattern '^[a-z0-9][a-z0-9-]*[a-z0-9]$|^[a-z0-9]$'",
      "type": "string_pattern_mismatch"
    }
  ]
}
```

### 500 Internal Server Error

Server error:
```json
{
  "detail": "Failed to load CA: decryption failed"
}
```

### 503 Service Unavailable

Service not ready:
```json
{
  "detail": "Master key not configured"
}
```

## Rate Limiting

Rate limiting should be configured at the reverse proxy level. Recommended limits:

| Endpoint | Limit |
|----------|-------|
| Certificate signing | 100/minute |
| List operations | 1000/minute |
| Health checks | Unlimited |

## Pagination

List endpoints support pagination:

```bash
# First page
GET /api/v1/environments/prod/certs?limit=50&offset=0

# Second page
GET /api/v1/environments/prod/certs?limit=50&offset=50
```

The response includes `total` for calculating pages:
```json
{
  "certificates": [...],
  "total": 150
}
```
