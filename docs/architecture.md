# Architecture

This document describes the system architecture, components, and design decisions for sshmgr.

## System Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Clients                                         │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   ┌─────────────┐         ┌─────────────┐         ┌─────────────┐          │
│   │  CLI Tool   │         │  REST API   │         │  Future UI  │          │
│   │  (sshmgr)   │         │  Clients    │         │  (Node.js)  │          │
│   └──────┬──────┘         └──────┬──────┘         └──────┬──────┘          │
│          │                       │                       │                  │
└──────────┼───────────────────────┼───────────────────────┼──────────────────┘
           │                       │                       │
           │  Device Flow          │  JWT Bearer           │
           │                       │                       │
┌──────────▼───────────────────────▼───────────────────────▼──────────────────┐
│                            sshmgr Application                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │                     Authentication Layer                             │   │
│   │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                  │   │
│   │  │ Device Flow │  │    JWT      │  │    RBAC     │                  │   │
│   │  │   (CLI)     │  │ Validation  │  │   Checks    │                  │   │
│   │  └─────────────┘  └─────────────┘  └─────────────┘                  │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                    │                                         │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │                        Core Library                                  │   │
│   │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                  │   │
│   │  │ Certificate │  │ Environment │  │   Policy    │                  │   │
│   │  │  Authority  │  │   Manager   │  │   Engine    │                  │   │
│   │  └─────────────┘  └─────────────┘  └─────────────┘                  │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                    │                                         │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │                       Storage Layer                                  │   │
│   │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                  │   │
│   │  │ Repositories│  │  Encrypted  │  │   Models    │                  │   │
│   │  │             │  │ Key Storage │  │             │                  │   │
│   │  └─────────────┘  └─────────────┘  └─────────────┘                  │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
└──────────────────────────────────┬──────────────────────────────────────────┘
                                   │
         ┌─────────────────────────┼─────────────────────────┐
         │                         │                         │
         ▼                         ▼                         ▼
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   PostgreSQL    │     │    Keycloak     │     │   ssh-keygen    │
│   (Database)    │     │   (Identity)    │     │   (Crypto)      │
└─────────────────┘     └─────────────────┘     └─────────────────┘
```

## Component Details

### CLI Layer (`src/sshmgr/cli/`)

The command-line interface built with [Click](https://click.palletsprojects.com/):

| Module | Purpose |
|--------|---------|
| `main.py` | Entry point, global options, command registration |
| `output.py` | Rich console output, formatting helpers |
| `commands/auth.py` | Login, logout, status commands |
| `commands/environment.py` | Environment CRUD operations |
| `commands/cert.py` | Certificate signing and management |
| `commands/rotate.py` | CA rotation commands |

**Key Features:**
- Device Authorization Flow for browser-based login
- Credential storage in `~/.sshmgr/credentials.json`
- Rich console output with spinners and tables
- JSON output mode for scripting (`-f json`)

### API Layer (`src/sshmgr/api/`)

REST API built with [FastAPI](https://fastapi.tiangolo.com/):

| Module | Purpose |
|--------|---------|
| `main.py` | FastAPI app, middleware, lifespan |
| `schemas.py` | Pydantic request/response models |
| `dependencies.py` | Dependency injection helpers |
| `routes/health.py` | Health and readiness endpoints |
| `routes/environments.py` | Environment CRUD and rotation |
| `routes/certificates.py` | Certificate signing and management |

**Key Features:**
- JWT authentication via Bearer tokens
- Role-based access control
- Environment-level authorization
- OpenAPI documentation (Swagger UI at `/api/docs`)

### Core Library (`src/sshmgr/core/`)

Business logic layer:

| Module | Purpose |
|--------|---------|
| `ca.py` | Certificate Authority - wraps `ssh-keygen` |
| `exceptions.py` | Custom exception hierarchy |

**Certificate Authority Design:**

```python
@dataclass
class CertificateAuthority:
    private_key: bytes      # PEM-encoded
    public_key: str         # OpenSSH format
    key_type: KeyType       # ed25519, rsa, ecdsa

    @classmethod
    def generate(cls, key_type: KeyType) -> Self

    def sign_user_key(self, public_key, principals, ...) -> SignedCertificate
    def sign_host_key(self, public_key, principals, ...) -> SignedCertificate
```

All cryptographic operations delegate to `ssh-keygen` via subprocess, ensuring we use battle-tested OpenSSH code.

### Authentication Layer (`src/sshmgr/auth/`)

Keycloak OIDC integration:

| Module | Purpose |
|--------|---------|
| `keycloak.py` | Keycloak client, token exchange |
| `device_flow.py` | OAuth 2.0 Device Authorization Flow |
| `jwt.py` | JWT validation with JWKS |
| `rbac.py` | Role-based access control, FastAPI dependencies |
| `credentials.py` | CLI credential storage and refresh |

**Role Hierarchy:**
```
admin > operator > viewer

admin:    Create/delete environments, rotate CAs, all operator permissions
operator: Issue certificates, revoke certificates, view audit logs
viewer:   Read-only access to environments and certificates
```

**Environment Access:**
- Admins can access all environments
- Others require Keycloak group membership: `/environments/{env-name}`

### Storage Layer (`src/sshmgr/storage/`)

Database access with SQLAlchemy 2.0 async:

| Module | Purpose |
|--------|---------|
| `database.py` | Engine and session management |
| `models.py` | ORM models (Environment, Certificate, Policy) |
| `repositories.py` | Data access classes |

### Key Storage (`src/sshmgr/keys/`)

Encryption for CA private keys:

| Module | Purpose |
|--------|---------|
| `base.py` | Abstract KeyStorage interface |
| `encrypted.py` | Fernet encryption for PostgreSQL storage |

**Encryption Flow:**
```
Private Key → Fernet.encrypt() → Base64 → "encrypted:..." prefix → Database
```

## Data Model

### Environment

```
┌─────────────────────────────────────────────────────────────────┐
│ Environment                                                      │
├─────────────────────────────────────────────────────────────────┤
│ id: UUID (PK)                                                   │
│ name: str (unique)                                              │
├─────────────────────────────────────────────────────────────────┤
│ User CA                        │ Host CA                        │
│ ─────────                      │ ─────────                      │
│ user_ca_public_key             │ host_ca_public_key             │
│ user_ca_key_ref (encrypted)    │ host_ca_key_ref (encrypted)    │
│ old_user_ca_public_key         │ old_host_ca_public_key         │
│ old_user_ca_key_ref            │ old_host_ca_key_ref            │
│ old_user_ca_expires_at         │ old_host_ca_expires_at         │
├─────────────────────────────────────────────────────────────────┤
│ default_user_cert_validity: timedelta (8h)                      │
│ default_host_cert_validity: timedelta (90d)                     │
│ created_at, updated_at                                          │
└─────────────────────────────────────────────────────────────────┘
```

### Certificate (Audit Log)

```
┌─────────────────────────────────────────────────────────────────┐
│ Certificate                                                      │
├─────────────────────────────────────────────────────────────────┤
│ id: UUID (PK)                                                   │
│ environment_id: UUID (FK)                                       │
│ cert_type: Enum (user, host)                                    │
│ serial: int                                                      │
│ key_id: str                                                      │
│ principals: list[str]                                            │
│ valid_after, valid_before: datetime                             │
│ public_key_fingerprint: str                                     │
│ issued_at: datetime                                              │
│ issued_by: str                                                   │
│ revoked_at: datetime (nullable)                                 │
│ revoked_by: str (nullable)                                      │
│ revocation_reason: str (nullable)                               │
└─────────────────────────────────────────────────────────────────┘
```

## Authentication Flow

### CLI Device Flow

```
┌─────────┐          ┌─────────┐          ┌──────────┐          ┌─────────┐
│  User   │          │   CLI   │          │ Keycloak │          │ Browser │
└────┬────┘          └────┬────┘          └────┬─────┘          └────┬────┘
     │                    │                    │                     │
     │ sshmgr login       │                    │                     │
     │───────────────────>│                    │                     │
     │                    │                    │                     │
     │                    │ POST /device       │                     │
     │                    │───────────────────>│                     │
     │                    │                    │                     │
     │                    │ device_code,       │                     │
     │                    │ user_code, uri     │                     │
     │                    │<───────────────────│                     │
     │                    │                    │                     │
     │ Display code & URL │                    │                     │
     │<───────────────────│                    │                     │
     │                    │                    │                     │
     │ Open browser ──────────────────────────────────────────────>│
     │                    │                    │                     │
     │                    │                    │   Enter code       │
     │                    │                    │<────────────────────│
     │                    │                    │                     │
     │                    │                    │   Authenticate     │
     │                    │                    │<────────────────────│
     │                    │                    │                     │
     │                    │ Poll /token        │                     │
     │                    │───────────────────>│                     │
     │                    │                    │                     │
     │                    │ access_token,      │                     │
     │                    │ refresh_token      │                     │
     │                    │<───────────────────│                     │
     │                    │                    │                     │
     │ Login successful   │                    │                     │
     │<───────────────────│                    │                     │
```

### API JWT Flow

```
┌─────────┐          ┌─────────┐          ┌──────────┐
│ Client  │          │   API   │          │ Keycloak │
└────┬────┘          └────┬────┘          └────┬─────┘
     │                    │                    │
     │ Request + Bearer   │                    │
     │───────────────────>│                    │
     │                    │                    │
     │                    │ Fetch JWKS         │
     │                    │───────────────────>│
     │                    │                    │
     │                    │ Public keys        │
     │                    │<───────────────────│
     │                    │                    │
     │                    │ Validate JWT       │
     │                    │ Extract claims     │
     │                    │ Check roles        │
     │                    │ Check env access   │
     │                    │                    │
     │ Response           │                    │
     │<───────────────────│                    │
```

## Certificate Signing Flow

```
┌─────────┐          ┌─────────┐          ┌──────────┐          ┌───────────┐
│ Client  │          │   API   │          │ Database │          │ssh-keygen │
└────┬────┘          └────┬────┘          └────┬─────┘          └─────┬─────┘
     │                    │                    │                      │
     │ Sign request       │                    │                      │
     │ + public key       │                    │                      │
     │───────────────────>│                    │                      │
     │                    │                    │                      │
     │                    │ Get environment    │                      │
     │                    │───────────────────>│                      │
     │                    │<───────────────────│                      │
     │                    │                    │                      │
     │                    │ Decrypt CA key     │                      │
     │                    │ (Fernet)           │                      │
     │                    │                    │                      │
     │                    │ Sign certificate ─────────────────────────>
     │                    │ (subprocess)       │                      │
     │                    │<───────────────────────────────────────────
     │                    │                    │                      │
     │                    │ Record audit log   │                      │
     │                    │───────────────────>│                      │
     │                    │                    │                      │
     │ Certificate        │                    │                      │
     │<───────────────────│                    │                      │
```

## Security Design

### Defense in Depth

1. **Authentication**: Keycloak OIDC with JWT validation
2. **Authorization**: Role-based (admin/operator/viewer) + environment access
3. **Encryption at Rest**: Fernet encryption for CA private keys
4. **No Custom Crypto**: All crypto operations via OpenSSH `ssh-keygen`
5. **Short-lived Certificates**: Default 8 hours for users, 90 days for hosts
6. **Audit Logging**: All certificate operations recorded in database

### Key Protection

```
Master Key (SSHMGR_MASTER_KEY)
    │
    ▼
┌─────────────────────────────────────┐
│ Fernet Symmetric Encryption         │
│ (AES-128-CBC + HMAC-SHA256)        │
└─────────────────────────────────────┘
    │
    ▼
CA Private Keys (encrypted in PostgreSQL)
```

The master key should be:
- Stored securely (environment variable, secrets manager)
- Rotated periodically
- Never committed to version control

## Technology Stack

| Component | Technology | Rationale |
|-----------|------------|-----------|
| Language | Python 3.11+ | Developer familiarity, rapid development |
| CLI | Click | Clean, composable, widely used |
| API | FastAPI | Async, auto docs, Pydantic validation |
| ORM | SQLAlchemy 2.0 | Mature, async support |
| Database | PostgreSQL | Production-grade, good for medium scale |
| Auth | Keycloak | Enterprise IdP, OIDC, RBAC |
| Crypto | OpenSSH ssh-keygen | Battle-tested, no custom implementation |
| Key Encryption | cryptography (Fernet) | Symmetric encryption, well-audited |
