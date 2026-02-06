# Security Model

This document describes the security architecture, threat model, and best practices for sshmgr.

## Security Overview

sshmgr implements defense in depth with multiple security layers:

```
┌─────────────────────────────────────────────────────────────────┐
│                    Security Layers                               │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. Authentication       Keycloak OIDC, JWT validation          │
│         │                                                        │
│         ▼                                                        │
│  2. Authorization        Role-based (admin/operator/viewer)     │
│         │                Environment-level access control        │
│         ▼                                                        │
│  3. Encryption           Fernet encryption for CA private keys  │
│         │                TLS for transport                       │
│         ▼                                                        │
│  4. Crypto Operations    OpenSSH ssh-keygen (no custom crypto)  │
│         │                                                        │
│         ▼                                                        │
│  5. Audit Logging        All operations recorded in database    │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Authentication

### Keycloak OIDC

All authentication is handled by Keycloak using OpenID Connect:

- **CLI**: OAuth 2.0 Device Authorization Flow
- **API**: JWT Bearer tokens

Benefits:
- No password storage in sshmgr
- Enterprise SSO integration (LDAP, SAML, social login)
- Multi-factor authentication support
- Centralized user management

### Token Validation

JWT tokens are validated by:

1. Verifying signature against Keycloak's JWKS
2. Checking token expiration (`exp` claim)
3. Validating issuer matches configured Keycloak realm
4. Extracting roles and groups from claims

```python
# Token validation flow
async def validate(self, token: str) -> TokenClaims:
    # 1. Get public keys from Keycloak JWKS endpoint
    jwks = await self._fetch_jwks()

    # 2. Decode and verify signature
    claims = jwt.decode(
        token,
        key=jwks,
        algorithms=["RS256"],
        issuer=self.issuer_url,
    )

    # 3. Extract roles from realm_access
    return TokenClaims.from_jwt(claims)
```

## Authorization

### Role-Based Access Control (RBAC)

Three roles with hierarchical permissions:

| Role | Permissions |
|------|-------------|
| **admin** | Create/delete environments, rotate CAs, manage policies, all operator permissions |
| **operator** | Issue certificates, revoke certificates, view audit logs, all viewer permissions |
| **viewer** | Read-only access to environments and certificates |

Role hierarchy: `admin > operator > viewer`

### Environment-Level Access

Users can only access environments they're authorized for:

1. **Admins**: Access all environments
2. **Others**: Must be member of Keycloak group `/environments/{env-name}`

Example:
- User in group `/environments/prod` can access `prod` environment
- User in group `/environments/staging` can access `staging` environment

### Permission Matrix

| Action | viewer | operator | admin |
|--------|--------|----------|-------|
| List environments | ✓* | ✓* | ✓ |
| View environment | ✓* | ✓* | ✓ |
| Create environment | | | ✓ |
| Delete environment | | | ✓ |
| Get CA public key | ✓* | ✓* | ✓ |
| List certificates | ✓* | ✓* | ✓ |
| View certificate | ✓* | ✓* | ✓ |
| Sign certificate | | ✓* | ✓ |
| Revoke certificate | | ✓* | ✓ |
| Rotate CA | | | ✓ |

*Requires environment access via group membership

## Encryption

### CA Private Key Protection

CA private keys are encrypted at rest using Fernet symmetric encryption:

```
┌─────────────────────────────────────────────────────────────────┐
│                    Key Encryption Flow                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Private Key (PEM)                                               │
│        │                                                         │
│        ▼                                                         │
│  ┌─────────────────────────────────────────┐                    │
│  │ Fernet.encrypt()                        │                    │
│  │  - AES-128-CBC encryption               │                    │
│  │  - HMAC-SHA256 authentication           │                    │
│  │  - Timestamp for key versioning         │                    │
│  └─────────────────────────────────────────┘                    │
│        │                                                         │
│        ▼                                                         │
│  Encrypted Blob (base64)                                         │
│        │                                                         │
│        ▼                                                         │
│  "encrypted:gAAAAABh..." prefix                                  │
│        │                                                         │
│        ▼                                                         │
│  Stored in PostgreSQL                                            │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Master Key Management

The master key (`SSHMGR_MASTER_KEY`) is critical:

**DO**:
- Store in a secrets manager (HashiCorp Vault, AWS Secrets Manager)
- Rotate periodically (requires re-encrypting all CA keys)
- Use different keys for different environments (dev/prod)
- Limit access to the key

**DON'T**:
- Commit to version control
- Store in plaintext files
- Share across team members unnecessarily
- Log or print the key

### Transport Security (TLS)

All production deployments must use HTTPS. sshmgr supports two TLS deployment models:

#### Option 1: Traefik with Let's Encrypt (Recommended)

The production Docker Compose (`docker-compose.prod.yml`) includes Traefik for automatic TLS:

```
┌─────────────────────────────────────────────────────────────────┐
│                    TLS Termination with Traefik                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Internet ──▶ Traefik (port 443) ──▶ sshmgr API (port 8000)     │
│                   │                                              │
│                   ├── Automatic Let's Encrypt certificates       │
│                   ├── HTTP to HTTPS redirect                     │
│                   ├── HSTS headers (1 year)                      │
│                   ├── X-Content-Type-Options: nosniff            │
│                   └── X-Frame-Options: DENY                      │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

**Security headers applied by Traefik:**

| Header | Value | Purpose |
|--------|-------|---------|
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` | Force HTTPS for 1 year |
| `X-Content-Type-Options` | `nosniff` | Prevent MIME-type sniffing |
| `X-Frame-Options` | `DENY` | Prevent clickjacking |

**Certificate renewal:**
- Traefik automatically renews certificates before expiration
- No manual intervention required
- Certificates stored in Docker volume `letsencrypt_data`

**Rate limits:**
- Let's Encrypt has rate limits (50 certs/domain/week)
- Use staging server for testing: uncomment `caserver` line in `docker-compose.prod.yml`

#### Option 2: External Reverse Proxy

For integration with existing infrastructure (nginx, HAProxy, cloud load balancers):

```nginx
# nginx example with TLS
server {
    listen 443 ssl http2;
    server_name sshmgr.example.com;

    ssl_certificate /etc/ssl/certs/sshmgr.crt;
    ssl_certificate_key /etc/ssl/private/sshmgr.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
    ssl_prefer_server_ciphers off;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Request-ID $request_id;
    }
}
```

#### TLS Best Practices

1. **Protocol versions**: Use TLS 1.2+ only (disable SSLv3, TLS 1.0, TLS 1.1)
2. **Cipher suites**: Use strong ciphers (ECDHE with AES-GCM)
3. **Certificate chain**: Include intermediate certificates
4. **HSTS**: Enable with long max-age and includeSubDomains
5. **OCSP stapling**: Enable for faster certificate validation

#### Internal Traffic

Traffic between Traefik and application containers stays unencrypted (HTTP) within the Docker network:
- This is secure because traffic never leaves the host
- Reduces complexity and CPU overhead
- Standard pattern for container deployments

Database and Keycloak internal connections:
- Database connections should use SSL in production
- Keycloak uses HTTP internally, HTTPS externally via Traefik

## Cryptographic Operations

### No Custom Crypto

All cryptographic operations use OpenSSH's `ssh-keygen`:

| Operation | Implementation |
|-----------|----------------|
| Key generation | `ssh-keygen -t ed25519` |
| Certificate signing | `ssh-keygen -s ca_key -I key_id ...` |
| Fingerprint | `ssh-keygen -l -f key.pub` |
| Certificate parsing | `ssh-keygen -L -f cert.pub` |

Benefits:
- Battle-tested implementation
- No crypto implementation bugs
- Compatible with standard SSH tooling
- Easy to audit

### Supported Key Types

| Type | Key Size | Recommended |
|------|----------|-------------|
| Ed25519 | 256 bits | ✓ Default |
| RSA | 4096 bits | Legacy support |
| ECDSA | 256/384/521 bits | Compatible |

Ed25519 is recommended for:
- Fast key generation and signing
- Small key size
- Strong security

## Certificate Security

### CA Trust Relationships

Understanding where to deploy CA public keys is critical:

```
┌─────────────────────────────────────────────────────────────────┐
│                    CA Trust Model                                │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  USER CA                          HOST CA                        │
│  ────────                         ────────                       │
│  Signs: User certificates         Signs: Host certificates       │
│  Trusted by: SSH SERVERS          Trusted by: SSH CLIENTS        │
│                                                                  │
│  ┌──────────┐    presents    ┌──────────┐                       │
│  │   User   │ ────cert────▶  │  Server  │                       │
│  │ (client) │                │  (sshd)  │                       │
│  └──────────┘                └──────────┘                       │
│       │                            │                             │
│       │                            │ validates against           │
│       │                            ▼                             │
│       │                    ┌──────────────────┐                 │
│       │                    │ User CA pub key  │                 │
│       │                    │ /etc/ssh/        │                 │
│       │                    │ trusted_user_ca  │                 │
│       │                    └──────────────────┘                 │
│       │                                                          │
│       │ validates against  ┌──────────────────┐                 │
│       └──────────────────▶ │ Host CA pub key  │                 │
│                            │ ~/.ssh/known_hosts│                 │
│                            │ @cert-authority  │                 │
│                            └──────────────────┘                 │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

| CA Type | What It Signs | Who Trusts It | Deployment Location |
|---------|---------------|---------------|---------------------|
| **User CA** | User public keys | SSH **servers** | `/etc/ssh/trusted_user_ca.pub` |
| **Host CA** | Host public keys | SSH **clients** | `~/.ssh/known_hosts` or `/etc/ssh/ssh_known_hosts` |

**Key insight**: The CA names refer to *what gets signed*, not *where the CA is deployed*:
- "User CA" signs **user** keys → servers trust it to authenticate **users**
- "Host CA" signs **host** keys → clients trust it to authenticate **hosts**

### Deploying User CA (Server Configuration)

On each SSH server that should accept certificate-authenticated users:

```bash
# 1. Get the User CA public key
sshmgr env get-ca prod --type user -o /etc/ssh/trusted_user_ca.pub

# 2. Configure sshd to trust certificates signed by this CA
# Add to /etc/ssh/sshd_config:
TrustedUserCAKeys /etc/ssh/trusted_user_ca.pub

# 3. Reload SSH daemon
sudo systemctl reload sshd
```

### Deploying Host CA (Client Configuration)

On each SSH client that should verify host certificates:

```bash
# 1. Get the Host CA public key
sshmgr env get-ca prod --type host

# 2. Add to ~/.ssh/known_hosts with @cert-authority directive:
@cert-authority *.example.com ssh-ed25519 AAAA...key...

# Or for system-wide configuration, add to /etc/ssh/ssh_known_hosts
```

### Short-Lived Certificates

Default validity periods minimize exposure window:

| Type | Default Validity | Rationale |
|------|------------------|-----------|
| User | 8 hours | Single work day |
| Host | 90 days | Infrastructure change frequency |

Short-lived certificates reduce the need for revocation.

### Certificate Contents

Certificates include:
- **Key ID**: Identifier for audit (e.g., email address)
- **Principals**: Authorized usernames/hostnames
- **Validity**: Start and end timestamps
- **Serial**: Unique within environment

### Revocation

Certificate revocation is recorded in the database, but enforcement requires:

1. Generating a Key Revocation List (KRL)
2. Distributing KRL to SSH servers
3. Configuring `RevokedKeys` in `sshd_config`

```bash
# Generate KRL (future feature)
sshmgr krl generate -e prod -o /etc/ssh/revoked_keys

# sshd_config
RevokedKeys /etc/ssh/revoked_keys
```

## Audit Logging

All certificate operations are logged:

```sql
-- Certificate audit log
SELECT
    serial,
    cert_type,
    key_id,
    principals,
    issued_at,
    issued_by,
    revoked_at,
    revoked_by,
    revocation_reason
FROM certificates
WHERE environment_id = ?
ORDER BY issued_at DESC;
```

Logged information:
- Who issued/revoked the certificate
- When it was issued/revoked
- Certificate details (key ID, principals, validity)
- Public key fingerprint

### CLI User Identification

For CLI operations, the `issued_by`/`revoked_by` is resolved in order:
1. `SSHMGR_CLI_USER` environment variable (for automation)
2. Keycloak authenticated username (if logged in)
3. System username with `cli:` prefix

## Rate Limiting

sshmgr includes built-in rate limiting using a token bucket algorithm:

```
┌─────────────────────────────────────────────────────────────────┐
│                    Rate Limiting                                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Per-Client Tracking:                                            │
│  - Authenticated users: by username                              │
│  - Anonymous requests: by IP (X-Forwarded-For supported)         │
│                                                                  │
│  Default Limits:                                                 │
│  - 100 requests per 60 seconds                                   │
│  - 20 request burst allowance                                    │
│                                                                  │
│  Response Headers:                                               │
│  - X-RateLimit-Limit: Maximum requests                           │
│  - X-RateLimit-Remaining: Remaining requests                     │
│  - X-RateLimit-Reset: Seconds until reset                        │
│  - Retry-After: Seconds to wait (when limited)                   │
│                                                                  │
│  Excluded Endpoints:                                             │
│  - /health, /ready, /metrics, /docs                              │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

Configure via environment variables:
```bash
SSHMGR_RATE_LIMIT_ENABLED=true
SSHMGR_RATE_LIMIT_REQUESTS=100
SSHMGR_RATE_LIMIT_WINDOW_SECONDS=60
SSHMGR_RATE_LIMIT_BURST=20
```

## CORS Security

Cross-Origin Resource Sharing (CORS) is disabled by default for security.

**When to enable CORS:**
- Web frontend running on a different origin
- Development environments with hot-reload servers

**Security considerations:**
- Only allow specific trusted origins, never use `*` in production
- `allow_credentials=true` with `*` origins is rejected by browsers
- Configure appropriate methods (don't allow all methods unnecessarily)

```bash
# Development (specific origins)
SSHMGR_CORS_ORIGINS=http://localhost:3000,http://localhost:5173

# Production (specific origin)
SSHMGR_CORS_ORIGINS=https://dashboard.example.com
```

## Request Tracing

All API requests include an `X-Request-ID` header for distributed tracing:

- If client provides `X-Request-ID`, it's preserved through the request
- If not provided, a UUID is generated automatically
- The ID appears in logs and is returned in response headers

This enables correlation of logs across services when debugging issues

## Threat Model

### In Scope

| Threat | Mitigation |
|--------|------------|
| Unauthorized certificate issuance | Authentication, RBAC, environment access |
| CA private key theft | Fernet encryption, access controls |
| Token theft | Short-lived JWTs, token refresh |
| Certificate forgery | CA signature verification by SSH |
| Audit log tampering | Database access controls, backups |

### Out of Scope

| Threat | Assumption |
|--------|------------|
| Keycloak compromise | Keycloak security is externally managed |
| Database server compromise | Database security is externally managed |
| Server OS compromise | OS-level security is externally managed |
| Network interception | TLS configured at infrastructure level |

## Security Checklist

### Development

- [ ] Never commit master key or credentials
- [ ] Use separate development Keycloak realm
- [ ] Use test database, not production
- [ ] Review code for injection vulnerabilities

### Deployment

- [ ] Enable HTTPS with valid certificates (Traefik or reverse proxy)
- [ ] Verify HSTS headers are set
- [ ] Configure database SSL
- [ ] Use secrets manager for master key
- [ ] Configure CORS origins (or leave disabled if no web frontend)
- [ ] Review rate limiting settings (enabled by default)
- [ ] Configure firewall rules (allow only 80/443)
- [ ] Set up log aggregation
- [ ] Test Let's Encrypt certificate renewal (if using Traefik)
- [ ] Verify DNS is correctly configured for all subdomains

### Operations

- [ ] Rotate master key periodically
- [ ] Review audit logs regularly
- [ ] Monitor for unusual certificate activity
- [ ] Keep dependencies updated
- [ ] Test backup and recovery
- [ ] Document incident response

## Reporting Security Issues

If you discover a security vulnerability:

1. **Do not** open a public issue
2. Email security@yourorg.com with:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
3. Allow 90 days for response before disclosure

## Security Updates

Subscribe to security announcements:
- GitHub Security Advisories
- Mailing list: security-announce@yourorg.com
