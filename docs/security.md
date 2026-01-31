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

### Transport Security

- All API traffic should use HTTPS (TLS 1.2+)
- Database connections should use SSL
- Keycloak communication over HTTPS

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

- [ ] Enable HTTPS with valid certificates
- [ ] Configure database SSL
- [ ] Use secrets manager for master key
- [ ] Set appropriate CORS origins
- [ ] Enable rate limiting at reverse proxy
- [ ] Configure firewall rules
- [ ] Set up log aggregation

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
