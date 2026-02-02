# CLI Reference

Complete reference for the `sshmgr` command-line interface.

## Global Options

```bash
sshmgr [OPTIONS] COMMAND [ARGS]...
```

| Option | Description |
|--------|-------------|
| `-f, --format [text\|json\|table]` | Output format (default: text) |
| `-e, --env ENV` | Target environment name |
| `-v, --verbose` | Enable verbose output |
| `--version` | Show version and exit |
| `--help` | Show help and exit |

## Authentication Commands

### sshmgr login

Login to sshmgr using browser authentication.

```bash
sshmgr login
```

Uses OAuth 2.0 Device Authorization Flow:
1. Displays a code and URL
2. You authenticate in your browser
3. CLI receives tokens automatically

**Example:**
```
$ sshmgr login
╭─────────────────── Login Required ───────────────────╮
│ To sign in, open a browser and visit:                │
│                                                      │
│   https://keycloak.example.com/device                │
│                                                      │
│ Then enter the code:                                 │
│                                                      │
│   ABCD-1234                                          │
╰──────────────────────────────────────────────────────╯

Waiting for authentication...
╭─────────────────── Login Successful ─────────────────╮
│ Successfully logged in as alice@example.com          │
╰──────────────────────────────────────────────────────╯
```

### sshmgr logout

Logout and clear stored credentials.

```bash
sshmgr logout
```

This will:
1. Invalidate the refresh token with Keycloak
2. Remove local credentials from `~/.sshmgr/`

### sshmgr auth status

Show current authentication status.

```bash
sshmgr auth status
```

**Example output:**
```
Authentication Status

Logged in as         alice@example.com
Keycloak URL         https://keycloak.example.com
Realm                sshmgr
Token Status         Valid (3245s remaining)
```

### sshmgr auth whoami

Show detailed information about the current user.

```bash
sshmgr auth whoami
```

**Example output:**
```
Current User

Username             alice
User ID              a1b2c3d4-e5f6-7890-abcd-ef1234567890
Email                alice@example.com ✓
Name                 Alice Smith
Roles                operator
Environments         prod, staging
```

### sshmgr auth refresh

Manually refresh the access token.

```bash
sshmgr auth refresh
```

## Environment Commands

### sshmgr env init

Initialize a new environment with CA keypairs.

```bash
sshmgr env init NAME [OPTIONS]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--user-validity` | `8h` | Default user certificate validity |
| `--host-validity` | `90d` | Default host certificate validity |
| `--key-type` | `ed25519` | Key type (ed25519, rsa, ecdsa) |

**Example:**
```bash
$ sshmgr env init customer-prod --user-validity 12h --host-validity 90d

✓ Environment 'customer-prod' created successfully

Environment ID:     a1b2c3d4-e5f6-7890-abcd-ef1234567890
User CA fingerprint: SHA256:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
Host CA fingerprint: SHA256:yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy

Next steps:
  1. Get User CA public key:  sshmgr env get-ca customer-prod --type user
  2. Get Host CA public key:  sshmgr env get-ca customer-prod --type host
  3. Distribute CA public keys to your infrastructure
```

### sshmgr env list

List all environments.

```bash
sshmgr env list
```

**Example output:**
```
                        Environments
┏━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━┓
┃ Name            ┃ User Cert Validity ┃ Host Cert Validity ┃ Created    ┃
┡━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━┩
│ prod            │ 8h                 │ 90d                │ 2024-01-15 │
│ staging         │ 12h                │ 30d                │ 2024-01-10 │
│ customer-prod   │ 8h                 │ 90d                │ 2024-01-20 │
└─────────────────┴────────────────────┴────────────────────┴────────────┘
```

### sshmgr env show

Show details of an environment.

```bash
sshmgr env show NAME
```

**Example output:**
```
╭─────────────── Environment: prod ───────────────╮
│ ID:           a1b2c3d4-e5f6-7890-abcd-ef123456  │
│ Name:         prod                               │
│ Created:      2024-01-15 10:30:00 UTC           │
│                                                  │
│ User CA                                          │
│   Fingerprint:  SHA256:xxxx...                  │
│   Validity:     8h                               │
│                                                  │
│ Host CA                                          │
│   Fingerprint:  SHA256:yyyy...                  │
│   Validity:     90d                              │
╰──────────────────────────────────────────────────╯
```

### sshmgr env delete

Delete an environment.

```bash
sshmgr env delete NAME [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `-f, --force` | Skip confirmation prompt |

**Example:**
```bash
$ sshmgr env delete old-env

! You are about to delete environment 'old-env'
This will:
  - Permanently delete the CA keypairs
  - Invalidate all certificates issued by this environment

Are you sure you want to continue? [y/N]: y
✓ Environment 'old-env' deleted
```

### sshmgr env get-ca

Get the CA public key for an environment.

```bash
sshmgr env get-ca NAME --type TYPE [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--type` | Required. CA type: `user` or `host` |
| `-o, --output` | Output file path (defaults to stdout) |
| `--include-old` | Include old CA if rotation is in progress |

**Examples:**
```bash
# Print to stdout
sshmgr env get-ca prod --type user

# Save to file
sshmgr env get-ca prod --type user -o /etc/ssh/user_ca.pub

# For known_hosts (host CA)
sshmgr env get-ca prod --type host >> ~/.ssh/known_hosts
```

## Certificate Commands

### sshmgr cert sign-user

Sign a user's public key to create an SSH certificate.

```bash
sshmgr cert sign-user [OPTIONS]
```

| Option | Required | Description |
|--------|----------|-------------|
| `-e, --env` | Yes | Environment name |
| `-k, --public-key` | Yes | Path to user's public key file |
| `-n, --principals` | Yes | Comma-separated list of principals |
| `-I, --key-id` | Yes | Key identifier (e.g., email) |
| `-V, --validity` | No | Validity period (default: env setting) |
| `-o, --output` | No | Output path (default: `<key>-cert.pub`) |
| `--force-command` | No | Force a specific command |

**Example:**
```bash
$ sshmgr cert sign-user \
    -e prod \
    -k ~/.ssh/id_ed25519.pub \
    -n "deploy,admin" \
    -I "alice@example.com" \
    -V 8h

✓ Certificate written to /home/alice/.ssh/id_ed25519-cert.pub

Serial:      42
Key ID:      alice@example.com
Principals:  deploy, admin
Valid until: 2024-01-21 18:30:00 UTC

Verify with: ssh-keygen -L -f /home/alice/.ssh/id_ed25519-cert.pub
```

### sshmgr cert sign-host

Sign a host's public key to create an SSH host certificate.

```bash
sshmgr cert sign-host [OPTIONS]
```

| Option | Required | Description |
|--------|----------|-------------|
| `-e, --env` | Yes | Environment name |
| `-k, --public-key` | Yes | Path to host's public key file |
| `-n, --principals` | Yes | Comma-separated hostnames/IPs |
| `-V, --validity` | No | Validity period (default: env setting) |
| `-o, --output` | No | Output path (default: `<key>-cert.pub`) |

**Example:**
```bash
$ sshmgr cert sign-host \
    -e prod \
    -k /etc/ssh/ssh_host_ed25519_key.pub \
    -n "server1.example.com,10.0.0.5"

✓ Certificate written to /etc/ssh/ssh_host_ed25519_key-cert.pub

Serial:      43
Key ID:      server1.example.com
Principals:  server1.example.com, 10.0.0.5
Valid until: 2024-04-20 10:30:00 UTC
```

### sshmgr cert list

List certificates issued for an environment.

```bash
sshmgr cert list -e ENV [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `-e, --env` | Environment name (required) |
| `--type` | Filter by type (user, host) |
| `--include-expired` | Include expired certificates |
| `--include-revoked` | Include revoked certificates |
| `--limit` | Maximum number to show (default: 50) |

**Example output:**
```
               Certificates for prod
┏━━━━━━━━┳━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━┓
┃ Serial ┃ Type ┃ Key ID               ┃ Principals     ┃ Status           ┃
┡━━━━━━━━╇━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━┩
│ 42     │ USER │ alice@example.com    │ deploy, admin  │ 7h remaining     │
│ 41     │ USER │ bob@example.com      │ deploy         │ 2h remaining     │
│ 40     │ HOST │ server1.example.com  │ server1, 10... │ 89d remaining    │
│ 39     │ USER │ charlie@example.com  │ readonly       │ Revoked          │
└────────┴──────┴──────────────────────┴────────────────┴──────────────────┘

Showing 4 certificate(s)
```

### sshmgr cert show

Show details of a specific certificate.

```bash
sshmgr cert show -e ENV -s SERIAL
```

### sshmgr cert revoke

Revoke a certificate.

```bash
sshmgr cert revoke -e ENV -s SERIAL [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `-e, --env` | Environment name (required) |
| `-s, --serial` | Certificate serial number (required) |
| `-r, --reason` | Reason for revocation |
| `-f, --force` | Skip confirmation prompt |

**Example:**
```bash
$ sshmgr cert revoke -e prod -s 39 -r "User terminated"

Certificate to revoke:
  Serial:     39
  Key ID:     charlie@example.com
  Principals: readonly

Revoke this certificate? [y/N]: y
✓ Certificate 39 revoked
! Remember to generate and distribute updated KRL files to enforce revocation
```

## CA Rotation Commands

### Understanding CA Trust Relationships

Before rotating CAs, understand where each CA type is deployed:

| CA Type | Signs | Trusted By | Deployment Location |
|---------|-------|------------|---------------------|
| **User CA** | User certificates | SSH **servers** | `/etc/ssh/trusted_user_ca.pub` |
| **Host CA** | Host certificates | SSH **clients** | `~/.ssh/known_hosts` |

**Key insight**: The names refer to *what gets signed*, not *where the CA goes*:
- "User CA" signs **user** keys → deployed to **servers** which authenticate users
- "Host CA" signs **host** keys → deployed to **clients** which verify hosts

### sshmgr rotate ca

Rotate a CA key with a grace period.

```bash
sshmgr rotate ca [OPTIONS]
```

| Option | Required | Description |
|--------|----------|-------------|
| `-e, --env` | Yes | Environment name |
| `--type` | Yes | CA type (user, host) |
| `-g, --grace-period` | No | Grace period (default: 24h) |
| `--key-type` | No | New key type (default: ed25519) |
| `-f, --force` | No | Skip confirmation |

**Example:**
```bash
$ sshmgr rotate ca -e prod --type user --grace-period 7d

CA Rotation for prod
  CA Type:          user
  Current CA:       SHA256:xxxx...
  Grace Period:     7d
  New Key Type:     ed25519

! After rotation, you must update your infrastructure to trust the new CA

Proceed with rotation? [y/N]: y

✓ User CA rotated successfully

Old CA fingerprint: SHA256:xxxx...
New CA fingerprint: SHA256:yyyy...

Next steps:
  1. Get new CA public key:  sshmgr env get-ca prod --type user
  2. Get both CAs:           sshmgr env get-ca prod --type user --include-old
  3. Update your infrastructure to trust both CAs
  4. Wait for grace period (7d) before removing old CA from config
```

### CA Rotation Step-by-Step

#### User CA Rotation (updating SSH servers)

After rotating the User CA, update each SSH server:

```bash
# 1. Get both CAs (current + old) and deploy to server
sshmgr env get-ca prod --type user --include-old -o /etc/ssh/trusted_user_ca.pub

# 2. Verify sshd_config has the TrustedUserCAKeys directive
grep TrustedUserCAKeys /etc/ssh/sshd_config
# Should show: TrustedUserCAKeys /etc/ssh/trusted_user_ca.pub

# 3. Reload SSH daemon to pick up the new CA
sudo systemctl reload sshd
```

The `trusted_user_ca.pub` file will contain both CAs:
```
ssh-ed25519 AAAA...new_ca... sshmgr-ca
# Old CA (expires: 2026-02-09 19:00:00+00:00)
ssh-ed25519 AAAA...old_ca... sshmgr-ca
```

#### Host CA Rotation (updating SSH clients)

After rotating the Host CA, update client known_hosts:

```bash
# 1. Get both Host CAs
sshmgr env get-ca prod --type host --include-old

# 2. Update ~/.ssh/known_hosts (or /etc/ssh/ssh_known_hosts)
# Add @cert-authority entries for both CAs:
@cert-authority *.example.com ssh-ed25519 AAAA...new_ca...
@cert-authority *.example.com ssh-ed25519 AAAA...old_ca...
```

#### After Grace Period Expires

Once the grace period ends, remove the old CA:

```bash
# 1. Get only the current CA (excludes expired old CA)
sshmgr env get-ca prod --type user -o /etc/ssh/trusted_user_ca.pub

# 2. Reload SSH daemon
sudo systemctl reload sshd

# 3. Clean up expired old CAs from database
sshmgr rotate cleanup -e prod
```

### sshmgr rotate status

Show CA rotation status for an environment.

```bash
sshmgr rotate status -e ENV
```

**Example output:**
```
Rotation Status: prod

User CA
  Current: SHA256:yyyy...
  Old:     SHA256:xxxx...
  Expires: 2024-01-28 10:30:00 UTC

Host CA
  Current: SHA256:zzzz...
  Status:  No rotation in progress
```

### sshmgr rotate cleanup

Clean up expired old CA keys.

```bash
sshmgr rotate cleanup [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `-e, --env` | Environment name (optional, cleans all if not specified) |
| `-f, --force` | Force cleanup even if grace period hasn't expired |

## JSON Output

All commands support JSON output with `-f json`:

```bash
$ sshmgr env list -f json
[
  {
    "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "name": "prod",
    "created_at": "2024-01-15T10:30:00+00:00",
    "default_user_cert_validity": "8:00:00",
    "default_host_cert_validity": "90 days, 0:00:00"
  }
]
```

This is useful for scripting and automation:

```bash
# Get all environment names
sshmgr env list -f json | jq -r '.[].name'

# Check if logged in
sshmgr auth status -f json | jq -e '.logged_in'
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | General error |
| 2 | Invalid arguments |
| 130 | Interrupted (Ctrl+C) |
