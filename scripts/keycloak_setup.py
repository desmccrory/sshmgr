#!/usr/bin/env python3
"""
Keycloak setup script for sshmgr.

Automates the creation of:
- sshmgr realm
- Realm roles (admin, operator, viewer)
- API client (sshmgr-api) - confidential client for JWT validation
- CLI client (sshmgr-cli) - public client for device authorization flow
- Environment groups structure
- Optional test user

Usage:
    python scripts/keycloak_setup.py [OPTIONS]

Environment Variables:
    KEYCLOAK_URL            Keycloak server URL (default: http://localhost:8080)
    KEYCLOAK_ADMIN          Admin username (default: admin)
    KEYCLOAK_ADMIN_PASSWORD Admin password (default: admin)
    SSHMGR_KEYCLOAK_REALM   Realm name (default: sshmgr)
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from dataclasses import dataclass

import httpx


@dataclass
class KeycloakConfig:
    """Keycloak connection configuration."""

    url: str
    admin_user: str
    admin_password: str
    realm: str

    @classmethod
    def from_env(cls) -> KeycloakConfig:
        """Create config from environment variables."""
        return cls(
            url=os.environ.get("KEYCLOAK_URL", "http://localhost:8080"),
            admin_user=os.environ.get("KEYCLOAK_ADMIN", "admin"),
            admin_password=os.environ.get("KEYCLOAK_ADMIN_PASSWORD", "admin"),
            realm=os.environ.get("SSHMGR_KEYCLOAK_REALM", "sshmgr"),
        )


class KeycloakAdmin:
    """Keycloak Admin API client."""

    def __init__(self, config: KeycloakConfig):
        self.config = config
        self.base_url = config.url.rstrip("/")
        self.client = httpx.Client(timeout=30.0)
        self._access_token: str | None = None

    def _get_token(self) -> str:
        """Get admin access token from master realm."""
        if self._access_token:
            return self._access_token

        response = self.client.post(
            f"{self.base_url}/realms/master/protocol/openid-connect/token",
            data={
                "grant_type": "password",
                "client_id": "admin-cli",
                "username": self.config.admin_user,
                "password": self.config.admin_password,
            },
        )
        response.raise_for_status()
        self._access_token = response.json()["access_token"]
        return self._access_token

    def _headers(self) -> dict[str, str]:
        """Get authorization headers."""
        return {
            "Authorization": f"Bearer {self._get_token()}",
            "Content-Type": "application/json",
        }

    def _admin_url(self, path: str) -> str:
        """Build admin API URL."""
        return f"{self.base_url}/admin/realms/{path}"

    def wait_for_ready(self, timeout: int = 120) -> bool:
        """Wait for Keycloak to be ready."""
        print(f"Waiting for Keycloak at {self.base_url}...")
        start = time.time()

        while time.time() - start < timeout:
            try:
                # Use /realms/master as readiness check (always available)
                # /health/ready requires KC_HEALTH_ENABLED=true in newer Keycloak
                response = self.client.get(f"{self.base_url}/realms/master")
                if response.status_code == 200:
                    print("Keycloak is ready!")
                    return True
            except httpx.RequestError:
                pass

            time.sleep(2)
            print(".", end="", flush=True)

        print("\nTimeout waiting for Keycloak")
        return False

    def realm_exists(self, realm: str) -> bool:
        """Check if realm exists."""
        try:
            response = self.client.get(
                self._admin_url(realm),
                headers=self._headers(),
            )
            return response.status_code == 200
        except httpx.RequestError:
            return False

    def create_realm(self, realm: str) -> bool:
        """Create a new realm."""
        if self.realm_exists(realm):
            print(f"Realm '{realm}' already exists")
            return True

        realm_config = {
            "realm": realm,
            "enabled": True,
            "displayName": "SSH Manager",
            "displayNameHtml": "<b>SSH Manager</b>",
            # Token settings
            "accessTokenLifespan": 3600,  # 1 hour
            "ssoSessionIdleTimeout": 1800,  # 30 minutes
            "ssoSessionMaxLifespan": 36000,  # 10 hours
            # OAuth settings
            "oauth2DeviceCodeLifespan": 600,  # 10 minutes
            "oauth2DevicePollingInterval": 5,  # 5 seconds
            # Security settings
            "bruteForceProtected": True,
            "permanentLockout": False,
            "maxFailureWaitSeconds": 900,
            "minimumQuickLoginWaitSeconds": 60,
            "waitIncrementSeconds": 60,
            "quickLoginCheckMilliSeconds": 1000,
            "maxDeltaTimeSeconds": 43200,
            "failureFactor": 5,
        }

        response = self.client.post(
            f"{self.base_url}/admin/realms",
            headers=self._headers(),
            json=realm_config,
        )

        if response.status_code == 201:
            print(f"Created realm '{realm}'")
            return True
        elif response.status_code == 409:
            print(f"Realm '{realm}' already exists")
            return True
        else:
            print(f"Failed to create realm: {response.status_code} - {response.text}")
            return False

    def create_role(self, realm: str, role_name: str, description: str) -> bool:
        """Create a realm role."""
        response = self.client.post(
            self._admin_url(f"{realm}/roles"),
            headers=self._headers(),
            json={
                "name": role_name,
                "description": description,
            },
        )

        if response.status_code == 201:
            print(f"  Created role '{role_name}'")
            return True
        elif response.status_code == 409:
            print(f"  Role '{role_name}' already exists")
            return True
        else:
            print(f"  Failed to create role '{role_name}': {response.text}")
            return False

    def get_client_by_client_id(self, realm: str, client_id: str) -> dict | None:
        """Get client by clientId."""
        response = self.client.get(
            self._admin_url(f"{realm}/clients"),
            headers=self._headers(),
            params={"clientId": client_id},
        )
        response.raise_for_status()
        clients = response.json()
        return clients[0] if clients else None

    def create_api_client(self, realm: str, client_id: str = "sshmgr-api") -> str | None:
        """
        Create the API client (confidential).

        Returns the client secret.
        """
        existing = self.get_client_by_client_id(realm, client_id)
        if existing:
            print(f"  Client '{client_id}' already exists")
            # Get the secret
            secret_response = self.client.get(
                self._admin_url(f"{realm}/clients/{existing['id']}/client-secret"),
                headers=self._headers(),
            )
            if secret_response.status_code == 200:
                return secret_response.json().get("value")
            return None

        client_config = {
            "clientId": client_id,
            "name": "SSH Manager API",
            "description": "Backend API for SSH certificate management",
            "enabled": True,
            "protocol": "openid-connect",
            # Confidential client
            "publicClient": False,
            "clientAuthenticatorType": "client-secret",
            # No direct access (API validates Bearer tokens)
            "directAccessGrantsEnabled": False,
            "standardFlowEnabled": False,
            "implicitFlowEnabled": False,
            "serviceAccountsEnabled": True,
            # Token settings
            "attributes": {
                "access.token.lifespan": "3600",
            },
        }

        response = self.client.post(
            self._admin_url(f"{realm}/clients"),
            headers=self._headers(),
            json=client_config,
        )

        if response.status_code == 201:
            print(f"  Created client '{client_id}'")
            # Get the created client to retrieve secret
            client = self.get_client_by_client_id(realm, client_id)
            if client:
                secret_response = self.client.get(
                    self._admin_url(f"{realm}/clients/{client['id']}/client-secret"),
                    headers=self._headers(),
                )
                if secret_response.status_code == 200:
                    return secret_response.json().get("value")
            return None
        else:
            print(f"  Failed to create client: {response.text}")
            return None

    def create_cli_client(self, realm: str, client_id: str = "sshmgr-cli") -> bool:
        """Create the CLI client (public with device flow)."""
        existing = self.get_client_by_client_id(realm, client_id)
        if existing:
            print(f"  Client '{client_id}' already exists")
            return True

        client_config = {
            "clientId": client_id,
            "name": "SSH Manager CLI",
            "description": "Command-line interface for SSH certificate management",
            "enabled": True,
            "protocol": "openid-connect",
            # Public client (no secret)
            "publicClient": True,
            # Enable device authorization flow
            "standardFlowEnabled": False,
            "implicitFlowEnabled": False,
            "directAccessGrantsEnabled": False,
            "serviceAccountsEnabled": False,
            # Device flow settings
            "attributes": {
                "oauth2.device.authorization.grant.enabled": "true",
                "oauth2.device.polling.interval": "5",
            },
            # Default scopes
            "defaultClientScopes": ["openid", "profile", "email", "roles"],
        }

        response = self.client.post(
            self._admin_url(f"{realm}/clients"),
            headers=self._headers(),
            json=client_config,
        )

        if response.status_code == 201:
            print(f"  Created client '{client_id}'")
            return True
        else:
            print(f"  Failed to create client: {response.text}")
            return False

    def get_group_by_path(self, realm: str, path: str) -> dict | None:
        """Get group by path."""
        response = self.client.get(
            self._admin_url(f"{realm}/group-by-path/{path}"),
            headers=self._headers(),
        )
        if response.status_code == 200:
            return response.json()
        return None

    def create_group(self, realm: str, name: str, parent_id: str | None = None) -> str | None:
        """
        Create a group.

        Returns the group ID.
        """
        if parent_id:
            url = self._admin_url(f"{realm}/groups/{parent_id}/children")
        else:
            url = self._admin_url(f"{realm}/groups")

        response = self.client.post(
            url,
            headers=self._headers(),
            json={"name": name},
        )

        if response.status_code == 201:
            # Extract ID from Location header
            location = response.headers.get("Location", "")
            group_id = location.split("/")[-1] if location else None
            print(f"  Created group '{name}'")
            return group_id
        elif response.status_code == 409:
            print(f"  Group '{name}' already exists")
            # Try to get existing group
            if parent_id:
                # Search in parent's children
                parent = self.client.get(
                    self._admin_url(f"{realm}/groups/{parent_id}"),
                    headers=self._headers(),
                ).json()
                for child in parent.get("subGroups", []):
                    if child["name"] == name:
                        return child["id"]
            else:
                group = self.get_group_by_path(realm, f"/{name}")
                return group["id"] if group else None
            return None
        else:
            print(f"  Failed to create group: {response.text}")
            return None

    def create_user(
        self,
        realm: str,
        username: str,
        password: str,
        email: str,
        roles: list[str],
        groups: list[str],
    ) -> bool:
        """Create a test user with roles and group membership."""
        # Check if user exists
        response = self.client.get(
            self._admin_url(f"{realm}/users"),
            headers=self._headers(),
            params={"username": username},
        )
        users = response.json()
        if users:
            print(f"  User '{username}' already exists")
            return True

        user_config = {
            "username": username,
            "email": email,
            "emailVerified": True,
            "enabled": True,
            "credentials": [
                {
                    "type": "password",
                    "value": password,
                    "temporary": False,
                }
            ],
        }

        response = self.client.post(
            self._admin_url(f"{realm}/users"),
            headers=self._headers(),
            json=user_config,
        )

        if response.status_code != 201:
            print(f"  Failed to create user: {response.text}")
            return False

        print(f"  Created user '{username}'")

        # Get user ID
        location = response.headers.get("Location", "")
        user_id = location.split("/")[-1]

        # Assign roles
        for role_name in roles:
            role_response = self.client.get(
                self._admin_url(f"{realm}/roles/{role_name}"),
                headers=self._headers(),
            )
            if role_response.status_code == 200:
                role = role_response.json()
                self.client.post(
                    self._admin_url(f"{realm}/users/{user_id}/role-mappings/realm"),
                    headers=self._headers(),
                    json=[role],
                )
                print(f"    Assigned role '{role_name}'")

        # Assign groups
        for group_path in groups:
            group = self.get_group_by_path(realm, group_path)
            if group:
                self.client.put(
                    self._admin_url(f"{realm}/users/{user_id}/groups/{group['id']}"),
                    headers=self._headers(),
                )
                print(f"    Added to group '{group_path}'")

        return True

    def add_roles_mapper_to_client(self, realm: str, client_id: str) -> bool:
        """Add realm roles mapper to client scope."""
        # This ensures roles appear in the token
        client = self.get_client_by_client_id(realm, client_id)
        if not client:
            return False

        # Get the roles client scope
        response = self.client.get(
            self._admin_url(f"{realm}/client-scopes"),
            headers=self._headers(),
        )
        scopes = response.json()
        roles_scope = next((s for s in scopes if s["name"] == "roles"), None)

        if roles_scope:
            # Add to default client scopes
            self.client.put(
                self._admin_url(
                    f"{realm}/clients/{client['id']}/default-client-scopes/{roles_scope['id']}"
                ),
                headers=self._headers(),
            )
        return True


def main():
    parser = argparse.ArgumentParser(
        description="Set up Keycloak for sshmgr",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic setup with defaults
  python scripts/keycloak_setup.py

  # With custom URL and create test user
  KEYCLOAK_URL=http://keycloak:8080 python scripts/keycloak_setup.py --create-test-user

  # Skip waiting for Keycloak (if already running)
  python scripts/keycloak_setup.py --no-wait

Environment Variables:
  KEYCLOAK_URL              Keycloak server URL (default: http://localhost:8080)
  KEYCLOAK_ADMIN            Admin username (default: admin)
  KEYCLOAK_ADMIN_PASSWORD   Admin password (default: admin)
  SSHMGR_KEYCLOAK_REALM     Realm name (default: sshmgr)
        """,
    )
    parser.add_argument(
        "--no-wait",
        action="store_true",
        help="Skip waiting for Keycloak to be ready",
    )
    parser.add_argument(
        "--create-test-user",
        action="store_true",
        help="Create a test admin user (testadmin/testadmin)",
    )
    parser.add_argument(
        "--create-environments",
        nargs="*",
        default=["dev", "staging", "prod"],
        help="Environment groups to create (default: dev staging prod)",
    )
    parser.add_argument(
        "--output-env",
        type=str,
        help="Output .env file with client secret",
    )

    args = parser.parse_args()
    config = KeycloakConfig.from_env()
    admin = KeycloakAdmin(config)

    print("=" * 60)
    print("sshmgr Keycloak Setup")
    print("=" * 60)
    print(f"Keycloak URL: {config.url}")
    print(f"Realm: {config.realm}")
    print()

    # Wait for Keycloak
    if not args.no_wait:
        if not admin.wait_for_ready():
            print("ERROR: Keycloak is not available")
            sys.exit(1)
        print()

    # Create realm
    print("Creating realm...")
    if not admin.create_realm(config.realm):
        print("ERROR: Failed to create realm")
        sys.exit(1)
    print()

    # Create roles
    print("Creating roles...")
    roles = [
        ("admin", "Full administrative access - manage environments, rotate CAs, manage policies"),
        ("operator", "Operational access - issue and revoke certificates, view audit logs"),
        ("viewer", "Read-only access - view environments and certificates"),
    ]
    for role_name, description in roles:
        admin.create_role(config.realm, role_name, description)
    print()

    # Create clients
    print("Creating clients...")
    api_secret = admin.create_api_client(config.realm, "sshmgr-api")
    admin.create_cli_client(config.realm, "sshmgr-cli")

    # Add roles mapper to CLI client
    admin.add_roles_mapper_to_client(config.realm, "sshmgr-cli")
    print()

    # Create groups
    print("Creating groups...")
    env_group_id = admin.create_group(config.realm, "environments")

    if env_group_id and args.create_environments:
        for env_name in args.create_environments:
            admin.create_group(config.realm, env_name, parent_id=env_group_id)
    print()

    # Create test user
    if args.create_test_user:
        print("Creating test user...")
        admin.create_user(
            realm=config.realm,
            username="testadmin",
            password="testadmin",
            email="testadmin@example.com",
            roles=["admin"],
            groups=["/environments/dev", "/environments/staging", "/environments/prod"],
        )
        print()

    # Output summary
    print("=" * 60)
    print("Setup Complete!")
    print("=" * 60)
    print()
    print("Clients created:")
    print("  - sshmgr-api (confidential)")
    print("  - sshmgr-cli (public, device flow enabled)")
    print()
    print("Roles created:")
    print("  - admin (full access)")
    print("  - operator (certificate operations)")
    print("  - viewer (read-only)")
    print()
    print("Groups created:")
    print("  - /environments")
    for env_name in args.create_environments or []:
        print(f"    - /environments/{env_name}")
    print()

    if api_secret:
        print("API Client Secret:")
        print(f"  {api_secret}")
        print()
        print("Add to your .env file:")
        print(f"  SSHMGR_KEYCLOAK_CLIENT_SECRET={api_secret}")
        print()

        if args.output_env:
            with open(args.output_env, "a") as f:
                f.write("\n# Keycloak configuration (generated by keycloak_setup.py)\n")
                f.write(f"SSHMGR_KEYCLOAK_URL={config.url}\n")
                f.write(f"SSHMGR_KEYCLOAK_REALM={config.realm}\n")
                f.write("SSHMGR_KEYCLOAK_CLIENT_ID=sshmgr-api\n")
                f.write(f"SSHMGR_KEYCLOAK_CLIENT_SECRET={api_secret}\n")
            print(f"Configuration appended to {args.output_env}")
            print()

    if args.create_test_user:
        print("Test User:")
        print("  Username: testadmin")
        print("  Password: testadmin")
        print("  Roles: admin")
        print("  Groups: /environments/dev, /environments/staging, /environments/prod")
        print()

    print("Next steps:")
    print("  1. Set SSHMGR_KEYCLOAK_CLIENT_SECRET in your environment")
    print("  2. Start the API: make run-api")
    print("  3. Login via CLI: sshmgr login")
    print()
    print("Keycloak Admin Console:")
    print(f"  {config.url}/admin/master/console/#/{config.realm}")


if __name__ == "__main__":
    main()
