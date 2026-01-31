"""Environment management API endpoints."""

from __future__ import annotations

from typing import Annotated
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Path, Query, status

from sshmgr.api.dependencies import (
    format_timedelta,
    get_cert_repository,
    get_env_repository,
    get_environment_by_name,
    get_key_storage,
    parse_validity,
    require_env_admin,
    require_env_viewer,
)
from sshmgr.api.schemas import (
    CAPublicKeyResponse,
    CertTypeEnum,
    EnvironmentCreate,
    EnvironmentListResponse,
    EnvironmentResponse,
    RotateCARequest,
    RotationStatusResponse,
    CARotationInfo,
)
from sshmgr.auth.rbac import AuthContext, get_current_user, Role, RequireRole
from sshmgr.core.ca import CertificateAuthority, KeyType
from sshmgr.keys.encrypted import EncryptedKeyStorage
from sshmgr.storage.models import Environment
from sshmgr.storage.repositories import EnvironmentRepository

router = APIRouter()


def environment_to_response(env: Environment) -> EnvironmentResponse:
    """Convert Environment model to response schema."""
    return EnvironmentResponse(
        id=env.id,
        name=env.name,
        user_ca_fingerprint=CertificateAuthority.get_public_key_fingerprint(
            env.user_ca_public_key
        ),
        host_ca_fingerprint=CertificateAuthority.get_public_key_fingerprint(
            env.host_ca_public_key
        ),
        default_user_cert_validity=format_timedelta(env.default_user_cert_validity),
        default_host_cert_validity=format_timedelta(env.default_host_cert_validity),
        created_at=env.created_at,
        updated_at=env.updated_at,
        has_old_user_ca=env.old_user_ca_public_key is not None,
        has_old_host_ca=env.old_host_ca_public_key is not None,
    )


@router.get(
    "",
    response_model=EnvironmentListResponse,
    summary="List environments",
    description="List all environments the user has access to.",
)
async def list_environments(
    auth: Annotated[AuthContext, Depends(get_current_user)],
    env_repo: Annotated[EnvironmentRepository, Depends(get_env_repository)],
) -> EnvironmentListResponse:
    """List all environments."""
    all_envs = await env_repo.list_all()

    # Filter by access (admins see all)
    if auth.has_role(Role.ADMIN):
        envs = all_envs
    else:
        accessible = set(auth.get_accessible_environments())
        envs = [e for e in all_envs if e.name in accessible]

    return EnvironmentListResponse(
        environments=[environment_to_response(e) for e in envs],
        total=len(envs),
    )


@router.post(
    "",
    response_model=EnvironmentResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create environment",
    description="Create a new environment with CA keypairs. Requires admin role.",
)
async def create_environment(
    request: EnvironmentCreate,
    auth: Annotated[AuthContext, Depends(get_current_user)],
    _: Annotated[None, Depends(RequireRole(Role.ADMIN))],
    env_repo: Annotated[EnvironmentRepository, Depends(get_env_repository)],
    key_storage: Annotated[EncryptedKeyStorage, Depends(get_key_storage)],
) -> EnvironmentResponse:
    """Create a new environment."""
    # Check if environment already exists
    existing = await env_repo.get_by_name(request.name)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Environment '{request.name}' already exists",
        )

    # Parse validity periods
    user_cert_validity = parse_validity(request.default_user_cert_validity)
    host_cert_validity = parse_validity(request.default_host_cert_validity)

    # Generate CA keypairs
    key_type = KeyType(request.key_type.value)
    user_ca = CertificateAuthority.generate(key_type=key_type)
    host_ca = CertificateAuthority.generate(key_type=key_type)

    # Encrypt and store private keys
    temp_id = uuid4()
    user_ca_key_ref = key_storage.store_key(temp_id, "user_ca", user_ca.private_key)
    host_ca_key_ref = key_storage.store_key(temp_id, "host_ca", host_ca.private_key)

    # Create environment
    env = await env_repo.create(
        name=request.name,
        user_ca_public_key=user_ca.public_key,
        user_ca_key_ref=user_ca_key_ref,
        host_ca_public_key=host_ca.public_key,
        host_ca_key_ref=host_ca_key_ref,
        default_user_cert_validity=user_cert_validity,
        default_host_cert_validity=host_cert_validity,
    )

    return environment_to_response(env)


@router.get(
    "/{env_name}",
    response_model=EnvironmentResponse,
    summary="Get environment",
    description="Get details of a specific environment.",
)
async def get_environment(
    env: Annotated[Environment, Depends(get_environment_by_name)],
    auth: Annotated[AuthContext, Depends(require_env_viewer)],
) -> EnvironmentResponse:
    """Get environment details."""
    return environment_to_response(env)


@router.delete(
    "/{env_name}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete environment",
    description="Delete an environment and its CA keys. Requires admin role.",
)
async def delete_environment(
    env_name: Annotated[str, Path(description="Environment name")],
    env: Annotated[Environment, Depends(get_environment_by_name)],
    auth: Annotated[AuthContext, Depends(require_env_admin)],
    env_repo: Annotated[EnvironmentRepository, Depends(get_env_repository)],
) -> None:
    """Delete an environment."""
    deleted = await env_repo.delete(env.id)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete environment",
        )


@router.get(
    "/{env_name}/ca/{ca_type}",
    response_model=CAPublicKeyResponse,
    summary="Get CA public key",
    description="Get the CA public key for an environment.",
)
async def get_ca_public_key(
    env_name: Annotated[str, Path(description="Environment name")],
    ca_type: Annotated[CertTypeEnum, Path(description="CA type (user or host)")],
    env: Annotated[Environment, Depends(get_environment_by_name)],
    auth: Annotated[AuthContext, Depends(require_env_viewer)],
    include_old: Annotated[
        bool, Query(description="Include old CA if rotation is in progress")
    ] = False,
) -> CAPublicKeyResponse:
    """Get CA public key."""
    if ca_type == CertTypeEnum.USER:
        public_key = env.user_ca_public_key
        old_public_key = env.old_user_ca_public_key if include_old else None
        old_expires = env.old_user_ca_expires_at
    else:
        public_key = env.host_ca_public_key
        old_public_key = env.old_host_ca_public_key if include_old else None
        old_expires = env.old_host_ca_expires_at

    return CAPublicKeyResponse(
        environment=env_name,
        ca_type=ca_type,
        public_key=public_key,
        fingerprint=CertificateAuthority.get_public_key_fingerprint(public_key),
        old_public_key=old_public_key,
        old_fingerprint=(
            CertificateAuthority.get_public_key_fingerprint(old_public_key)
            if old_public_key
            else None
        ),
        old_expires_at=old_expires,
    )


@router.post(
    "/{env_name}/rotate",
    response_model=RotationStatusResponse,
    summary="Rotate CA",
    description="Rotate a CA key with a grace period. Requires admin role.",
)
async def rotate_ca(
    env_name: Annotated[str, Path(description="Environment name")],
    request: RotateCARequest,
    env: Annotated[Environment, Depends(get_environment_by_name)],
    auth: Annotated[AuthContext, Depends(require_env_admin)],
    env_repo: Annotated[EnvironmentRepository, Depends(get_env_repository)],
    key_storage: Annotated[EncryptedKeyStorage, Depends(get_key_storage)],
) -> RotationStatusResponse:
    """Rotate a CA key."""
    grace_td = parse_validity(request.grace_period)
    key_type = KeyType(request.key_type.value)

    # Generate new CA
    new_ca = CertificateAuthority.generate(key_type=key_type)
    new_key_ref = key_storage.store_key(
        env.id, f"{request.ca_type.value}_ca", new_ca.private_key
    )

    # Perform rotation
    if request.ca_type == CertTypeEnum.USER:
        env = await env_repo.rotate_user_ca(
            env_id=env.id,
            new_public_key=new_ca.public_key,
            new_key_ref=new_key_ref,
            grace_period=grace_td,
        )
    else:
        env = await env_repo.rotate_host_ca(
            env_id=env.id,
            new_public_key=new_ca.public_key,
            new_key_ref=new_key_ref,
            grace_period=grace_td,
        )

    # Return updated status
    return RotationStatusResponse(
        environment=env_name,
        user_ca=CARotationInfo(
            rotating=env.old_user_ca_public_key is not None,
            fingerprint=CertificateAuthority.get_public_key_fingerprint(
                env.user_ca_public_key
            ),
            old_fingerprint=(
                CertificateAuthority.get_public_key_fingerprint(
                    env.old_user_ca_public_key
                )
                if env.old_user_ca_public_key
                else None
            ),
            old_expires_at=env.old_user_ca_expires_at,
        ),
        host_ca=CARotationInfo(
            rotating=env.old_host_ca_public_key is not None,
            fingerprint=CertificateAuthority.get_public_key_fingerprint(
                env.host_ca_public_key
            ),
            old_fingerprint=(
                CertificateAuthority.get_public_key_fingerprint(
                    env.old_host_ca_public_key
                )
                if env.old_host_ca_public_key
                else None
            ),
            old_expires_at=env.old_host_ca_expires_at,
        ),
    )


@router.get(
    "/{env_name}/rotation-status",
    response_model=RotationStatusResponse,
    summary="Get rotation status",
    description="Get the CA rotation status for an environment.",
)
async def get_rotation_status(
    env_name: Annotated[str, Path(description="Environment name")],
    env: Annotated[Environment, Depends(get_environment_by_name)],
    auth: Annotated[AuthContext, Depends(require_env_viewer)],
) -> RotationStatusResponse:
    """Get CA rotation status."""
    return RotationStatusResponse(
        environment=env_name,
        user_ca=CARotationInfo(
            rotating=env.old_user_ca_public_key is not None,
            fingerprint=CertificateAuthority.get_public_key_fingerprint(
                env.user_ca_public_key
            ),
            old_fingerprint=(
                CertificateAuthority.get_public_key_fingerprint(
                    env.old_user_ca_public_key
                )
                if env.old_user_ca_public_key
                else None
            ),
            old_expires_at=env.old_user_ca_expires_at,
        ),
        host_ca=CARotationInfo(
            rotating=env.old_host_ca_public_key is not None,
            fingerprint=CertificateAuthority.get_public_key_fingerprint(
                env.host_ca_public_key
            ),
            old_fingerprint=(
                CertificateAuthority.get_public_key_fingerprint(
                    env.old_host_ca_public_key
                )
                if env.old_host_ca_public_key
                else None
            ),
            old_expires_at=env.old_host_ca_expires_at,
        ),
    )
