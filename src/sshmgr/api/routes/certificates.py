"""Certificate management API endpoints."""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Path, Query, status

from sshmgr.api.dependencies import (
    get_cert_repository,
    get_env_repository,
    get_environment_by_name,
    get_key_storage,
    parse_validity,
    require_env_operator,
    require_env_viewer,
)
from sshmgr.api.schemas import (
    CertificateListResponse,
    CertificateResponse,
    CertTypeEnum,
    HostCertificateRequest,
    RevokeRequest,
    UserCertificateRequest,
)
from sshmgr.auth.rbac import AuthContext
from sshmgr.core.ca import CertificateAuthority
from sshmgr.core.exceptions import InvalidKeyError, SigningError
from sshmgr.keys.encrypted import EncryptedKeyStorage
from sshmgr.storage.models import CertType, Certificate, Environment
from sshmgr.storage.repositories import CertificateRepository, EnvironmentRepository

router = APIRouter()


def certificate_to_response(
    cert: Certificate, include_certificate: bool = False
) -> CertificateResponse:
    """Convert Certificate model to response schema."""
    return CertificateResponse(
        id=cert.id,
        serial=cert.serial,
        cert_type=CertTypeEnum(cert.cert_type.value),
        key_id=cert.key_id,
        principals=cert.principals,
        valid_after=cert.valid_after,
        valid_before=cert.valid_before,
        public_key_fingerprint=cert.public_key_fingerprint,
        certificate=None,  # Not stored, only returned when signing
        issued_at=cert.issued_at,
        issued_by=cert.issued_by,
        revoked_at=cert.revoked_at,
        revoked_by=cert.revoked_by,
        revocation_reason=cert.revocation_reason,
    )


@router.get(
    "",
    response_model=CertificateListResponse,
    summary="List certificates",
    description="List certificates issued for an environment.",
)
async def list_certificates(
    env_name: Annotated[str, Path(description="Environment name")],
    env: Annotated[Environment, Depends(get_environment_by_name)],
    auth: Annotated[AuthContext, Depends(require_env_viewer)],
    cert_repo: Annotated[CertificateRepository, Depends(get_cert_repository)],
    cert_type: Annotated[
        CertTypeEnum | None, Query(description="Filter by certificate type")
    ] = None,
    include_expired: Annotated[
        bool, Query(description="Include expired certificates")
    ] = False,
    include_revoked: Annotated[
        bool, Query(description="Include revoked certificates")
    ] = True,
    limit: Annotated[int, Query(ge=1, le=500, description="Maximum results")] = 100,
    offset: Annotated[int, Query(ge=0, description="Offset for pagination")] = 0,
) -> CertificateListResponse:
    """List certificates for an environment."""
    type_filter = CertType(cert_type.value) if cert_type else None

    certs = await cert_repo.list_by_environment(
        environment_id=env.id,
        cert_type=type_filter,
        include_expired=include_expired,
        include_revoked=include_revoked,
        limit=limit,
        offset=offset,
    )

    total = await cert_repo.count_by_environment(env.id, type_filter)

    return CertificateListResponse(
        certificates=[certificate_to_response(c) for c in certs],
        total=total,
    )


@router.post(
    "/user",
    response_model=CertificateResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Sign user certificate",
    description="Sign a user's public key to create an SSH certificate.",
)
async def sign_user_certificate(
    env_name: Annotated[str, Path(description="Environment name")],
    request: UserCertificateRequest,
    env: Annotated[Environment, Depends(get_environment_by_name)],
    auth: Annotated[AuthContext, Depends(require_env_operator)],
    cert_repo: Annotated[CertificateRepository, Depends(get_cert_repository)],
    key_storage: Annotated[EncryptedKeyStorage, Depends(get_key_storage)],
) -> CertificateResponse:
    """Sign a user certificate."""
    # Parse validity or use default
    if request.validity:
        cert_validity = parse_validity(request.validity)
    else:
        cert_validity = env.default_user_cert_validity

    # Load CA
    try:
        ca_private_key = key_storage.retrieve_key(env.user_ca_key_ref)
        ca = CertificateAuthority.from_private_key(ca_private_key)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to load CA: {e}",
        )

    # Get next serial
    serial = await cert_repo.get_max_serial(env.id) + 1

    # Sign certificate
    try:
        signed_cert = ca.sign_user_key(
            public_key=request.public_key,
            principals=request.principals,
            key_id=request.key_id,
            validity=cert_validity,
            serial=serial,
            force_command=request.force_command,
        )
    except InvalidKeyError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid public key: {e}",
        )
    except SigningError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Signing failed: {e}",
        )

    # Get public key fingerprint
    pub_key_fingerprint = CertificateAuthority.get_public_key_fingerprint(
        request.public_key
    )

    # Record in database
    cert = await cert_repo.create(
        environment_id=env.id,
        cert_type=CertType.USER,
        serial=signed_cert.serial,
        key_id=request.key_id,
        principals=request.principals,
        valid_after=signed_cert.valid_after,
        valid_before=signed_cert.valid_before,
        public_key_fingerprint=pub_key_fingerprint,
        issued_by=auth.username,
    )

    # Build response with certificate content
    response = certificate_to_response(cert)
    response.certificate = signed_cert.certificate
    return response


@router.post(
    "/host",
    response_model=CertificateResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Sign host certificate",
    description="Sign a host's public key to create an SSH host certificate.",
)
async def sign_host_certificate(
    env_name: Annotated[str, Path(description="Environment name")],
    request: HostCertificateRequest,
    env: Annotated[Environment, Depends(get_environment_by_name)],
    auth: Annotated[AuthContext, Depends(require_env_operator)],
    cert_repo: Annotated[CertificateRepository, Depends(get_cert_repository)],
    key_storage: Annotated[EncryptedKeyStorage, Depends(get_key_storage)],
) -> CertificateResponse:
    """Sign a host certificate."""
    # Parse validity or use default
    if request.validity:
        cert_validity = parse_validity(request.validity)
    else:
        cert_validity = env.default_host_cert_validity

    # Load CA
    try:
        ca_private_key = key_storage.retrieve_key(env.host_ca_key_ref)
        ca = CertificateAuthority.from_private_key(ca_private_key)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to load CA: {e}",
        )

    # Get next serial
    serial = await cert_repo.get_max_serial(env.id) + 1

    # Sign certificate
    try:
        signed_cert = ca.sign_host_key(
            public_key=request.public_key,
            principals=request.principals,
            validity=cert_validity,
            serial=serial,
        )
    except InvalidKeyError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid public key: {e}",
        )
    except SigningError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Signing failed: {e}",
        )

    # Get public key fingerprint
    pub_key_fingerprint = CertificateAuthority.get_public_key_fingerprint(
        request.public_key
    )

    # Record in database
    cert = await cert_repo.create(
        environment_id=env.id,
        cert_type=CertType.HOST,
        serial=signed_cert.serial,
        key_id=signed_cert.key_id,
        principals=request.principals,
        valid_after=signed_cert.valid_after,
        valid_before=signed_cert.valid_before,
        public_key_fingerprint=pub_key_fingerprint,
        issued_by=auth.username,
    )

    # Build response with certificate content
    response = certificate_to_response(cert)
    response.certificate = signed_cert.certificate
    return response


@router.get(
    "/{serial}",
    response_model=CertificateResponse,
    summary="Get certificate",
    description="Get details of a specific certificate by serial number.",
)
async def get_certificate(
    env_name: Annotated[str, Path(description="Environment name")],
    serial: Annotated[int, Path(description="Certificate serial number")],
    env: Annotated[Environment, Depends(get_environment_by_name)],
    auth: Annotated[AuthContext, Depends(require_env_viewer)],
    cert_repo: Annotated[CertificateRepository, Depends(get_cert_repository)],
) -> CertificateResponse:
    """Get certificate details."""
    cert = await cert_repo.get_by_serial(env.id, serial)
    if not cert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Certificate with serial {serial} not found",
        )

    return certificate_to_response(cert)


@router.delete(
    "/{serial}",
    response_model=CertificateResponse,
    summary="Revoke certificate",
    description="Revoke a certificate. Note: Revocation requires distributing a KRL to SSH servers.",
)
async def revoke_certificate(
    env_name: Annotated[str, Path(description="Environment name")],
    serial: Annotated[int, Path(description="Certificate serial number")],
    env: Annotated[Environment, Depends(get_environment_by_name)],
    auth: Annotated[AuthContext, Depends(require_env_operator)],
    cert_repo: Annotated[CertificateRepository, Depends(get_cert_repository)],
    request: RevokeRequest | None = None,
) -> CertificateResponse:
    """Revoke a certificate."""
    cert = await cert_repo.get_by_serial(env.id, serial)
    if not cert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Certificate with serial {serial} not found",
        )

    if cert.revoked_at:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Certificate {serial} is already revoked",
        )

    reason = request.reason if request else None
    cert = await cert_repo.revoke(
        cert_id=cert.id,
        revoked_by=auth.username,
        reason=reason,
    )

    return certificate_to_response(cert)


@router.get(
    "/by-key-id/{key_id}",
    response_model=CertificateListResponse,
    summary="Find certificates by key ID",
    description="Find all certificates issued to a specific key ID (e.g., email).",
)
async def find_certificates_by_key_id(
    env_name: Annotated[str, Path(description="Environment name")],
    key_id: Annotated[str, Path(description="Key identifier to search for")],
    env: Annotated[Environment, Depends(get_environment_by_name)],
    auth: Annotated[AuthContext, Depends(require_env_viewer)],
    cert_repo: Annotated[CertificateRepository, Depends(get_cert_repository)],
) -> CertificateListResponse:
    """Find certificates by key ID."""
    certs = await cert_repo.list_by_key_id(key_id, environment_id=env.id)

    return CertificateListResponse(
        certificates=[certificate_to_response(c) for c in certs],
        total=len(certs),
    )
