// Enums matching backend
export type CertType = "user" | "host";
export type KeyType = "ed25519" | "rsa" | "ecdsa";

// Environment types
export interface Environment {
  id: string;
  name: string;
  user_ca_fingerprint: string;
  host_ca_fingerprint: string;
  default_user_cert_validity: string;
  default_host_cert_validity: string;
  created_at: string;
  updated_at: string | null;
  has_old_user_ca: boolean;
  has_old_host_ca: boolean;
}

export interface EnvironmentCreate {
  name: string;
  key_type?: KeyType;
  default_user_cert_validity?: string;
  default_host_cert_validity?: string;
}

export interface EnvironmentListResponse {
  environments: Environment[];
  total: number;
}

export interface CAPublicKeyResponse {
  environment: string;
  ca_type: CertType;
  public_key: string;
  fingerprint: string;
  old_public_key?: string | null;
  old_fingerprint?: string | null;
  old_expires_at?: string | null;
}

// Certificate types
export interface Certificate {
  id: string;
  serial: number;
  cert_type: CertType;
  key_id: string;
  principals: string[];
  valid_after: string;
  valid_before: string;
  public_key_fingerprint: string;
  certificate?: string | null;
  issued_at: string;
  issued_by: string;
  revoked_at?: string | null;
  revoked_by?: string | null;
  revocation_reason?: string | null;
}

export interface CertificateListResponse {
  certificates: Certificate[];
  total: number;
}

export interface CertificateListParams {
  cert_type?: CertType;
  include_expired?: boolean;
  include_revoked?: boolean;
  limit?: number;
  offset?: number;
}

export interface UserCertificateRequest {
  public_key: string;
  principals: string[];
  key_id: string;
  validity?: string;
  force_command?: string;
}

export interface HostCertificateRequest {
  public_key: string;
  principals: string[];
  validity?: string;
}

export interface RevokeRequest {
  reason?: string;
}

// CA Rotation types
export interface RotateCARequest {
  ca_type: CertType;
  grace_period?: string;
  key_type?: KeyType;
}

export interface CARotationInfo {
  rotating: boolean;
  fingerprint: string;
  old_fingerprint?: string | null;
  old_expires_at?: string | null;
}

export interface RotationStatusResponse {
  environment: string;
  user_ca: CARotationInfo;
  host_ca: CARotationInfo;
}

// Health types
export interface HealthResponse {
  status: string;
  version: string;
  timestamp: string;
}

export interface ReadinessResponse {
  status: string;
  database: string;
  keycloak: string;
}

// Error types
export interface APIError {
  detail: string;
  code?: string;
}

// Computed certificate status
export type CertificateStatus = "valid" | "expired" | "revoked";

export function getCertificateStatus(cert: Certificate): CertificateStatus {
  if (cert.revoked_at) return "revoked";
  if (new Date(cert.valid_before) < new Date()) return "expired";
  return "valid";
}
