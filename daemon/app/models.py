"""
Pydantic models for API request/response schemas.
"""

from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum


# ──────────────────────────────────────
# Enums
# ──────────────────────────────────────

class CertificateMode(str, Enum):
    SHARED = "shared"
    PER_NODE = "per-node"


class ACMEProviderType(str, Enum):
    DIGICERT = "digicert"
    LETSENCRYPT = "letsencrypt"


class DNSProviderType(str, Enum):
    CLOUDFLARE = "cloudflare"
    AWS_ROUTE53 = "aws_route53"
    AZURE_DNS = "azure_dns"
    OVHCLOUD = "ovhcloud"


class ActionType(str, Enum):
    CHECK = "check"
    RENEW = "renew"
    FORCE_RENEW = "force-renew"


# ──────────────────────────────────────
# Settings Models
# ──────────────────────────────────────

class ISESettings(BaseModel):
    ise_host: str = Field(..., description="ISE PAN hostname or IP")
    ise_username: str = Field(..., description="ISE admin username")
    ise_password: str = Field(..., description="ISE admin password")
    ise_ers_port: int = Field(9060, description="ISE ERS API port")
    ise_open_api_port: int = Field(443, description="ISE Open API port")


class ISETestSettings(BaseModel):
    ise_host: Optional[str] = Field(None, description="ISE PAN hostname or IP")
    ise_username: Optional[str] = Field(None, description="ISE admin username")
    ise_password: Optional[str] = Field(None, description="ISE admin password (falls back to saved if omitted)")
    ise_ers_port: Optional[int] = Field(None, description="ISE ERS API port")
    ise_open_api_port: Optional[int] = Field(None, description="ISE Open API port")


class ACMESettings(BaseModel):
    """Legacy single-provider settings — kept for backwards compatibility."""
    acme_provider: ACMEProviderType = Field(
        ACMEProviderType.DIGICERT,
        description="ACME provider (digicert or letsencrypt)"
    )
    acme_directory_url: str = Field(
        "https://acme.digicert.com/v2/acme/directory/",
        description="ACME directory URL"
    )
    acme_kid: Optional[str] = Field(None, description="ACME Key ID (DigiCert)")
    acme_hmac_key: Optional[str] = Field(None, description="ACME HMAC Key (DigiCert)")
    acme_account_email: Optional[str] = Field(None, description="Account email (LetsEncrypt)")


class ACMEProviderCreate(BaseModel):
    name: str = Field(..., description="User-friendly label (unique)")
    provider_type: ACMEProviderType = Field(..., description="Provider type")
    directory_url: str = Field(..., description="ACME directory URL")
    kid: Optional[str] = Field(None, description="Key ID (DigiCert)")
    hmac_key: Optional[str] = Field(None, description="HMAC key (DigiCert)")
    account_email: Optional[str] = Field(None, description="Account email (LetsEncrypt)")
    account_key: Optional[str] = Field(None, description="Account private key PEM (LetsEncrypt)")
    dns_provider_id: Optional[int] = Field(None, description="DNS provider used for DNS-01 challenge")


class ACMEProviderUpdate(BaseModel):
    name: Optional[str] = None
    provider_type: Optional[ACMEProviderType] = None
    directory_url: Optional[str] = None
    kid: Optional[str] = None
    hmac_key: Optional[str] = None
    account_email: Optional[str] = None
    account_key: Optional[str] = None
    dns_provider_id: Optional[int] = None


class ACMEProviderResponse(BaseModel):
    id: int
    name: str
    provider_type: str
    directory_url: str
    kid: Optional[str] = None
    hmac_key: Optional[str] = None
    account_email: Optional[str] = None
    has_account_key: bool = False
    dns_provider_id: Optional[int] = None
    dns_provider_name: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class DNSProviderCreate(BaseModel):
    name: str = Field(..., description="User-friendly label (unique)")
    provider_type: DNSProviderType = Field(..., description="DNS provider type")
    config: Dict[str, Any] = Field(default_factory=dict, description="Provider-specific configuration values")


class DNSProviderUpdate(BaseModel):
    name: Optional[str] = None
    provider_type: Optional[DNSProviderType] = None
    config: Optional[Dict[str, Any]] = None


class DNSProviderResponse(BaseModel):
    id: int
    name: str
    provider_type: str
    config: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class CertificateSettings(BaseModel):
    common_name: str = Field(..., description="Certificate Common Name")
    san_names: List[str] = Field(default_factory=list, description="Subject Alternative Names")
    key_type: str = Field("RSA_2048", description="Key type")
    portal_group_tag: str = Field(
        "Default Portal Certificate Group",
        description="ISE Portal Group Tag"
    )
    certificate_mode: CertificateMode = Field(
        CertificateMode.SHARED,
        description="Certificate mode"
    )
    renewal_threshold_days: int = Field(30, description="Days before expiry to trigger renewal")


class DNSSettings(BaseModel):
    dns_provider: DNSProviderType = Field(DNSProviderType.CLOUDFLARE, description="DNS provider")
    cloudflare_api_token: Optional[str] = Field(None, description="Cloudflare API token")
    cloudflare_zone_id: Optional[str] = Field(None, description="Cloudflare Zone ID")
    aws_hosted_zone_id: Optional[str] = Field(None, description="AWS Route53 Hosted Zone ID")
    aws_region: Optional[str] = Field("us-east-1", description="AWS Region")
    azure_subscription_id: Optional[str] = Field(None, description="Azure Subscription ID")
    azure_resource_group: Optional[str] = Field(None, description="Azure Resource Group")
    azure_dns_zone_name: Optional[str] = Field(None, description="Azure DNS Zone Name")
    ovh_endpoint: Optional[str] = Field("ovh-eu", description="OVHcloud API endpoint")
    ovh_application_key: Optional[str] = Field(None, description="OVHcloud Application Key")
    ovh_application_secret: Optional[str] = Field(None, description="OVHcloud Application Secret")
    ovh_consumer_key: Optional[str] = Field(None, description="OVHcloud Consumer Key")
    ovh_dns_zone: Optional[str] = Field(None, description="OVHcloud DNS Zone")


class SMTPSettings(BaseModel):
    smtp_server: Optional[str] = Field(None, description="SMTP server hostname")
    smtp_port: int = Field(587, description="SMTP port")
    smtp_username: Optional[str] = Field(None, description="SMTP username")
    smtp_password: Optional[str] = Field(None, description="SMTP password")
    alert_recipients: List[str] = Field(default_factory=list, description="Alert recipients")


class SchedulerSettings(BaseModel):
    scheduler_enabled: bool = Field(True, description="Enable automatic scheduling")
    scheduler_cron_hour: int = Field(2, description="Hour to run (0-23)")
    scheduler_cron_minute: int = Field(0, description="Minute to run (0-59)")
    scheduler_interval_hours: int = Field(24, description="Interval between runs")


class AllSettings(BaseModel):
    ise: ISESettings
    acme: ACMESettings
    certificate: CertificateSettings
    dns: DNSSettings
    smtp: SMTPSettings
    scheduler: SchedulerSettings


# ──────────────────────────────────────
# Node Models
# ──────────────────────────────────────

class ISENodeCreate(BaseModel):
    name: str
    role: str = "PSN"
    enabled: bool = True
    is_primary: bool = False


class ISENodeResponse(BaseModel):
    id: int
    name: str
    role: str
    enabled: bool
    is_primary: bool
    last_cert_check: Optional[datetime] = None
    cert_expiry_date: Optional[datetime] = None
    cert_days_remaining: Optional[int] = None
    cert_status: str = "unknown"

    class Config:
        from_attributes = True


# ──────────────────────────────────────
# Discovery Models
# ──────────────────────────────────────

class DiscoveredNode(BaseModel):
    ers_id: str
    name: str
    fqdn: str
    roles: List[str]
    is_primary_pan: bool


class DiscoverNodesResponse(BaseModel):
    nodes: List[DiscoveredNode]
    total: int
    psn_count: int


class SystemCertificateInfo(BaseModel):
    id: str
    friendly_name: str
    subject: str
    issuer: Optional[str] = None
    expiration_date: Optional[str] = None
    used_by: Optional[str] = None
    key_type: Optional[str] = None
    node_name: Optional[str] = None
    node_id: Optional[int] = None
    san_names: List[str] = Field(default_factory=list)
    portal_group_tag: Optional[str] = None


class InspectedCertificate(BaseModel):
    """
    Fully-parsed view of a certificate exported from ISE.

    Returned by ``GET /api/v1/settings/certificates/{node_id}/{cert_id}/inspect``
    so the frontend can pre-populate a new managed certificate with the same
    subject, SANs, key type, extensions, etc.
    """
    # Core identification
    common_name: str = ""
    subject_dn: str = ""
    subject: Dict[str, Any] = Field(default_factory=dict)
    issuer_dn: str = ""
    issuer: Dict[str, Any] = Field(default_factory=dict)
    serial_number: Optional[str] = None

    # Validity
    not_before: Optional[str] = None
    not_after: Optional[str] = None

    # Key material
    key_type: str = "RSA_2048"
    public_key: Dict[str, Any] = Field(default_factory=dict)
    signature_algorithm: Optional[str] = None
    version: Optional[str] = None

    # Extensions
    san_names: List[str] = Field(default_factory=list)
    san: Dict[str, List[str]] = Field(default_factory=dict)
    key_usage: List[str] = Field(default_factory=list)
    extended_key_usage: List[str] = Field(default_factory=list)
    basic_constraints: Optional[Dict[str, Any]] = None

    # Fingerprints
    fingerprint_sha1: Optional[str] = None
    fingerprint_sha256: Optional[str] = None

    # ISE-side metadata echoed back for convenience
    source_cert_id: Optional[str] = None
    source_node_id: Optional[int] = None
    source_node_name: Optional[str] = None
    friendly_name: Optional[str] = None
    portal_group_tag: Optional[str] = None


# ──────────────────────────────────────
# Status Models
# ──────────────────────────────────────

class DaemonStatusResponse(BaseModel):
    state: str
    current_action: Optional[str] = None
    last_run_at: Optional[datetime] = None
    last_run_status: Optional[str] = None
    next_run_at: Optional[datetime] = None
    uptime_since: datetime
    total_renewals: int = 0
    successful_renewals: int = 0
    failed_renewals: int = 0
    last_error: Optional[str] = None
    version: str
    nodes: List[ISENodeResponse] = []
    scheduler_enabled: bool = True

    class Config:
        from_attributes = True


# ──────────────────────────────────────
# History Models
# ──────────────────────────────────────

class RenewalHistoryResponse(BaseModel):
    id: int
    run_id: str
    status: str
    mode: str
    trigger: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[float] = None
    common_name: Optional[str] = None
    node_results: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None
    dns_challenge_created: bool = False
    dns_challenge_cleaned: bool = False
    notification_sent: bool = False

    class Config:
        from_attributes = True


class RenewalHistoryList(BaseModel):
    total: int
    page: int
    page_size: int
    items: List[RenewalHistoryResponse]


# ──────────────────────────────────────
# Action Models
# ──────────────────────────────────────

class ActionRequest(BaseModel):
    action: ActionType
    mode_override: Optional[CertificateMode] = None


class ActionResponse(BaseModel):
    message: str
    run_id: Optional[str] = None
    status: str


# ──────────────────────────────────────
# General
# ──────────────────────────────────────

class HealthResponse(BaseModel):
    status: str
    version: str
    uptime_seconds: float
    database: str
    scheduler: str


class MessageResponse(BaseModel):
    message: str
    success: bool = True


# ──────────────────────────────────────
# Managed Certificate Models
# ──────────────────────────────────────

class ManagedCertificateCreate(BaseModel):
    common_name: str = Field(..., description="Certificate Common Name")
    san_names: List[str] = Field(default_factory=list)
    key_type: str = Field("RSA_2048")
    subject: Dict[str, Any] = Field(
        default_factory=dict,
        description="Additional subject DN components (O, OU, C, ST, L, …) preserved at renewal time",
    )
    portal_group_tag: str = Field("Default Portal Certificate Group")
    certificate_mode: CertificateMode = Field(CertificateMode.SHARED)
    renewal_threshold_days: int = Field(30)
    enabled: bool = Field(True)
    acme_provider_id: Optional[int] = Field(None, description="ACME provider to use for renewal")
    node_ids: List[int] = Field(default_factory=list, description="ISE node IDs to assign")


class ManagedCertificateUpdate(BaseModel):
    common_name: Optional[str] = None
    san_names: Optional[List[str]] = None
    key_type: Optional[str] = None
    subject: Optional[Dict[str, Any]] = None
    portal_group_tag: Optional[str] = None
    certificate_mode: Optional[CertificateMode] = None
    renewal_threshold_days: Optional[int] = None
    enabled: Optional[bool] = None
    acme_provider_id: Optional[int] = None
    node_ids: Optional[List[int]] = None


class CertificateRequestPayload(BaseModel):
    """
    Payload for the direct "request and push" flow (Settings → Certificates →
    Request New Certificate). Unlike ManagedCertificateCreate which just
    persists a renewal schedule, this triggers the full ACME + ISE flow
    immediately and streams live log output back to the caller.
    """
    common_name: str = Field(..., description="Certificate Common Name")
    san_names: List[str] = Field(default_factory=list)
    key_type: str = Field("RSA_2048")
    subject: Dict[str, Any] = Field(
        default_factory=dict,
        description="Extra subject DN components (O, OU, C, ST, L, emailAddress, …)",
    )
    portal_group_tag: str = Field("Default Portal Certificate Group")
    usage: str = Field(
        "Portal",
        description="ISE 'Used By' role (Portal, Admin, EAP, etc.)",
    )
    certificate_mode: CertificateMode = Field(CertificateMode.SHARED)
    acme_provider_id: int = Field(..., description="ACME provider to use")
    node_ids: List[int] = Field(..., description="ISE nodes to push the cert to")


class CertificateIsePushPayload(BaseModel):
    """
    Payload for the /push-to-ise SSE endpoint.  Carries the already-obtained
    cert+key and the ISE targeting parameters so the ISE import can be
    triggered independently of the ACME issuance step.
    """
    cert_pem: str
    key_pem: str
    common_name: str
    node_ids: List[int]
    portal_group_tag: str
    certificate_mode: str = "shared"
    usage: str = "Portal"


class CertificateDownloadBundlePayload(BaseModel):
    """Payload for the /download-bundle endpoint."""
    cert_pem: str
    key_pem: str
    common_name: str


class ManagedCertificateResponse(BaseModel):
    id: int
    common_name: str
    san_names: List[str] = []
    key_type: str
    subject: Dict[str, Any] = Field(default_factory=dict)
    portal_group_tag: str
    certificate_mode: str
    renewal_threshold_days: int
    enabled: bool
    acme_provider_id: Optional[int] = None
    acme_provider_name: Optional[str] = None
    last_renewal_at: Optional[datetime] = None
    last_renewal_status: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    nodes: List[ISENodeResponse] = []

    class Config:
        from_attributes = True
