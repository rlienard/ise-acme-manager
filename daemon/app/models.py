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


class ACMEProvider(str, Enum):
    DIGICERT = "digicert"
    LETSENCRYPT = "letsencrypt"


class DNSProvider(str, Enum):
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
    acme_provider: ACMEProvider = Field(
        ACMEProvider.DIGICERT,
        description="ACME provider (digicert or letsencrypt)"
    )
    acme_directory_url: str = Field(
        "https://acme.digicert.com/v2/acme/directory/",
        description="ACME directory URL"
    )
    acme_kid: Optional[str] = Field(None, description="ACME Key ID (DigiCert)")
    acme_hmac_key: Optional[str] = Field(None, description="ACME HMAC Key (DigiCert)")
    acme_account_email: Optional[str] = Field(None, description="Account email (LetsEncrypt)")


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
    dns_provider: DNSProvider = Field(DNSProvider.CLOUDFLARE, description="DNS provider")
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
    portal_group_tag: str = Field("Default Portal Certificate Group")
    certificate_mode: CertificateMode = Field(CertificateMode.SHARED)
    renewal_threshold_days: int = Field(30)
    enabled: bool = Field(True)
    node_ids: List[int] = Field(default_factory=list, description="ISE node IDs to assign")


class ManagedCertificateUpdate(BaseModel):
    common_name: Optional[str] = None
    san_names: Optional[List[str]] = None
    key_type: Optional[str] = None
    portal_group_tag: Optional[str] = None
    certificate_mode: Optional[CertificateMode] = None
    renewal_threshold_days: Optional[int] = None
    enabled: Optional[bool] = None
    node_ids: Optional[List[int]] = None


class ManagedCertificateResponse(BaseModel):
    id: int
    common_name: str
    san_names: List[str] = []
    key_type: str
    portal_group_tag: str
    certificate_mode: str
    renewal_threshold_days: int
    enabled: bool
    last_renewal_at: Optional[datetime] = None
    last_renewal_status: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    nodes: List[ISENodeResponse] = []

    class Config:
        from_attributes = True
