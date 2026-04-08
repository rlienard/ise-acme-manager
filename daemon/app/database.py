"""
Database models and setup using SQLAlchemy + SQLite.
Stores configuration, renewal history, and daemon state.
"""

import os
from datetime import datetime
from sqlalchemy import (
    create_engine, Column, Integer, String, Text, Boolean,
    DateTime, Float, JSON, Enum as SQLEnum, ForeignKey, Table,
    inspect, text
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
import enum

DATABASE_DIR = os.getenv("DATA_DIR", "/app/data")
DATABASE_URL = f"sqlite:///{DATABASE_DIR}/ise_acme.db"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# ──────────────────────────────────────
# Enums
# ──────────────────────────────────────

class RenewalStatus(str, enum.Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"
    SKIPPED = "skipped"


class DaemonState(str, enum.Enum):
    IDLE = "idle"
    RUNNING = "running"
    ERROR = "error"
    DISABLED = "disabled"


# ──────────────────────────────────────
# Models
# ──────────────────────────────────────

class Settings(Base):
    """Stores all configuration settings as key-value pairs."""
    __tablename__ = "settings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    key = Column(String(255), unique=True, nullable=False, index=True)
    value = Column(Text, nullable=True)
    value_type = Column(String(50), default="string")  # string, integer, boolean, json
    category = Column(String(100), nullable=False)  # ise, acme, certificate, dns, smtp, scheduler
    description = Column(Text, nullable=True)
    is_secret = Column(Boolean, default=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class ISENode(Base):
    """ISE PSN node registry."""
    __tablename__ = "ise_nodes"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), unique=True, nullable=False)
    role = Column(String(50), default="PSN")
    enabled = Column(Boolean, default=True)
    is_primary = Column(Boolean, default=False)
    last_cert_check = Column(DateTime, nullable=True)
    cert_expiry_date = Column(DateTime, nullable=True)
    cert_days_remaining = Column(Integer, nullable=True)
    cert_status = Column(String(50), default="unknown")
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


# ── Association table: ManagedCertificate ↔ ISENode ──
certificate_node_assignments = Table(
    "certificate_node_assignments", Base.metadata,
    Column("certificate_id", Integer, ForeignKey("managed_certificates.id", ondelete="CASCADE"), primary_key=True),
    Column("node_id", Integer, ForeignKey("ise_nodes.id", ondelete="CASCADE"), primary_key=True),
)


class DNSProvider(Base):
    """DNS provider configuration — multiple providers supported, linked from ACME providers for DNS-01 challenge automation."""
    __tablename__ = "dns_providers"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), unique=True, nullable=False)  # user-friendly label
    provider_type = Column(String(50), nullable=False)  # 'cloudflare', 'aws_route53', 'azure_dns', 'ovhcloud'
    config_json = Column(Text, nullable=True)  # JSON-encoded provider-specific configuration
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class ACMEProvider(Base):
    """ACME provider configuration — multiple providers supported for per-cert selection."""
    __tablename__ = "acme_providers"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), unique=True, nullable=False)  # user-friendly label
    provider_type = Column(String(50), nullable=False)  # 'digicert' or 'letsencrypt'
    directory_url = Column(String(512), nullable=False)
    kid = Column(Text, nullable=True)          # DigiCert Key ID
    hmac_key = Column(Text, nullable=True)     # DigiCert HMAC key
    account_email = Column(String(255), nullable=True)  # LetsEncrypt
    account_key = Column(Text, nullable=True)  # LetsEncrypt account PEM
    dns_provider_id = Column(Integer, ForeignKey("dns_providers.id", ondelete="SET NULL"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    dns_provider = relationship("DNSProvider")


class ManagedCertificate(Base):
    """Multi-certificate management — each row is an independently managed cert."""
    __tablename__ = "managed_certificates"

    id = Column(Integer, primary_key=True, autoincrement=True)
    common_name = Column(String(255), nullable=False)
    san_names = Column(JSON, default=[])
    key_type = Column(String(50), default="RSA_2048")
    portal_group_tag = Column(String(255), default="Default Portal Certificate Group")
    certificate_mode = Column(String(20), default="shared")  # shared / per-node
    renewal_threshold_days = Column(Integer, default=30)
    enabled = Column(Boolean, default=True)
    acme_provider_id = Column(Integer, ForeignKey("acme_providers.id", ondelete="SET NULL"), nullable=True)
    last_renewal_at = Column(DateTime, nullable=True)
    last_renewal_status = Column(String(50), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    nodes = relationship("ISENode", secondary=certificate_node_assignments, backref="managed_certificates")
    acme_provider = relationship("ACMEProvider")


class RenewalHistory(Base):
    """Certificate renewal audit log."""
    __tablename__ = "renewal_history"

    id = Column(Integer, primary_key=True, autoincrement=True)
    run_id = Column(String(36), nullable=False, index=True)  # UUID for each run
    status = Column(SQLEnum(RenewalStatus), default=RenewalStatus.PENDING)
    mode = Column(String(20), default="shared")  # shared or per-node
    trigger = Column(String(50), default="scheduled")  # scheduled, manual, force
    started_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    duration_seconds = Column(Float, nullable=True)
    common_name = Column(String(255), nullable=True)
    node_results = Column(JSON, nullable=True)  # Per-node results
    error_message = Column(Text, nullable=True)
    dns_challenge_created = Column(Boolean, default=False)
    dns_challenge_cleaned = Column(Boolean, default=False)
    notification_sent = Column(Boolean, default=False)
    log_output = Column(Text, nullable=True)
    managed_certificate_id = Column(Integer, ForeignKey("managed_certificates.id", ondelete="SET NULL"), nullable=True)


class DaemonStatus(Base):
    """Daemon runtime state tracking."""
    __tablename__ = "daemon_status"

    id = Column(Integer, primary_key=True, autoincrement=True)
    state = Column(SQLEnum(DaemonState), default=DaemonState.IDLE)
    current_action = Column(String(255), nullable=True)
    last_run_at = Column(DateTime, nullable=True)
    last_run_status = Column(String(50), nullable=True)
    next_run_at = Column(DateTime, nullable=True)
    uptime_since = Column(DateTime, default=datetime.utcnow)
    total_renewals = Column(Integer, default=0)
    successful_renewals = Column(Integer, default=0)
    failed_renewals = Column(Integer, default=0)
    last_error = Column(Text, nullable=True)
    version = Column(String(20), default="2.0.0")
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


# ──────────────────────────────────────
# Database initialization
# ──────────────────────────────────────

def init_db():
    """Create all tables and seed initial data."""
    os.makedirs(DATABASE_DIR, exist_ok=True)
    Base.metadata.create_all(bind=engine)

    # Add new columns to existing tables (lightweight migration)
    _migrate_add_columns()

    db = SessionLocal()
    try:
        # Initialize daemon status if not exists
        status = db.query(DaemonStatus).first()
        if not status:
            status = DaemonStatus(
                state=DaemonState.IDLE,
                uptime_since=datetime.utcnow()
            )
            db.add(status)

        # Seed default settings if empty
        if db.query(Settings).count() == 0:
            _seed_default_settings(db)

        db.commit()

        # Migrate legacy single-cert config to managed certificates
        _migrate_single_cert_to_managed(db)

        # Migrate legacy global ACME settings to an ACMEProvider row
        _migrate_legacy_acme_provider(db)

        # Migrate legacy global DNS settings to a DNSProvider row
        _migrate_legacy_dns_provider(db)

    finally:
        db.close()


def _migrate_add_columns():
    """Add newly-introduced columns to existing tables (idempotent)."""
    inspector = inspect(engine)
    if "managed_certificates" in inspector.get_table_names():
        cols = {c["name"] for c in inspector.get_columns("managed_certificates")}
        if "acme_provider_id" not in cols:
            with engine.begin() as conn:
                conn.execute(text(
                    "ALTER TABLE managed_certificates ADD COLUMN acme_provider_id INTEGER"
                ))
    if "acme_providers" in inspector.get_table_names():
        cols = {c["name"] for c in inspector.get_columns("acme_providers")}
        if "dns_provider_id" not in cols:
            with engine.begin() as conn:
                conn.execute(text(
                    "ALTER TABLE acme_providers ADD COLUMN dns_provider_id INTEGER"
                ))


def _migrate_legacy_acme_provider(db):
    """Create a default ACMEProvider row from legacy settings, assign to existing certs."""
    if db.query(ACMEProvider).count() > 0:
        return

    def _get(key, default=None):
        row = db.query(Settings).filter(Settings.key == key).first()
        if not row or row.value is None:
            return default
        return row.value

    provider_type = _get("acme_provider", "digicert") or "digicert"
    directory_url = _get("acme_directory_url") or (
        "https://acme.digicert.com/v2/acme/directory/"
        if provider_type == "digicert"
        else "https://acme-api.letsencrypt.org/directory"
    )
    name = "DigiCert (default)" if provider_type == "digicert" else "Let's Encrypt (default)"

    provider = ACMEProvider(
        name=name,
        provider_type=provider_type,
        directory_url=directory_url,
        kid=_get("acme_kid") or None,
        hmac_key=_get("acme_hmac_key") or None,
        account_email=_get("acme_account_email") or None,
        account_key=_get("acme_account_key") or None,
    )
    db.add(provider)
    db.flush()

    # Assign to any existing managed certificates that have no provider
    existing_certs = (
        db.query(ManagedCertificate)
        .filter(ManagedCertificate.acme_provider_id.is_(None))
        .all()
    )
    for cert in existing_certs:
        cert.acme_provider_id = provider.id

    db.commit()


def _migrate_legacy_dns_provider(db):
    """Create a default DNSProvider row from legacy global DNS settings, link to existing ACME providers."""
    import json
    if db.query(DNSProvider).count() > 0:
        return

    def _get(key, default=None):
        row = db.query(Settings).filter(Settings.key == key).first()
        if not row or row.value is None:
            return default
        return row.value

    provider_type = (_get("dns_provider", "cloudflare") or "cloudflare").lower()

    # Map provider type to the relevant config keys from legacy settings.
    config_keys_by_type = {
        "cloudflare": ["cloudflare_api_token", "cloudflare_zone_id"],
        "aws_route53": ["aws_hosted_zone_id", "aws_region"],
        "azure_dns": ["azure_subscription_id", "azure_resource_group", "azure_dns_zone_name"],
        "ovhcloud": [
            "ovh_endpoint", "ovh_application_key", "ovh_application_secret",
            "ovh_consumer_key", "ovh_dns_zone",
        ],
    }
    keys = config_keys_by_type.get(provider_type, [])
    config = {k: _get(k, "") or "" for k in keys}

    # If no legacy config was ever populated, skip the seed entirely.
    if not any(config.values()):
        return

    name_by_type = {
        "cloudflare": "Cloudflare (default)",
        "aws_route53": "AWS Route53 (default)",
        "azure_dns": "Azure DNS (default)",
        "ovhcloud": "OVHcloud (default)",
    }
    name = name_by_type.get(provider_type, f"{provider_type} (default)")

    provider = DNSProvider(
        name=name,
        provider_type=provider_type,
        config_json=json.dumps(config),
    )
    db.add(provider)
    db.flush()

    # Link to any existing ACME providers that have no DNS provider assigned.
    orphan_acme = (
        db.query(ACMEProvider)
        .filter(ACMEProvider.dns_provider_id.is_(None))
        .all()
    )
    for ap in orphan_acme:
        ap.dns_provider_id = provider.id

    db.commit()


def _migrate_single_cert_to_managed(db):
    """Migrate legacy single-cert settings to a ManagedCertificate row (runs once)."""
    import json
    if db.query(ManagedCertificate).count() > 0:
        return

    cn_setting = db.query(Settings).filter(Settings.key == "common_name").first()
    if not cn_setting or not cn_setting.value:
        return

    # Read legacy settings
    def _get(key, default=None):
        row = db.query(Settings).filter(Settings.key == key).first()
        if not row or not row.value:
            return default
        return row.value

    san_raw = _get("san_names", "[]")
    try:
        san_names = json.loads(san_raw)
    except (ValueError, TypeError):
        san_names = []

    try:
        threshold = int(_get("renewal_threshold_days", "30"))
    except (ValueError, TypeError):
        threshold = 30

    cert = ManagedCertificate(
        common_name=cn_setting.value,
        san_names=san_names,
        key_type=_get("key_type", "RSA_2048"),
        portal_group_tag=_get("portal_group_tag", "Default Portal Certificate Group"),
        certificate_mode=_get("certificate_mode", "shared"),
        renewal_threshold_days=threshold,
        enabled=True,
    )
    db.add(cert)
    db.flush()

    # Assign all enabled nodes
    enabled_nodes = db.query(ISENode).filter(ISENode.enabled == True).all()
    cert.nodes = enabled_nodes
    db.commit()


def _seed_default_settings(db):
    """Populate default settings."""
    defaults = [
        # ISE Settings
        ("ise_host", "", "string", "ise", "ISE PAN hostname or IP", False),
        ("ise_username", "", "string", "ise", "ISE admin username", False),
        ("ise_password", "", "string", "ise", "ISE admin password", True),
        ("ise_ers_port", "9060", "integer", "ise", "ISE ERS API port", False),
        ("ise_open_api_port", "443", "integer", "ise", "ISE Open API port", False),

        # ACME Settings
        ("acme_provider", "digicert", "string", "acme", "ACME provider (digicert or letsencrypt)", False),
        ("acme_directory_url", "https://acme.digicert.com/v2/acme/directory/", "string", "acme", "ACME directory URL", False),
        ("acme_kid", "", "string", "acme", "ACME Key ID (KID)", True),
        ("acme_hmac_key", "", "string", "acme", "ACME HMAC Key", True),
        ("acme_account_email", "", "string", "acme", "ACME account email (LetsEncrypt)", False),
        ("acme_account_key", "", "string", "acme", "ACME account private key PEM (LetsEncrypt)", True),

        # Certificate Settings
        ("common_name", "", "string", "certificate", "Certificate Common Name", False),
        ("san_names", "[]", "json", "certificate", "Subject Alternative Names", False),
        ("key_type", "RSA_2048", "string", "certificate", "Key type", False),
        ("portal_group_tag", "Default Portal Certificate Group", "string", "certificate", "ISE Portal Group Tag", False),
        ("certificate_mode", "shared", "string", "certificate", "Certificate mode: shared or per-node", False),
        ("renewal_threshold_days", "30", "integer", "certificate", "Days before expiry to trigger renewal", False),

        # DNS Settings
        ("dns_provider", "cloudflare", "string", "dns", "DNS provider", False),
        ("cloudflare_api_token", "", "string", "dns", "Cloudflare API token", True),
        ("cloudflare_zone_id", "", "string", "dns", "Cloudflare Zone ID", False),
        ("aws_hosted_zone_id", "", "string", "dns", "AWS Route53 Hosted Zone ID", False),
        ("aws_region", "us-east-1", "string", "dns", "AWS Region", False),
        ("azure_subscription_id", "", "string", "dns", "Azure Subscription ID", False),
        ("azure_resource_group", "", "string", "dns", "Azure Resource Group", False),
        ("azure_dns_zone_name", "", "string", "dns", "Azure DNS Zone Name", False),
        ("ovh_endpoint", "ovh-eu", "string", "dns", "OVHcloud API endpoint", False),
        ("ovh_application_key", "", "string", "dns", "OVHcloud Application Key", True),
        ("ovh_application_secret", "", "string", "dns", "OVHcloud Application Secret", True),
        ("ovh_consumer_key", "", "string", "dns", "OVHcloud Consumer Key", True),
        ("ovh_dns_zone", "", "string", "dns", "OVHcloud DNS Zone", False),

        # SMTP Settings
        ("smtp_server", "", "string", "smtp", "SMTP server hostname", False),
        ("smtp_port", "587", "integer", "smtp", "SMTP port", False),
        ("smtp_username", "", "string", "smtp", "SMTP username", False),
        ("smtp_password", "", "string", "smtp", "SMTP password", True),
        ("alert_recipients", "[]", "json", "smtp", "Alert email recipients", False),

        # Scheduler Settings
        ("scheduler_enabled", "true", "boolean", "scheduler", "Enable automatic scheduling", False),
        ("scheduler_cron_hour", "2", "integer", "scheduler", "Hour to run (0-23)", False),
        ("scheduler_cron_minute", "0", "integer", "scheduler", "Minute to run (0-59)", False),
        ("scheduler_interval_hours", "24", "integer", "scheduler", "Interval between runs in hours", False),
    ]

    for key, value, vtype, category, desc, is_secret in defaults:
        setting = Settings(
            key=key, value=value, value_type=vtype,
            category=category, description=desc, is_secret=is_secret
        )
        db.add(setting)


def get_db():
    """Dependency for FastAPI — yields a database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
