"""
Settings API endpoints.
"""

import os
from typing import Optional
from fastapi import APIRouter, Body, Depends, HTTPException
from sqlalchemy.orm import Session

from ..database import get_db, Settings, ISENode
from ..config import ConfigManager
from ..models import (
    AllSettings, ISESettings, ISETestSettings, ACMESettings, CertificateSettings,
    DNSSettings, SMTPSettings, SchedulerSettings,
    ISENodeCreate, ISENodeResponse, MessageResponse,
    DiscoverNodesResponse, DiscoveredNode, SystemCertificateInfo,
    InspectedCertificate
)
from ..scheduler import configure_scheduler
from ..services.ise_client import ISEClient
from ..services.dns_providers import get_dns_provider
from ..services.cert_inspector import parse_pem_certificate, extract_pem_from_ise_export

router = APIRouter(prefix="/api/v1/settings", tags=["Settings"])


@router.get("", response_model=dict)
def get_all_settings(db: Session = Depends(get_db)):
    """Get all settings (secrets masked)."""
    return ConfigManager.get_safe(db)


@router.get("/system", response_model=dict)
def get_system_settings():
    """Get system-level settings derived from the container environment."""
    return {
        "custom_dns_server": os.environ.get("CUSTOM_DNS_SERVER", "")
    }


@router.put("/ise", response_model=MessageResponse)
def update_ise_settings(settings: ISESettings, db: Session = Depends(get_db)):
    """Update ISE connection settings."""
    ConfigManager.set_bulk(db, settings.model_dump(), "ise")
    return MessageResponse(message="ISE settings updated")


@router.put("/acme", response_model=MessageResponse)
def update_acme_settings(settings: ACMESettings, db: Session = Depends(get_db)):
    """Update ACME provider settings (DigiCert or LetsEncrypt)."""
    data = settings.model_dump(exclude_none=True)
    if "acme_provider" in data:
        data["acme_provider"] = data["acme_provider"].value if hasattr(data["acme_provider"], "value") else data["acme_provider"]
    ConfigManager.set_bulk(db, data, "acme")
    return MessageResponse(message="ACME settings updated")


@router.put("/certificate", response_model=MessageResponse)
def update_certificate_settings(settings: CertificateSettings, db: Session = Depends(get_db)):
    """Update certificate settings."""
    data = settings.model_dump()
    data["certificate_mode"] = data["certificate_mode"].value
    ConfigManager.set_bulk(db, data, "certificate")
    return MessageResponse(message="Certificate settings updated")


@router.put("/dns", response_model=MessageResponse)
def update_dns_settings(settings: DNSSettings, db: Session = Depends(get_db)):
    """Update DNS provider settings."""
    data = settings.model_dump()
    data["dns_provider"] = data["dns_provider"].value
    ConfigManager.set_bulk(db, data, "dns")
    return MessageResponse(message="DNS settings updated")


@router.put("/smtp", response_model=MessageResponse)
def update_smtp_settings(settings: SMTPSettings, db: Session = Depends(get_db)):
    """Update SMTP notification settings."""
    ConfigManager.set_bulk(db, settings.model_dump(), "smtp")
    return MessageResponse(message="SMTP settings updated")


@router.put("/scheduler", response_model=MessageResponse)
def update_scheduler_settings(settings: SchedulerSettings, db: Session = Depends(get_db)):
    """Update scheduler settings and reconfigure the scheduler."""
    ConfigManager.set_bulk(db, settings.model_dump(), "scheduler")
    configure_scheduler()
    return MessageResponse(message="Scheduler settings updated and applied")


# ──────────────────────────────
# ISE Nodes
# ──────────────────────────────

@router.get("/nodes", response_model=list[ISENodeResponse])
def get_nodes(db: Session = Depends(get_db)):
    """Get all ISE nodes."""
    return db.query(ISENode).all()


@router.post("/nodes", response_model=ISENodeResponse)
def add_node(node: ISENodeCreate, db: Session = Depends(get_db)):
    """Add a new ISE node."""
    existing = db.query(ISENode).filter(ISENode.name == node.name).first()
    if existing:
        raise HTTPException(status_code=409, detail="Node already exists")

    # If this is primary, unset other primaries
    if node.is_primary:
        db.query(ISENode).update({ISENode.is_primary: False})

    db_node = ISENode(**node.model_dump())
    db.add(db_node)
    db.commit()
    db.refresh(db_node)
    return db_node


@router.put("/nodes/{node_id}", response_model=ISENodeResponse)
def update_node(node_id: int, node: ISENodeCreate, db: Session = Depends(get_db)):
    """Update an ISE node."""
    db_node = db.query(ISENode).filter(ISENode.id == node_id).first()
    if not db_node:
        raise HTTPException(status_code=404, detail="Node not found")

    if node.is_primary:
        db.query(ISENode).update({ISENode.is_primary: False})

    for key, value in node.model_dump().items():
        setattr(db_node, key, value)

    db.commit()
    db.refresh(db_node)
    return db_node


@router.delete("/nodes/{node_id}", response_model=MessageResponse)
def delete_node(node_id: int, db: Session = Depends(get_db)):
    """Delete an ISE node."""
    db_node = db.query(ISENode).filter(ISENode.id == node_id).first()
    if not db_node:
        raise HTTPException(status_code=404, detail="Node not found")

    db.delete(db_node)
    db.commit()
    return MessageResponse(message=f"Node {db_node.name} deleted")


# ──────────────────────────────
# Node Discovery
# ──────────────────────────────

@router.post("/nodes/discover", response_model=DiscoverNodesResponse)
def discover_nodes(db: Session = Depends(get_db)):
    """Discover all ISE deployment nodes via ERS API."""
    config = ConfigManager.get_flat(db)
    client = ISEClient(config)
    try:
        nodes = client.discover_nodes()
        discovered = [DiscoveredNode(**n) for n in nodes]
        psn_count = sum(1 for n in discovered if "PSN" in n.roles)
        return DiscoverNodesResponse(nodes=discovered, total=len(discovered), psn_count=psn_count)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"ERS discovery failed: {e}")


@router.post("/nodes/sync", response_model=MessageResponse)
def sync_discovered_nodes(nodes: list[ISENodeCreate], db: Session = Depends(get_db)):
    """Sync discovered nodes into the database (upsert by name)."""
    new_count = 0
    updated_count = 0

    for node in nodes:
        existing = db.query(ISENode).filter(ISENode.name == node.name).first()
        if existing:
            existing.role = node.role
            existing.is_primary = node.is_primary
            existing.enabled = node.enabled
            updated_count += 1
        else:
            if node.is_primary:
                db.query(ISENode).update({ISENode.is_primary: False})
            db_node = ISENode(**node.model_dump())
            db.add(db_node)
            new_count += 1

    db.commit()
    return MessageResponse(message=f"Synced {new_count + updated_count} nodes ({new_count} new, {updated_count} updated)")


# ──────────────────────────────
# System Certificates
# ──────────────────────────────

@router.get("/certificates", response_model=list[SystemCertificateInfo])
def get_system_certificates(db: Session = Depends(get_db)):
    """Fetch system certificates from every enabled ISE node and merge them."""
    config = ConfigManager.get_flat(db)
    client = ISEClient(config)

    nodes = db.query(ISENode).filter(ISENode.enabled == True).all()
    if not nodes:
        raise HTTPException(status_code=404, detail="No enabled ISE nodes configured. Add or discover nodes first.")

    result: list[SystemCertificateInfo] = []
    errors: list[str] = []

    for node in nodes:
        try:
            certs = client.get_system_certificates(node.name)
        except Exception as e:
            errors.append(f"{node.name}: {e}")
            continue

        for cert in certs:
            # Parse SAN names — ISE returns them as a comma-separated string
            san_raw = (
                cert.get("subjectAlternativeNames")
                or cert.get("subjectAlternativeName")
                or ""
            )
            if isinstance(san_raw, list):
                san_list = [s.strip() for s in san_raw if s]
            else:
                san_list = [s.strip() for s in str(san_raw).split(",") if s.strip()]

            result.append(SystemCertificateInfo(
                id=str(cert.get("id", "")),
                friendly_name=cert.get("friendlyName", ""),
                subject=cert.get("subject", ""),
                issuer=cert.get("issuedBy", cert.get("issuer", "")),
                expiration_date=cert.get("expirationDate", ""),
                used_by=cert.get("usedBy", ""),
                key_type=cert.get("keyType", ""),
                node_name=node.name,
                node_id=node.id,
                san_names=san_list,
                portal_group_tag=cert.get("portalGroupTag") or None,
            ))

    # If every node failed, surface the aggregated error.
    if errors and not result:
        raise HTTPException(status_code=502, detail=f"Failed to fetch certificates from any node: {'; '.join(errors)}")

    return result


@router.get(
    "/certificates/{node_id}/{cert_id}/inspect",
    response_model=InspectedCertificate,
)
def inspect_system_certificate(node_id: int, cert_id: str, db: Session = Depends(get_db)):
    """
    Export a system certificate from ISE, parse it, and return every attribute
    needed to clone a new managed certificate from it (subject DN, SANs, key
    type, extensions, etc.).
    """
    node = db.query(ISENode).filter(ISENode.id == node_id).first()
    if not node:
        raise HTTPException(status_code=404, detail=f"ISE node {node_id} not found")

    config = ConfigManager.get_flat(db)
    client = ISEClient(config)

    try:
        raw_body, _response = client.export_certificate_for_inspection(cert_id, node.name)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Failed to export certificate from ISE: {e}")

    # Try JSON first (ISE commonly wraps the cert in a JSON body). If that
    # fails, fall back to treating the body as a raw PEM/ZIP/DER payload.
    pem_text: Optional[str] = None
    try:
        import json
        parsed_json = json.loads(raw_body.decode("utf-8")) if raw_body else None
        if parsed_json is not None:
            pem_text = extract_pem_from_ise_export(parsed_json)
    except (ValueError, UnicodeDecodeError):
        pem_text = None

    if pem_text is None:
        try:
            pem_text = extract_pem_from_ise_export(raw_body)
        except ValueError as e:
            raise HTTPException(
                status_code=502,
                detail=f"Could not parse certificate export from ISE: {e}",
            )

    try:
        parsed = parse_pem_certificate(pem_text)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to parse exported certificate: {e}")

    # Look up the ISE list entry to echo back friendly_name and portal tag so
    # the frontend can pre-populate those too without a second round trip.
    friendly_name: Optional[str] = None
    portal_group_tag: Optional[str] = None
    try:
        certs = client.get_system_certificates(node.name)
        for cert in certs:
            if str(cert.get("id", "")) == str(cert_id):
                friendly_name = cert.get("friendlyName")
                portal_group_tag = cert.get("portalGroupTag") or None
                break
    except Exception:
        pass

    return InspectedCertificate(
        common_name=parsed["common_name"],
        subject_dn=parsed["subject_dn"],
        subject=parsed["subject"],
        issuer_dn=parsed["issuer_dn"],
        issuer=parsed["issuer"],
        serial_number=parsed["serial_number"],
        not_before=parsed["not_before"],
        not_after=parsed["not_after"],
        key_type=parsed["key_type"],
        public_key=parsed["public_key"],
        signature_algorithm=parsed["signature_algorithm"],
        version=parsed["version"],
        san_names=parsed["san_names"],
        san=parsed["san"],
        key_usage=parsed["key_usage"],
        extended_key_usage=parsed["extended_key_usage"],
        basic_constraints=parsed["basic_constraints"],
        fingerprint_sha1=parsed["fingerprint_sha1"],
        fingerprint_sha256=parsed["fingerprint_sha256"],
        source_cert_id=cert_id,
        source_node_id=node.id,
        source_node_name=node.name,
        friendly_name=friendly_name,
        portal_group_tag=portal_group_tag,
    )


@router.get("/portal-group-tags", response_model=list[str])
def get_portal_group_tags(db: Session = Depends(get_db)):
    """Auto-discover ISE Portal Group Tags from portals and system certificates."""
    config = ConfigManager.get_flat(db)
    client = ISEClient(config)

    node = db.query(ISENode).filter(ISENode.is_primary == True).first()
    if not node:
        node = db.query(ISENode).filter(ISENode.enabled == True).first()

    try:
        return client.get_portal_group_tags(node.name if node else None)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Failed to fetch portal group tags: {e}")


# ──────────────────────────────
# Connection Tests
# ──────────────────────────────

@router.post("/test/ise", response_model=dict)
def test_ise_connection(
    settings: Optional[ISETestSettings] = Body(default=None),
    db: Session = Depends(get_db)
):
    """Test ISE Open API connectivity. Accepts optional form values to test unsaved settings."""
    config = ConfigManager.get_flat(db)
    if settings:
        overrides = {k: v for k, v in settings.model_dump().items() if v is not None}
        config.update(overrides)
    client = ISEClient(config)
    return client.test_connection()


@router.post("/test/ers", response_model=dict)
def test_ers_connection(
    settings: Optional[ISETestSettings] = Body(default=None),
    db: Session = Depends(get_db)
):
    """Test ISE ERS API connectivity. Accepts optional form values to test unsaved settings."""
    config = ConfigManager.get_flat(db)
    if settings:
        overrides = {k: v for k, v in settings.model_dump().items() if v is not None}
        config.update(overrides)
    client = ISEClient(config)
    return client.test_ers_connection()


@router.post("/test/dns", response_model=dict)
def test_dns_connection(db: Session = Depends(get_db)):
    """Test DNS provider connectivity."""
    config = ConfigManager.get_flat(db)
    try:
        provider = get_dns_provider(config)
        return provider.test_connection()
    except Exception as e:
        return {"success": False, "message": str(e)}
