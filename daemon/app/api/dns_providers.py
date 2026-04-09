"""
DNS Providers API — CRUD for multiple DNS provider configurations.

Each DNS provider can be linked to one or more ACME providers and is used
when running the DNS-01 challenge for that ACME provider's certificates.
"""

import json
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from typing import List, Optional

from ..database import get_db, DNSProvider, ACMEProvider
from ..models import (
    DNSProviderCreate,
    DNSProviderUpdate,
    DNSProviderResponse,
    MessageResponse,
)
from ..services.dns_providers import (
    build_dns_client,
    DNS_SECRET_KEYS,
    ovh_request_consumer_key,
)

router = APIRouter(prefix="/api/v1/dns-providers", tags=["dns-providers"])

MASKED = "••••••••"


def _load_config(provider: DNSProvider) -> dict:
    if not provider.config_json:
        return {}
    try:
        return json.loads(provider.config_json) or {}
    except (ValueError, TypeError):
        return {}


def _mask_config(config: dict) -> dict:
    """Replace any secret-key values with the masked placeholder."""
    masked = {}
    for k, v in config.items():
        if k in DNS_SECRET_KEYS and v:
            masked[k] = MASKED
        else:
            masked[k] = v
    return masked


def _to_response(provider: DNSProvider) -> dict:
    return {
        "id": provider.id,
        "name": provider.name,
        "provider_type": provider.provider_type,
        "config": _mask_config(_load_config(provider)),
        "created_at": provider.created_at,
        "updated_at": provider.updated_at,
    }


def _get_or_404(provider_id: int, db: Session) -> DNSProvider:
    provider = db.query(DNSProvider).filter(DNSProvider.id == provider_id).first()
    if not provider:
        raise HTTPException(status_code=404, detail="DNS provider not found")
    return provider


@router.get("", response_model=List[DNSProviderResponse])
def list_providers(db: Session = Depends(get_db)):
    providers = db.query(DNSProvider).order_by(DNSProvider.id.asc()).all()
    return [_to_response(p) for p in providers]


@router.get("/{provider_id}", response_model=DNSProviderResponse)
def get_provider(provider_id: int, db: Session = Depends(get_db)):
    return _to_response(_get_or_404(provider_id, db))


@router.post("", response_model=DNSProviderResponse, status_code=201)
def create_provider(data: DNSProviderCreate, db: Session = Depends(get_db)):
    existing = db.query(DNSProvider).filter(DNSProvider.name == data.name).first()
    if existing:
        raise HTTPException(status_code=409, detail=f"DNS provider with name '{data.name}' already exists")

    config = dict(data.config or {})
    # Don't persist the masked sentinel.
    for k in list(config.keys()):
        if k in DNS_SECRET_KEYS and config[k] == MASKED:
            config.pop(k)

    provider = DNSProvider(
        name=data.name,
        provider_type=data.provider_type.value,
        config_json=json.dumps(config),
    )
    db.add(provider)
    db.commit()
    db.refresh(provider)
    return _to_response(provider)


@router.put("/{provider_id}", response_model=DNSProviderResponse)
def update_provider(provider_id: int, data: DNSProviderUpdate, db: Session = Depends(get_db)):
    provider = _get_or_404(provider_id, db)

    if data.name is not None and data.name != provider.name:
        conflict = db.query(DNSProvider).filter(DNSProvider.name == data.name).first()
        if conflict:
            raise HTTPException(status_code=409, detail=f"DNS provider with name '{data.name}' already exists")
        provider.name = data.name

    if data.provider_type is not None:
        provider.provider_type = data.provider_type.value

    if data.config is not None:
        existing_config = _load_config(provider)
        new_config = dict(existing_config)
        for k, v in data.config.items():
            # Preserve existing secret if the incoming value is empty/masked.
            if k in DNS_SECRET_KEYS and (v in (None, "", MASKED)):
                continue
            if v is None:
                new_config.pop(k, None)
            else:
                new_config[k] = v
        provider.config_json = json.dumps(new_config)

    db.commit()
    db.refresh(provider)
    return _to_response(provider)


@router.delete("/{provider_id}", response_model=MessageResponse)
def delete_provider(provider_id: int, db: Session = Depends(get_db)):
    provider = _get_or_404(provider_id, db)

    in_use = (
        db.query(ACMEProvider)
        .filter(ACMEProvider.dns_provider_id == provider_id)
        .count()
    )
    if in_use:
        raise HTTPException(
            status_code=409,
            detail=f"Cannot delete — DNS provider is used by {in_use} ACME provider(s)",
        )

    db.delete(provider)
    db.commit()
    return MessageResponse(message=f"DNS provider '{provider.name}' deleted")


@router.post("/{provider_id}/test", response_model=dict)
def test_provider(provider_id: int, db: Session = Depends(get_db)):
    """Test DNS provider connectivity using its stored credentials."""
    provider = _get_or_404(provider_id, db)
    try:
        client = build_dns_client(provider)
        return client.test_connection()
    except Exception as e:
        return {"success": False, "message": str(e)}


class OVHConsumerKeyRequest(BaseModel):
    application_key: Optional[str] = Field(None, description="OVH Application Key")
    application_secret: Optional[str] = Field(None, description="OVH Application Secret")
    endpoint: Optional[str] = Field("ovh-eu", description="OVH API endpoint")
    dns_zone: Optional[str] = Field(None, description="DNS zone to scope the consumer key to")
    provider_id: Optional[int] = Field(None, description="Existing DNS provider id to reuse stored credentials from")


@router.post("/ovh/request-consumer-key", response_model=dict)
def ovh_request_consumer_key_endpoint(
    data: OVHConsumerKeyRequest,
    db: Session = Depends(get_db),
):
    """Request an OVHcloud Consumer Key scoped with the permissions needed
    for DNS-01 challenge automation.

    The user must visit the returned ``validation_url`` and approve the
    permissions before the Consumer Key becomes valid.
    """
    app_key = data.application_key or ""
    app_secret = data.application_secret or ""
    endpoint = data.endpoint or "ovh-eu"
    zone = (data.dns_zone or "").strip()

    # Fall back to credentials stored on an existing provider so the user
    # doesn't have to retype them when editing an OVH provider.
    if data.provider_id is not None and (not app_key or not app_secret):
        stored = db.query(DNSProvider).filter(DNSProvider.id == data.provider_id).first()
        if stored is not None:
            cfg = _load_config(stored)
            if not app_key:
                app_key = cfg.get("ovh_application_key", "") or ""
            if not app_secret:
                app_secret = cfg.get("ovh_application_secret", "") or ""
            if not zone:
                zone = (cfg.get("ovh_dns_zone", "") or "").strip()
            if not data.endpoint:
                endpoint = cfg.get("ovh_endpoint", "ovh-eu") or "ovh-eu"

    if not app_key or not app_secret:
        raise HTTPException(
            status_code=400,
            detail="OVH application key and application secret are required",
        )

    try:
        result = ovh_request_consumer_key(
            application_key=app_key,
            application_secret=app_secret,
            endpoint=endpoint,
            zone_name=zone,
        )
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Failed to request consumer key: {e}")

    if not result.get("consumer_key") or not result.get("validation_url"):
        raise HTTPException(status_code=502, detail="OVH did not return a consumer key and validation URL")

    return {
        "success": True,
        "consumer_key": result["consumer_key"],
        "validation_url": result["validation_url"],
        "message": "Open the validation URL and approve the permissions, then save the provider.",
    }
