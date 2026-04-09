"""
ACME Providers API — CRUD for multiple ACME provider configurations.
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List

from ..database import get_db, ACMEProvider, ManagedCertificate, DNSProvider
from ..models import (
    ACMEProviderCreate,
    ACMEProviderUpdate,
    ACMEProviderResponse,
    MessageResponse,
)
from ..services.acme_client import test_acme_provider

router = APIRouter(prefix="/api/v1/acme-providers", tags=["acme-providers"])


def _to_response(provider: ACMEProvider) -> dict:
    """Convert DB row to response dict, masking the account key."""
    return {
        "id": provider.id,
        "name": provider.name,
        "provider_type": provider.provider_type,
        "directory_url": provider.directory_url,
        "kid": provider.kid,
        "hmac_key": provider.hmac_key,
        "account_email": provider.account_email,
        "has_account_key": bool(provider.account_key),
        "dns_provider_id": provider.dns_provider_id,
        "dns_provider_name": provider.dns_provider.name if provider.dns_provider else None,
        "created_at": provider.created_at,
        "updated_at": provider.updated_at,
    }


def _get_or_404(provider_id: int, db: Session) -> ACMEProvider:
    provider = db.query(ACMEProvider).filter(ACMEProvider.id == provider_id).first()
    if not provider:
        raise HTTPException(status_code=404, detail="ACME provider not found")
    return provider


def _validate_dns_provider(dns_provider_id, db: Session):
    if dns_provider_id is None:
        return
    exists = db.query(DNSProvider).filter(DNSProvider.id == dns_provider_id).first()
    if not exists:
        raise HTTPException(status_code=400, detail=f"DNS provider id {dns_provider_id} not found")


@router.get("", response_model=List[ACMEProviderResponse])
def list_providers(db: Session = Depends(get_db)):
    providers = db.query(ACMEProvider).order_by(ACMEProvider.id.asc()).all()
    return [_to_response(p) for p in providers]


@router.get("/{provider_id}", response_model=ACMEProviderResponse)
def get_provider(provider_id: int, db: Session = Depends(get_db)):
    return _to_response(_get_or_404(provider_id, db))


@router.post("", response_model=ACMEProviderResponse, status_code=201)
def create_provider(data: ACMEProviderCreate, db: Session = Depends(get_db)):
    existing = db.query(ACMEProvider).filter(ACMEProvider.name == data.name).first()
    if existing:
        raise HTTPException(status_code=409, detail=f"Provider with name '{data.name}' already exists")

    _validate_dns_provider(data.dns_provider_id, db)

    provider = ACMEProvider(
        name=data.name,
        provider_type=data.provider_type.value,
        directory_url=data.directory_url,
        kid=data.kid or None,
        hmac_key=data.hmac_key or None,
        account_email=data.account_email or None,
        account_key=data.account_key or None,
        dns_provider_id=data.dns_provider_id,
    )
    db.add(provider)
    db.commit()
    db.refresh(provider)
    return _to_response(provider)


@router.put("/{provider_id}", response_model=ACMEProviderResponse)
def update_provider(provider_id: int, data: ACMEProviderUpdate, db: Session = Depends(get_db)):
    provider = _get_or_404(provider_id, db)

    if data.name is not None and data.name != provider.name:
        conflict = db.query(ACMEProvider).filter(ACMEProvider.name == data.name).first()
        if conflict:
            raise HTTPException(status_code=409, detail=f"Provider with name '{data.name}' already exists")
        provider.name = data.name

    if data.provider_type is not None:
        provider.provider_type = data.provider_type.value
    if data.directory_url is not None:
        provider.directory_url = data.directory_url

    # Secret-style fields: only update when a non-empty value is provided so that
    # unchanged masked fields in the UI don't blow away the stored secret.
    if data.kid is not None and data.kid != "":
        provider.kid = data.kid
    if data.hmac_key is not None and data.hmac_key != "":
        provider.hmac_key = data.hmac_key
    if data.account_email is not None:
        provider.account_email = data.account_email or None
    if data.account_key is not None and data.account_key != "":
        provider.account_key = data.account_key
    if data.dns_provider_id is not None:
        _validate_dns_provider(data.dns_provider_id, db)
        provider.dns_provider_id = data.dns_provider_id

    db.commit()
    db.refresh(provider)
    return _to_response(provider)


@router.post("/{provider_id}/test", response_model=dict)
def test_provider(provider_id: int, db: Session = Depends(get_db)):
    """Validate an ACME provider configuration without issuing a certificate.

    Fetches the directory URL, checks the required RFC 8555 endpoints,
    pulls a fresh nonce, and (for Let's Encrypt) registers or looks up the
    account so a misconfigured directory URL or wrong account email is
    surfaced before the next renewal run.
    """
    provider = _get_or_404(provider_id, db)
    try:
        return test_acme_provider(
            provider_type=provider.provider_type,
            directory_url=provider.directory_url,
            account_email=provider.account_email,
            account_key_pem=provider.account_key,
            kid=provider.kid,
            hmac_key=provider.hmac_key,
        )
    except Exception as e:
        return {"success": False, "message": f"Test failed: {e}"}


@router.delete("/{provider_id}", response_model=MessageResponse)
def delete_provider(provider_id: int, db: Session = Depends(get_db)):
    provider = _get_or_404(provider_id, db)

    in_use = (
        db.query(ManagedCertificate)
        .filter(ManagedCertificate.acme_provider_id == provider_id)
        .count()
    )
    if in_use:
        raise HTTPException(
            status_code=409,
            detail=f"Cannot delete — provider is used by {in_use} managed certificate(s)",
        )

    db.delete(provider)
    db.commit()
    return MessageResponse(message=f"ACME provider '{provider.name}' deleted")
