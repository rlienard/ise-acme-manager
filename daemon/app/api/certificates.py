"""
Managed Certificates API — CRUD for multi-certificate management.
"""

import io
import json
import logging
import queue
import re as _re
import threading
import zipfile
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response as FastAPIResponse, StreamingResponse
from sqlalchemy.orm import Session
from typing import List

from ..database import (
    get_db, SessionLocal,
    ManagedCertificate, ISENode, ACMEProvider,
)
from ..models import (
    ManagedCertificateCreate,
    ManagedCertificateUpdate,
    ManagedCertificateResponse,
    CertificateRequestPayload,
    CertificateIsePushPayload,
    CertificateDownloadBundlePayload,
    CertificateDecodePayload,
)
from ..services.cert_request import CertificateRequestRunner, CertificateRequestError
from ..services.ise_client import split_certificate_chain, _split_pem_chain

from cryptography import x509
from cryptography.hazmat.primitives import hashes

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/certificates", tags=["certificates"])


def _get_cert_or_404(cert_id: int, db: Session) -> ManagedCertificate:
    cert = db.query(ManagedCertificate).filter(ManagedCertificate.id == cert_id).first()
    if not cert:
        raise HTTPException(status_code=404, detail="Managed certificate not found")
    return cert


def _assign_nodes(cert: ManagedCertificate, node_ids: List[int], db: Session):
    if node_ids is not None:
        nodes = db.query(ISENode).filter(ISENode.id.in_(node_ids)).all() if node_ids else []
        cert.nodes = nodes


def _validate_provider(provider_id: int, db: Session):
    if provider_id is None:
        return
    exists = db.query(ACMEProvider).filter(ACMEProvider.id == provider_id).first()
    if not exists:
        raise HTTPException(status_code=400, detail=f"ACME provider id {provider_id} not found")


def _serialize_cert(cert: ManagedCertificate) -> dict:
    return {
        "id": cert.id,
        "common_name": cert.common_name,
        "san_names": cert.san_names or [],
        "key_type": cert.key_type,
        "subject": cert.subject or {},
        "portal_group_tag": cert.portal_group_tag,
        "certificate_mode": cert.certificate_mode,
        "renewal_threshold_days": cert.renewal_threshold_days,
        "enabled": cert.enabled,
        "acme_provider_id": cert.acme_provider_id,
        "acme_provider_name": cert.acme_provider.name if cert.acme_provider else None,
        "last_renewal_at": cert.last_renewal_at,
        "last_renewal_status": cert.last_renewal_status,
        "created_at": cert.created_at,
        "updated_at": cert.updated_at,
        "nodes": cert.nodes,
    }


@router.get("", response_model=List[ManagedCertificateResponse])
def list_certificates(db: Session = Depends(get_db)):
    certs = db.query(ManagedCertificate).all()
    return [_serialize_cert(c) for c in certs]


@router.get("/{cert_id}", response_model=ManagedCertificateResponse)
def get_certificate(cert_id: int, db: Session = Depends(get_db)):
    return _serialize_cert(_get_cert_or_404(cert_id, db))


@router.post("", response_model=ManagedCertificateResponse, status_code=201)
def create_certificate(data: ManagedCertificateCreate, db: Session = Depends(get_db)):
    _validate_provider(data.acme_provider_id, db)

    cert = ManagedCertificate(
        common_name=data.common_name,
        san_names=data.san_names,
        key_type=data.key_type,
        subject=data.subject or {},
        portal_group_tag=data.portal_group_tag,
        certificate_mode=data.certificate_mode.value,
        renewal_threshold_days=data.renewal_threshold_days,
        enabled=data.enabled,
        acme_provider_id=data.acme_provider_id,
    )
    db.add(cert)
    db.flush()
    _assign_nodes(cert, data.node_ids, db)
    db.commit()
    db.refresh(cert)
    return _serialize_cert(cert)


@router.put("/{cert_id}", response_model=ManagedCertificateResponse)
def update_certificate(cert_id: int, data: ManagedCertificateUpdate, db: Session = Depends(get_db)):
    cert = _get_cert_or_404(cert_id, db)

    if data.common_name is not None:
        cert.common_name = data.common_name
    if data.san_names is not None:
        cert.san_names = data.san_names
    if data.key_type is not None:
        cert.key_type = data.key_type
    if data.subject is not None:
        cert.subject = data.subject
    if data.portal_group_tag is not None:
        cert.portal_group_tag = data.portal_group_tag
    if data.certificate_mode is not None:
        cert.certificate_mode = data.certificate_mode.value
    if data.renewal_threshold_days is not None:
        cert.renewal_threshold_days = data.renewal_threshold_days
    if data.enabled is not None:
        cert.enabled = data.enabled
    if data.acme_provider_id is not None:
        _validate_provider(data.acme_provider_id, db)
        cert.acme_provider_id = data.acme_provider_id
    if data.node_ids is not None:
        _assign_nodes(cert, data.node_ids, db)

    db.commit()
    db.refresh(cert)
    return _serialize_cert(cert)


@router.delete("/{cert_id}", status_code=204)
def delete_certificate(cert_id: int, db: Session = Depends(get_db)):
    cert = _get_cert_or_404(cert_id, db)
    db.delete(cert)
    db.commit()


# ──────────────────────────────────────────────────────────
# Live "request + push" flow with Server-Sent Events
# ──────────────────────────────────────────────────────────

def _sse(event: str, data: dict) -> str:
    """Format a Server-Sent Events frame."""
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


def _make_sse_stream(events: "queue.Queue", stop_events: "tuple[str, ...]" = ("complete",)):
    """Return a generator that yields SSE frames from a queue until a stop event."""
    def stream():
        yield _sse("log", {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "phase": "connect",
            "level": "info",
            "message": "Connected to certificate request stream",
            "data": {},
        })
        while True:
            item = events.get()
            if item is None:
                break
            yield _sse(item["event"], item["data"])
            if item["event"] in stop_events:
                break
    return stream()


def _sse_response(events: "queue.Queue", stop_events: "tuple[str, ...]" = ("complete",)):
    """Wrap _make_sse_stream in a StreamingResponse."""
    return StreamingResponse(
        _make_sse_stream(events, stop_events),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.post("/request")
def request_certificate_stream(payload: CertificateRequestPayload):
    """
    Request a new certificate from the configured ACME provider.

    For **Let's Encrypt** providers the endpoint only runs the ACME
    issuance phase (ACME order → DNS-01 challenge → cert download) and
    then emits a ``cert_obtained`` SSE event carrying the cert+key PEM so
    the UI can offer the operator a choice: download a local bundle or
    push directly to ISE.

    For **DigiCert / ISE-managed ACME** providers the full
    request-and-install flow runs automatically as before, ending with a
    ``complete`` event.

    This endpoint does NOT create a managed-certificate row.
    """
    events: queue.Queue = queue.Queue()

    def emit(phase: str, level: str, payload_data: dict):
        events.put({
            "event": "log",
            "data": {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "phase": phase,
                "level": level,
                **payload_data,
            },
        })

    def worker():
        db = SessionLocal()
        try:
            # Detect provider type so we can choose the split vs full flow.
            provider = (
                db.query(ACMEProvider)
                .filter(ACMEProvider.id == payload.acme_provider_id)
                .first()
            )
            runner = CertificateRequestRunner(db, payload, emit)

            if provider and provider.provider_type == "letsencrypt":
                # ── Split flow: ACME only ──────────────────────────────
                cert_pem, key_pem = runner.run_acme_phase()
                components = split_certificate_chain(cert_pem)
                events.put({
                    "event": "cert_obtained",
                    "data": {
                        "cert_pem": cert_pem,
                        "key_pem": key_pem,
                        "leaf_pem": components["leaf"],
                        "intermediate_pem": components["intermediate"],
                        "root_pem": components["root"],
                        "ca_chain_pem": components["ca_chain"],
                        "common_name": payload.common_name,
                        "node_ids": payload.node_ids,
                        "portal_group_tag": payload.portal_group_tag,
                        "certificate_mode": (
                            payload.certificate_mode.value
                            if hasattr(payload.certificate_mode, "value")
                            else str(payload.certificate_mode)
                        ),
                        "usage": payload.usage,
                    },
                })
            else:
                # ── Legacy full flow (DigiCert / ISE-managed ACME) ─────
                runner.run()
                events.put({
                    "event": "complete",
                    "data": {
                        "success": True,
                        "message": "Certificate request completed",
                    },
                })
        except CertificateRequestError as e:
            logger.warning(f"Certificate request failed: {e}")
            events.put({
                "event": "complete",
                "data": {"success": False, "message": str(e)},
            })
        except Exception as e:
            logger.exception("Certificate request crashed")
            events.put({
                "event": "complete",
                "data": {"success": False, "message": f"Unexpected error: {e}"},
            })
        finally:
            db.close()
            events.put(None)  # sentinel

    threading.Thread(target=worker, daemon=True).start()
    # cert_obtained is a terminal event for this stream (same as complete).
    return _sse_response(events, stop_events=("complete", "cert_obtained"))


@router.post("/push-to-ise")
def push_certificate_to_ise(payload: CertificateIsePushPayload):
    """
    Import an already-obtained certificate into the target ISE nodes.

    Receives the cert+key PEM (obtained from a prior ``/request`` call
    that emitted ``cert_obtained``) together with the ISE targeting
    parameters and streams live progress events until the import and
    portal bind are complete on all nodes.
    """
    events: queue.Queue = queue.Queue()

    def emit(phase: str, level: str, payload_data: dict):
        events.put({
            "event": "log",
            "data": {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "phase": phase,
                "level": level,
                **payload_data,
            },
        })

    def worker():
        db = SessionLocal()
        try:
            # We pass None for the CertificateRequestPayload because
            # run_ise_push() receives all necessary data as explicit args
            # and never reads self.payload.
            runner = CertificateRequestRunner(db, None, emit)
            runner.run_ise_push(
                cert_pem=payload.cert_pem,
                key_pem=payload.key_pem,
                common_name=payload.common_name,
                node_ids=payload.node_ids,
                portal_group_tag=payload.portal_group_tag,
                certificate_mode=payload.certificate_mode,
                phase=payload.phase,
            )
            phase_messages = {
                "ca_chain": "CA chain uploaded to ISE trusted certificate store",
                "leaf": "Leaf certificate imported and bound on ISE",
                "all": "Certificate pushed to ISE successfully",
            }
            events.put({
                "event": "complete",
                "data": {
                    "success": True,
                    "message": phase_messages.get(
                        payload.phase, "Certificate pushed to ISE successfully"
                    ),
                    "phase": payload.phase,
                },
            })
        except CertificateRequestError as e:
            logger.warning(f"ISE push failed: {e}")
            events.put({
                "event": "complete",
                "data": {"success": False, "message": str(e)},
            })
        except Exception as e:
            logger.exception("ISE push crashed")
            events.put({
                "event": "complete",
                "data": {"success": False, "message": f"Unexpected error: {e}"},
            })
        finally:
            db.close()
            events.put(None)

    threading.Thread(target=worker, daemon=True).start()
    return _sse_response(events)


@router.post("/download-bundle")
def download_certificate_bundle(payload: CertificateDownloadBundlePayload):
    """
    Return a ZIP archive containing the certificate (PEM) and private key.

    The archive contains:

    - ``certificate.pem`` — the full chain returned by the ACME CA
    - ``private_key.pem`` — the unencrypted PKCS8 private key
    - ``leaf.pem`` — the leaf (end-entity) certificate only
    - ``intermediate.pem`` — all intermediate CA certificates concatenated
    - ``root.pem`` — the root CA certificate (if available)
    - ``ca-chain.pem`` — intermediates + root concatenated (for importing
      into ISE or other trust stores)

    The split files are derived from the caller-supplied pre-split fields
    when present, or computed on-the-fly from ``cert_pem`` otherwise.
    The download filename is derived from the Common Name.
    """
    # Use caller-supplied split components when available; otherwise split
    # the full chain here so the endpoint works with older callers too.
    if payload.leaf_pem is not None:
        leaf = payload.leaf_pem
        intermediate = payload.intermediate_pem or ""
        root = payload.root_pem or ""
        ca_chain = payload.ca_chain_pem or (intermediate + root)
    else:
        components = split_certificate_chain(payload.cert_pem)
        leaf = components["leaf"]
        intermediate = components["intermediate"]
        root = components["root"]
        ca_chain = components["ca_chain"]

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("certificate.pem", payload.cert_pem)
        zf.writestr("private_key.pem", payload.key_pem)
        if leaf:
            zf.writestr("leaf.pem", leaf)
        if intermediate:
            zf.writestr("intermediate.pem", intermediate)
        if root:
            zf.writestr("root.pem", root)
        if ca_chain:
            zf.writestr("ca-chain.pem", ca_chain)

    safe_cn = _re.sub(r"[^\w\-.]", "_", payload.common_name)
    return FastAPIResponse(
        content=buf.getvalue(),
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="{safe_cn}-bundle.zip"',
        },
    )


def _describe_certificate(pem_block: str) -> dict:
    """Parse a single PEM certificate and return a human-readable summary."""
    cert = x509.load_pem_x509_certificate(
        (pem_block.strip() + "\n").encode("utf-8")
    )

    def _name_to_str(name: x509.Name) -> str:
        try:
            return name.rfc4514_string()
        except Exception:
            return str(name)

    def _cn(name: x509.Name) -> str:
        try:
            attrs = name.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
            return attrs[0].value if attrs else ""
        except Exception:
            return ""

    san_dns: list = []
    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        san_dns = list(san_ext.value.get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound:
        pass
    except Exception:
        pass

    try:
        fingerprint = cert.fingerprint(hashes.SHA256()).hex().upper()
        fingerprint_colon = ":".join(
            fingerprint[i:i + 2] for i in range(0, len(fingerprint), 2)
        )
    except Exception:
        fingerprint_colon = ""

    try:
        serial_hex = format(cert.serial_number, "X")
    except Exception:
        serial_hex = ""

    is_self_signed = cert.issuer == cert.subject

    # Use the *_utc variants where available to avoid deprecation warnings.
    try:
        not_before = cert.not_valid_before_utc.isoformat()
        not_after = cert.not_valid_after_utc.isoformat()
    except AttributeError:
        not_before = cert.not_valid_before.isoformat() + "Z"
        not_after = cert.not_valid_after.isoformat() + "Z"

    return {
        "subject": _name_to_str(cert.subject),
        "subject_cn": _cn(cert.subject),
        "issuer": _name_to_str(cert.issuer),
        "issuer_cn": _cn(cert.issuer),
        "serial_number": serial_hex,
        "not_before": not_before,
        "not_after": not_after,
        "san_dns": san_dns,
        "fingerprint_sha256": fingerprint_colon,
        "is_self_signed": is_self_signed,
        "pem": pem_block.strip() + "\n",
    }


@router.post("/decode-chain")
def decode_certificate_chain(payload: CertificateDecodePayload):
    """
    Parse a PEM bundle and return a human-readable summary of each
    certificate it contains.

    Used by the frontend to show the contents of the leaf or CA chain
    before the user confirms an ISE push.
    """
    if not payload.pem or not payload.pem.strip():
        return {"certificates": []}

    blocks = _split_pem_chain(payload.pem)
    certificates: list = []
    for idx, blk in enumerate(blocks):
        try:
            certificates.append(_describe_certificate(blk))
        except Exception as e:
            logger.warning(
                "decode-chain: failed to parse certificate block %d: %s", idx, e
            )
            certificates.append({
                "subject": "(unparseable)",
                "subject_cn": "",
                "issuer": "",
                "issuer_cn": "",
                "serial_number": "",
                "not_before": "",
                "not_after": "",
                "san_dns": [],
                "fingerprint_sha256": "",
                "is_self_signed": False,
                "pem": blk.strip() + "\n",
                "error": str(e),
            })

    return {"certificates": certificates}
