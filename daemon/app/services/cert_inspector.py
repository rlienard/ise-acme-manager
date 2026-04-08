"""
Certificate Inspector — parses X.509 certificates (PEM) and extracts all
relevant attributes (subject, SANs, key usage, EKU, validity, etc.)
so they can be copied onto a new managed certificate.
"""

import base64
import io
import logging
import re
import zipfile
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, ed25519, ed448
from cryptography.x509.oid import ExtensionOID, NameOID

logger = logging.getLogger(__name__)


# Subject component name → short attribute label
_NAME_OID_MAP = {
    NameOID.COMMON_NAME: "CN",
    NameOID.COUNTRY_NAME: "C",
    NameOID.LOCALITY_NAME: "L",
    NameOID.STATE_OR_PROVINCE_NAME: "ST",
    NameOID.ORGANIZATION_NAME: "O",
    NameOID.ORGANIZATIONAL_UNIT_NAME: "OU",
    NameOID.EMAIL_ADDRESS: "emailAddress",
    NameOID.SERIAL_NUMBER: "serialNumber",
    NameOID.DN_QUALIFIER: "dnQualifier",
    NameOID.GIVEN_NAME: "GN",
    NameOID.SURNAME: "SN",
    NameOID.TITLE: "title",
    NameOID.STREET_ADDRESS: "street",
    NameOID.POSTAL_CODE: "postalCode",
    NameOID.DOMAIN_COMPONENT: "DC",
}


# Extended Key Usage OID → friendly label
_EKU_LABELS = {
    "1.3.6.1.5.5.7.3.1": "serverAuth",
    "1.3.6.1.5.5.7.3.2": "clientAuth",
    "1.3.6.1.5.5.7.3.3": "codeSigning",
    "1.3.6.1.5.5.7.3.4": "emailProtection",
    "1.3.6.1.5.5.7.3.8": "timeStamping",
    "1.3.6.1.5.5.7.3.9": "OCSPSigning",
    "1.3.6.1.4.1.311.20.2.2": "smartcardLogon",
    "1.3.6.1.5.2.3.4": "pkinitKDC",
}


def _name_to_dict(name: x509.Name) -> dict:
    """Convert an x509.Name into a dict keyed by short attribute labels."""
    result: dict[str, list[str]] = {}
    for attr in name:
        label = _NAME_OID_MAP.get(attr.oid, attr.oid.dotted_string)
        result.setdefault(label, []).append(str(attr.value))
    # Flatten single-value entries for easier consumption in the UI
    return {k: (v[0] if len(v) == 1 else v) for k, v in result.items()}


def _name_to_rfc4514(name: x509.Name) -> str:
    """Render an x509.Name in RFC 4514 (human-readable DN) form."""
    try:
        return name.rfc4514_string()
    except Exception:
        return ", ".join(f"{_NAME_OID_MAP.get(a.oid, a.oid.dotted_string)}={a.value}" for a in name)


def _extract_sans(cert: x509.Certificate) -> dict:
    """Return all Subject Alternative Name entries grouped by type."""
    dns: list[str] = []
    ip: list[str] = []
    email: list[str] = []
    uri: list[str] = []
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        san = ext.value
        dns = [str(v) for v in san.get_values_for_type(x509.DNSName)]
        ip = [str(v) for v in san.get_values_for_type(x509.IPAddress)]
        email = [str(v) for v in san.get_values_for_type(x509.RFC822Name)]
        uri = [str(v) for v in san.get_values_for_type(x509.UniformResourceIdentifier)]
    except x509.ExtensionNotFound:
        pass
    return {"dns": dns, "ip": ip, "email": email, "uri": uri}


def _extract_key_usage(cert: x509.Certificate) -> list[str]:
    """Return the set of active KeyUsage flags."""
    try:
        ku = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
    except x509.ExtensionNotFound:
        return []

    flags = []
    for name in (
        "digital_signature",
        "content_commitment",
        "key_encipherment",
        "data_encipherment",
        "key_agreement",
        "key_cert_sign",
        "crl_sign",
    ):
        if getattr(ku, name, False):
            flags.append(name)
    # encipher_only / decipher_only are only valid when key_agreement=True
    if getattr(ku, "key_agreement", False):
        try:
            if ku.encipher_only:
                flags.append("encipher_only")
        except ValueError:
            pass
        try:
            if ku.decipher_only:
                flags.append("decipher_only")
        except ValueError:
            pass
    return flags


def _extract_eku(cert: x509.Certificate) -> list[str]:
    """Return the list of Extended Key Usage labels."""
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value
    except x509.ExtensionNotFound:
        return []
    return [_EKU_LABELS.get(oid.dotted_string, oid.dotted_string) for oid in ext]


def _extract_basic_constraints(cert: x509.Certificate) -> Optional[dict]:
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
    except x509.ExtensionNotFound:
        return None
    return {"ca": bool(ext.ca), "path_length": ext.path_length}


def _describe_public_key(cert: x509.Certificate) -> dict:
    """Return a human-friendly description of the certificate's public key."""
    pk = cert.public_key()
    if isinstance(pk, rsa.RSAPublicKey):
        size = pk.key_size
        return {
            "algorithm": "RSA",
            "key_size": size,
            "key_type": f"RSA_{size}" if size in (2048, 3072, 4096) else f"RSA_{size}",
        }
    if isinstance(pk, ec.EllipticCurvePublicKey):
        curve = pk.curve.name
        # Map common curves back to ISE-compatible key types.
        curve_key_type = {
            "secp256r1": "ECDSA_256",
            "secp384r1": "ECDSA_384",
            "secp521r1": "ECDSA_521",
        }.get(curve, f"EC_{curve}")
        return {
            "algorithm": "ECDSA",
            "curve": curve,
            "key_size": pk.curve.key_size,
            "key_type": curve_key_type,
        }
    if isinstance(pk, dsa.DSAPublicKey):
        return {"algorithm": "DSA", "key_size": pk.key_size, "key_type": f"DSA_{pk.key_size}"}
    if isinstance(pk, ed25519.Ed25519PublicKey):
        return {"algorithm": "Ed25519", "key_size": 256, "key_type": "ED25519"}
    if isinstance(pk, ed448.Ed448PublicKey):
        return {"algorithm": "Ed448", "key_size": 448, "key_type": "ED448"}
    return {"algorithm": "unknown", "key_type": "RSA_2048"}


def _fingerprint(cert: x509.Certificate, algo) -> str:
    return cert.fingerprint(algo).hex(":").upper()


def parse_pem_certificate(pem_data: bytes | str) -> dict:
    """
    Parse a PEM-encoded X.509 certificate and return a dictionary containing
    all fields relevant to cloning a new certificate from an existing one.
    """
    if isinstance(pem_data, str):
        pem_bytes = pem_data.encode("utf-8")
    else:
        pem_bytes = pem_data

    # cryptography only accepts the first cert in a bundle. Trim to the leaf cert.
    match = re.search(
        rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
        pem_bytes,
        re.DOTALL,
    )
    if match:
        pem_bytes = match.group(0)

    try:
        cert = x509.load_pem_x509_certificate(pem_bytes)
    except ValueError:
        # Fall back to DER in case the caller handed us raw DER bytes.
        cert = x509.load_der_x509_certificate(pem_bytes)

    subject_dict = _name_to_dict(cert.subject)
    issuer_dict = _name_to_dict(cert.issuer)
    sans = _extract_sans(cert)

    # "san_names" is a flat list suitable for the managed-certificate form,
    # combining DNS names and string IP entries, preserving order and uniqueness.
    san_flat: list[str] = []
    for value in (*sans["dns"], *sans["ip"]):
        if value and value not in san_flat:
            san_flat.append(value)

    common_name = subject_dict.get("CN") if isinstance(subject_dict.get("CN"), str) else None
    if isinstance(subject_dict.get("CN"), list):
        common_name = subject_dict["CN"][0] if subject_dict["CN"] else None

    key_info = _describe_public_key(cert)

    return {
        "subject_dn": _name_to_rfc4514(cert.subject),
        "subject": subject_dict,
        "common_name": common_name or "",
        "issuer_dn": _name_to_rfc4514(cert.issuer),
        "issuer": issuer_dict,
        "serial_number": format(cert.serial_number, "X"),
        "not_before": cert.not_valid_before_utc.isoformat() if hasattr(cert, "not_valid_before_utc") else cert.not_valid_before.isoformat(),
        "not_after": cert.not_valid_after_utc.isoformat() if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after.isoformat(),
        "signature_algorithm": cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else None,
        "version": cert.version.name,
        "san_names": san_flat,
        "san": sans,
        "key_usage": _extract_key_usage(cert),
        "extended_key_usage": _extract_eku(cert),
        "basic_constraints": _extract_basic_constraints(cert),
        "public_key": key_info,
        "key_type": key_info.get("key_type", "RSA_2048"),
        "fingerprint_sha1": _fingerprint(cert, hashes.SHA1()),
        "fingerprint_sha256": _fingerprint(cert, hashes.SHA256()),
        "pem": cert.public_bytes(serialization.Encoding.PEM).decode("ascii"),
    }


def extract_pem_from_ise_export(payload) -> str:
    """
    Normalize the many possible shapes of an ISE export response into a PEM
    string containing (at least) the leaf certificate.

    ISE versions differ in how they respond:
      • JSON: ``{"response": {"certData": "-----BEGIN CERTIFICATE-----..."}}``
      • JSON: ``{"certData": "...", "privateKeyData": "..."}``
      • JSON: ``{"response": {"fileData": "<base64-encoded ZIP>"}}``
      • Raw binary: a ZIP file containing ``.pem`` / ``.cer`` / ``.crt`` entries
    """
    # Already a PEM string
    if isinstance(payload, (bytes, bytearray)):
        # Could be a ZIP or a raw PEM
        data = bytes(payload)
        if data.startswith(b"PK\x03\x04"):
            return _pem_from_zip_bytes(data)
        text = data.decode("utf-8", errors="replace")
        if "BEGIN CERTIFICATE" in text:
            return text
        # Could be base64-wrapped
        try:
            decoded = base64.b64decode(data, validate=False)
            if decoded.startswith(b"PK\x03\x04"):
                return _pem_from_zip_bytes(decoded)
            if b"BEGIN CERTIFICATE" in decoded:
                return decoded.decode("utf-8", errors="replace")
        except Exception:
            pass
        raise ValueError("ISE export response is not a recognized certificate format")

    if isinstance(payload, str):
        if "BEGIN CERTIFICATE" in payload:
            return payload
        # Assume base64-encoded ZIP or PEM
        try:
            decoded = base64.b64decode(payload, validate=False)
        except Exception as e:
            raise ValueError(f"ISE export string is not PEM or base64: {e}")
        return extract_pem_from_ise_export(decoded)

    if isinstance(payload, dict):
        # Peel the "response" wrapper if present
        inner = payload.get("response", payload) or payload
        if isinstance(inner, dict):
            for key in ("certData", "certificateData", "certificate", "pem", "data"):
                value = inner.get(key)
                if isinstance(value, str) and "BEGIN CERTIFICATE" in value:
                    return value
            for key in ("fileData", "fileContent", "zipData", "data"):
                value = inner.get(key)
                if isinstance(value, str) and value:
                    try:
                        return extract_pem_from_ise_export(value)
                    except ValueError:
                        continue
        elif isinstance(inner, str):
            return extract_pem_from_ise_export(inner)

    raise ValueError("Unable to locate certificate data in ISE export response")


def _pem_from_zip_bytes(zip_bytes: bytes, password: Optional[bytes] = None) -> str:
    """Extract the first PEM-looking entry from a ZIP archive."""
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        names = zf.namelist()
        # Prefer files that look like certs (not keys)
        preferred = [n for n in names if re.search(r"\.(pem|cer|crt)$", n, re.I) and "key" not in n.lower()]
        candidates = preferred or names
        for name in candidates:
            try:
                data = zf.read(name, pwd=password)
            except RuntimeError:
                # Encrypted archive we can't open; skip and let caller handle.
                continue
            text = data.decode("utf-8", errors="replace")
            if "BEGIN CERTIFICATE" in text:
                return text
    raise ValueError("ZIP archive from ISE does not contain a PEM certificate")
