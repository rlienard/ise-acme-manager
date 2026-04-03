"""
Standalone ACME v2 client for LetsEncrypt DNS-01 challenge flow.

Implements RFC 8555 (ACME) using only `cryptography` and `requests`.
Used when acme_provider is 'letsencrypt' — bypasses ISE's built-in ACME
client and manages the certificate lifecycle externally.
"""

import base64
import hashlib
import json
import logging
import time

import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, utils
from cryptography.x509.oid import NameOID
from cryptography import x509

logger = logging.getLogger(__name__)

LETSENCRYPT_DIRECTORY = "https://acme-api.letsencrypt.org/directory"
LETSENCRYPT_STAGING_DIRECTORY = "https://acme-staging-v02.api.letsencrypt.org/directory"


def _b64url(data: bytes) -> str:
    """Base64url-encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    """Base64url-decode with padding restoration."""
    s += "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)


class ACMEv2Client:
    """Minimal ACME v2 client for DNS-01 challenges (LetsEncrypt)."""

    def __init__(self, directory_url: str, account_email: str,
                 account_key_pem: str = None):
        self.directory_url = directory_url or LETSENCRYPT_DIRECTORY
        self.account_email = account_email
        self.session = requests.Session()
        self.session.headers.update({"Content-Type": "application/jose+json"})
        self._directory = None
        self._account_url = None
        self._nonce = None

        # Load or generate EC P-256 account key
        if account_key_pem:
            self._account_key = serialization.load_pem_private_key(
                account_key_pem.encode("utf-8") if isinstance(account_key_pem, str)
                else account_key_pem,
                password=None,
            )
        else:
            self._account_key = ec.generate_private_key(ec.SECP256R1())

    # ── Key helpers ──────────────────────────────────────

    def get_account_key_pem(self) -> str:
        """Export the account private key as PEM (for persistence)."""
        return self._account_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode("utf-8")

    def _jwk(self) -> dict:
        """Return the JSON Web Key (public) for the account key."""
        pub = self._account_key.public_key()
        numbers = pub.public_numbers()
        # EC P-256 coordinates are 32 bytes each
        x_bytes = numbers.x.to_bytes(32, "big")
        y_bytes = numbers.y.to_bytes(32, "big")
        return {
            "kty": "EC",
            "crv": "P-256",
            "x": _b64url(x_bytes),
            "y": _b64url(y_bytes),
        }

    def _thumbprint(self) -> str:
        """JWK thumbprint per RFC 7638."""
        jwk = self._jwk()
        # Canonical JSON with sorted keys, no whitespace
        canonical = json.dumps(
            {"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"], "y": jwk["y"]},
            separators=(",", ":"), sort_keys=True,
        )
        digest = hashlib.sha256(canonical.encode("utf-8")).digest()
        return _b64url(digest)

    def _sign_jws(self, url: str, payload: dict | str | None) -> dict:
        """Build a JWS request body (Flattened JSON Serialization)."""
        protected = {"alg": "ES256", "nonce": self._get_nonce(), "url": url}
        if self._account_url:
            protected["kid"] = self._account_url
        else:
            protected["jwk"] = self._jwk()

        protected_b64 = _b64url(json.dumps(protected).encode("utf-8"))

        if payload is None:
            # POST-as-GET
            payload_b64 = ""
        elif payload == "":
            payload_b64 = ""
        else:
            payload_b64 = _b64url(json.dumps(payload).encode("utf-8"))

        sign_input = f"{protected_b64}.{payload_b64}".encode("ascii")

        # ES256 signature: sign with SHA-256, then convert DER to raw r||s
        der_sig = self._account_key.sign(sign_input, ec.ECDSA(hashes.SHA256()))
        r, s = utils.decode_dss_signature(der_sig)
        sig_bytes = r.to_bytes(32, "big") + s.to_bytes(32, "big")

        return {
            "protected": protected_b64,
            "payload": payload_b64,
            "signature": _b64url(sig_bytes),
        }

    # ── Nonce / directory ────────────────────────────────

    def _get_directory(self) -> dict:
        if not self._directory:
            resp = self.session.get(self.directory_url, timeout=30)
            resp.raise_for_status()
            self._directory = resp.json()
        return self._directory

    def _get_nonce(self) -> str:
        if self._nonce:
            nonce = self._nonce
            self._nonce = None
            return nonce
        directory = self._get_directory()
        resp = requests.head(directory["newNonce"], timeout=10)
        return resp.headers["Replay-Nonce"]

    def _post(self, url: str, payload=None, expected=(200, 201)) -> requests.Response:
        """Signed POST to ACME endpoint with automatic nonce refresh."""
        body = self._sign_jws(url, payload)
        resp = self.session.post(url, json=body, timeout=30)
        # Save nonce for next request
        if "Replay-Nonce" in resp.headers:
            self._nonce = resp.headers["Replay-Nonce"]
        if resp.status_code not in expected:
            logger.error(f"ACME request failed: {resp.status_code} {resp.text}")
            resp.raise_for_status()
        return resp

    # ── Account ──────────────────────────────────────────

    def register_account(self) -> str:
        """Register or fetch existing account. Returns account URL."""
        directory = self._get_directory()
        payload = {
            "termsOfServiceAgreed": True,
            "contact": [f"mailto:{self.account_email}"],
        }
        resp = self._post(directory["newAccount"], payload, expected=(200, 201))
        self._account_url = resp.headers["Location"]
        logger.info(f"ACME account registered/found: {self._account_url}")
        return self._account_url

    # ── Order flow ───────────────────────────────────────

    def create_order(self, domains: list[str]) -> dict:
        """Create a new certificate order."""
        directory = self._get_directory()
        payload = {
            "identifiers": [{"type": "dns", "value": d} for d in domains],
        }
        resp = self._post(directory["newOrder"], payload)
        order = resp.json()
        order["order_url"] = resp.headers["Location"]
        logger.info(f"ACME order created: {order['order_url']} for {domains}")
        return order

    def get_authorization(self, authz_url: str) -> dict:
        """Fetch authorization object (POST-as-GET)."""
        resp = self._post(authz_url, payload=None)
        return resp.json()

    def get_dns01_challenge(self, authz: dict) -> dict:
        """Extract the dns-01 challenge from an authorization."""
        for ch in authz.get("challenges", []):
            if ch["type"] == "dns-01":
                return ch
        raise ValueError("No dns-01 challenge found in authorization")

    def get_dns_txt_value(self, token: str) -> str:
        """Compute the TXT record value for a dns-01 challenge."""
        key_authz = f"{token}.{self._thumbprint()}"
        digest = hashlib.sha256(key_authz.encode("utf-8")).digest()
        return _b64url(digest)

    def get_dns_record_name(self, domain: str) -> str:
        """Return the DNS record name for the challenge."""
        return f"_acme-challenge.{domain}"

    def respond_to_challenge(self, challenge_url: str):
        """Tell the ACME server we are ready for validation."""
        self._post(challenge_url, payload={}, expected=(200,))
        logger.info(f"Challenge response sent: {challenge_url}")

    def poll_authorization(self, authz_url: str, max_wait: int = 120,
                           interval: int = 5) -> dict:
        """Poll until authorization is valid or fails."""
        elapsed = 0
        while elapsed < max_wait:
            authz = self.get_authorization(authz_url)
            status = authz.get("status")
            if status == "valid":
                return authz
            if status in ("invalid", "deactivated", "expired", "revoked"):
                raise RuntimeError(f"Authorization failed with status: {status}")
            time.sleep(interval)
            elapsed += interval
        raise TimeoutError(f"Authorization not valid after {max_wait}s")

    def finalize_order(self, order: dict, common_name: str,
                       san_names: list[str] = None) -> tuple[str, str]:
        """
        Finalize the order by submitting a CSR.

        Returns (cert_pem, private_key_pem).
        """
        # Generate a new private key for the certificate
        cert_key = ec.generate_private_key(ec.SECP256R1())
        cert_key_pem = cert_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode("utf-8")

        # Build CSR
        builder = x509.CertificateSigningRequestBuilder()
        builder = builder.subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]))

        all_names = [common_name] + (san_names or [])
        unique_names = list(dict.fromkeys(all_names))  # deduplicate, preserve order
        san_entries = []
        for name in unique_names:
            if name.startswith("*."):
                san_entries.append(x509.DNSName(name))
            else:
                san_entries.append(x509.DNSName(name))
        builder = builder.add_extension(
            x509.SubjectAlternativeName(san_entries), critical=False,
        )

        csr = builder.sign(cert_key, hashes.SHA256())
        csr_der = csr.public_bytes(serialization.Encoding.DER)

        # Submit CSR
        finalize_url = order["finalize"]
        payload = {"csr": _b64url(csr_der)}
        resp = self._post(finalize_url, payload)
        order_resp = resp.json()

        # Poll for certificate
        order_url = order.get("order_url")
        cert_url = order_resp.get("certificate")
        if not cert_url:
            cert_url = self._poll_order_ready(order_url)

        # Download certificate
        cert_resp = self._post(cert_url, payload=None)
        cert_pem = cert_resp.text

        logger.info(f"Certificate obtained for {common_name}")
        return cert_pem, cert_key_pem

    def _poll_order_ready(self, order_url: str, max_wait: int = 180,
                          interval: int = 5) -> str:
        """Poll order until certificate URL is available."""
        elapsed = 0
        while elapsed < max_wait:
            resp = self._post(order_url, payload=None)
            order = resp.json()
            if order.get("status") == "valid" and order.get("certificate"):
                return order["certificate"]
            if order.get("status") in ("invalid",):
                raise RuntimeError(f"Order failed: {order}")
            time.sleep(interval)
            elapsed += interval
        raise TimeoutError(f"Order not ready after {max_wait}s")
