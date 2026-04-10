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
import re
import time

import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils
from cryptography.x509.oid import NameOID
from cryptography import x509

logger = logging.getLogger(__name__)

LETSENCRYPT_DIRECTORY = "https://acme-v02.api.letsencrypt.org/directory"
LETSENCRYPT_STAGING_DIRECTORY = "https://acme-staging-v02.api.letsencrypt.org/directory"


# ISE-compatible key types → (algorithm, parameters) used to generate the
# certificate private key during CSR build. Keeping this mapping in one place
# ensures the renewal flow honors whatever the user selected on the managed
# certificate (or cloned from the inspected source cert).
_KEY_TYPE_GENERATORS = {
    "RSA_2048": ("rsa", 2048),
    "RSA_3072": ("rsa", 3072),
    "RSA_4096": ("rsa", 4096),
    "ECDSA_256": ("ec", ec.SECP256R1),
    "ECDSA_384": ("ec", ec.SECP384R1),
    "ECDSA_521": ("ec", ec.SECP521R1),
}


# Short subject-DN labels understood by finalize_order() when building the
# CSR. Values are taken from the InspectedCertificate / ManagedCertificate
# ``subject`` dict so we can preserve O / OU / C / ST / L / emailAddress
# across renewals. Unknown keys are ignored.
_SUBJECT_LABEL_TO_OID = {
    "CN": NameOID.COMMON_NAME,
    "C": NameOID.COUNTRY_NAME,
    "ST": NameOID.STATE_OR_PROVINCE_NAME,
    "L": NameOID.LOCALITY_NAME,
    "O": NameOID.ORGANIZATION_NAME,
    "OU": NameOID.ORGANIZATIONAL_UNIT_NAME,
    "emailAddress": NameOID.EMAIL_ADDRESS,
    "serialNumber": NameOID.SERIAL_NUMBER,
    "GN": NameOID.GIVEN_NAME,
    "SN": NameOID.SURNAME,
    "title": NameOID.TITLE,
    "street": NameOID.STREET_ADDRESS,
    "postalCode": NameOID.POSTAL_CODE,
    "DC": NameOID.DOMAIN_COMPONENT,
}


def _generate_cert_key(key_type: str):
    """Generate a new private key that matches ISE's key_type labels."""
    spec = _KEY_TYPE_GENERATORS.get((key_type or "").upper())
    if spec is None:
        logger.warning(
            f"Unknown key_type '{key_type}', defaulting to RSA_2048"
        )
        spec = _KEY_TYPE_GENERATORS["RSA_2048"]
    kind, param = spec
    if kind == "rsa":
        return rsa.generate_private_key(public_exponent=65537, key_size=param)
    # EC curve — ``param`` is the curve class
    return ec.generate_private_key(param())


def _build_subject_name(common_name: str, subject: dict | None) -> x509.Name:
    """Build an x509.Name from a subject dict, always including the CN."""
    attrs: list[x509.NameAttribute] = []
    if subject:
        for label, value in subject.items():
            if value in (None, "", [], {}):
                continue
            oid = _SUBJECT_LABEL_TO_OID.get(label)
            if oid is None:
                continue
            # The inspected subject stores single values as strings and
            # multi-valued RDNs as lists — normalize to a list for iteration.
            values = value if isinstance(value, list) else [value]
            for v in values:
                if not v:
                    continue
                if oid == NameOID.COMMON_NAME:
                    # Honor the canonical CN from the managed cert row, not
                    # whatever drifted into the inspected snapshot.
                    continue
                attrs.append(x509.NameAttribute(oid, str(v)))
    if common_name:
        attrs.insert(0, x509.NameAttribute(NameOID.COMMON_NAME, common_name))
    if not attrs:
        attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, common_name or ""))
    return x509.Name(attrs)


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
                       san_names: list[str] = None,
                       key_type: str = "RSA_2048",
                       subject: dict | None = None) -> tuple[str, str]:
        """
        Finalize the order by submitting a CSR.

        The certificate private key is generated according to ``key_type``
        (e.g. RSA_2048, RSA_4096, ECDSA_256) so the renewed certificate
        matches whatever the managed certificate row configured. If
        ``subject`` is provided, its components (O, OU, C, ST, L, …) are
        copied into the CSR so renewals preserve the full subject DN of
        the certificate that was cloned from ISE.

        Returns (cert_pem, private_key_pem).
        """
        # Generate a new private key matching the requested key type
        cert_key = _generate_cert_key(key_type)
        cert_key_pem = cert_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode("utf-8")

        # Build CSR with full subject DN (CN plus any cloned components)
        builder = x509.CertificateSigningRequestBuilder()
        builder = builder.subject_name(_build_subject_name(common_name, subject))

        all_names = [common_name] + (san_names or [])
        unique_names = list(dict.fromkeys(all_names))  # deduplicate, preserve order
        san_entries = [x509.DNSName(name) for name in unique_names if name]
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

        # For staging environments whose root CA is not in any device
        # trust store, prefer an alternate chain that includes the
        # self-signed root (RFC 8555 §7.4.2 Link rel="alternate").
        cert_pem = self._prefer_chain_with_root(cert_pem, cert_resp)

        # Log the downloaded certificate chain for diagnostics.
        pem_blocks = re.findall(
            r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
            cert_pem,
            re.DOTALL,
        )
        logger.info(
            "Certificate obtained for %s — chain contains %d certificate(s)",
            common_name, len(pem_blocks),
        )
        for idx, block in enumerate(pem_blocks):
            try:
                cert_obj = x509.load_pem_x509_certificate(
                    (block.strip() + "\n").encode("utf-8")
                )
                subj_cn = cert_obj.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
                iss_cn = cert_obj.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
                is_self_signed = cert_obj.issuer == cert_obj.subject
                logger.info(
                    "  [%d] Subject: %s | Issuer: %s%s",
                    idx,
                    subj_cn[0].value if subj_cn else "(no CN)",
                    iss_cn[0].value if iss_cn else "(no CN)",
                    " (self-signed root)" if is_self_signed else "",
                )
            except Exception:
                logger.info("  [%d] (could not parse certificate)", idx)

        return cert_pem, cert_key_pem

    def _prefer_chain_with_root(
        self, cert_pem: str, cert_resp: requests.Response,
    ) -> str:
        """Return a chain that includes the self-signed root, if available.

        ACME servers may offer alternate certificate chains via ``Link``
        headers (RFC 8555 §7.4.2).  For staging environments such as
        Let's Encrypt staging, the root CA is not in any device trust
        store.  An alternate chain that extends to the self-signed root
        lets the ISE import flow add the root to the trusted store
        without relying on AIA URLs (which may serve certificates from
        a different chain path).

        If the default chain already contains a self-signed root or no
        alternate chain is available, the original *cert_pem* is
        returned unchanged.
        """
        blocks = re.findall(
            r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
            cert_pem,
            re.DOTALL,
        )
        if len(blocks) < 2:
            return cert_pem

        # Check if the default chain already ends with a self-signed root.
        try:
            top = x509.load_pem_x509_certificate(
                (blocks[-1].strip() + "\n").encode("utf-8")
            )
            if top.issuer == top.subject:
                return cert_pem  # already has root
        except Exception:
            return cert_pem

        # Parse alternate chain URL(s) from Link headers.
        alt_urls: list[str] = []
        for part in cert_resp.headers.get("Link", "").split(","):
            part = part.strip()
            if 'rel="alternate"' in part:
                m = re.search(r"<([^>]+)>", part)
                if m:
                    alt_urls.append(m.group(1))

        for alt_url in alt_urls:
            try:
                alt_resp = self._post(alt_url, payload=None)
                alt_pem = alt_resp.text
                alt_blocks = re.findall(
                    r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
                    alt_pem,
                    re.DOTALL,
                )
                if len(alt_blocks) < 2:
                    continue
                alt_top = x509.load_pem_x509_certificate(
                    (alt_blocks[-1].strip() + "\n").encode("utf-8")
                )
                if alt_top.issuer == alt_top.subject:
                    top_cn = alt_top.subject.get_attributes_for_oid(
                        NameOID.COMMON_NAME
                    )
                    logger.info(
                        "Default chain has %d cert(s) without self-signed "
                        "root. Using alternate chain with %d cert(s) "
                        "including self-signed root '%s'.",
                        len(blocks),
                        len(alt_blocks),
                        top_cn[0].value if top_cn else "(no CN)",
                    )
                    return alt_pem
            except Exception as exc:
                logger.info(
                    "Could not fetch alternate chain from %s: %s",
                    alt_url, exc,
                )

        logger.info(
            "No alternate chain with self-signed root found; "
            "using default chain (%d certificate(s)). "
            "The root CA will be resolved via AIA.",
            len(blocks),
        )
        return cert_pem

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


# ── Provider connectivity test ─────────────────────────────────

# Endpoints any RFC 8555 directory must expose. We use this list to detect
# directory URLs that respond with JSON but aren't actually ACME servers.
_REQUIRED_DIRECTORY_KEYS = ("newAccount", "newOrder", "newNonce")


def test_acme_provider(
    provider_type: str,
    directory_url: str,
    account_email: str | None = None,
    account_key_pem: str | None = None,
    kid: str | None = None,
    hmac_key: str | None = None,
) -> dict:
    """Validate an ACME provider configuration end-to-end (no cert issued).

    The test runs the same handshake an actual renewal would perform up to
    the point of creating an order:

    1. Fetch the directory URL and check it exposes the required RFC 8555
       endpoints.
    2. Pull a fresh nonce from ``newNonce`` to confirm the server is alive.
    3. For LetsEncrypt only, register or look up the account using the
       configured email + account key. This is the safest way to detect a
       mismatched directory URL (e.g. a "letsencrypt" provider that's still
       pointing at DigiCert) because LetsEncrypt is the only flow we drive
       end-to-end from this daemon.

    Returns ``{"success": bool, "message": str, "details": {...}}`` and never
    raises — failures are reported via ``success=False`` so the API layer
    can surface a clean message to the UI.
    """
    details: dict = {"directory_url": directory_url, "provider_type": provider_type}

    if not directory_url:
        return {
            "success": False,
            "message": "ACME directory URL is empty",
            "details": details,
        }

    # ── 1. Directory metadata ─────────────────────────────
    try:
        resp = requests.get(directory_url, timeout=15)
    except requests.exceptions.RequestException as e:
        return {
            "success": False,
            "message": f"Could not reach ACME directory: {e}",
            "details": details,
        }

    if resp.status_code != 200:
        return {
            "success": False,
            "message": (
                f"ACME directory returned HTTP {resp.status_code}. "
                "Verify the directory URL — for Let's Encrypt it should be "
                "https://acme-v02.api.letsencrypt.org/directory (or the "
                "staging URL https://acme-staging-v02.api.letsencrypt.org/directory)."
            ),
            "details": details,
        }

    try:
        directory = resp.json()
    except ValueError:
        return {
            "success": False,
            "message": "ACME directory did not return JSON — wrong URL?",
            "details": details,
        }

    missing = [k for k in _REQUIRED_DIRECTORY_KEYS if k not in directory]
    if missing:
        return {
            "success": False,
            "message": (
                f"Directory is missing required ACME endpoint(s): {', '.join(missing)}. "
                "This usually means the URL is not an RFC 8555 directory."
            ),
            "details": details,
        }

    details["endpoints"] = {k: directory.get(k) for k in _REQUIRED_DIRECTORY_KEYS}
    details["meta"] = directory.get("meta") or {}

    # Cross-check provider_type vs the directory host so a "letsencrypt"
    # provider pointed at DigiCert (the bug that motivates this feature)
    # is flagged before we even hit newNonce.
    host = (directory_url or "").lower()
    if provider_type == "letsencrypt" and "letsencrypt" not in host:
        return {
            "success": False,
            "message": (
                "Directory URL does not look like a Let's Encrypt endpoint. "
                "Expected something under acme-v02.api.letsencrypt.org or "
                "acme-staging-v02.api.letsencrypt.org."
            ),
            "details": details,
        }
    if provider_type == "digicert" and "digicert" not in host:
        return {
            "success": False,
            "message": (
                "Directory URL does not look like a DigiCert endpoint. "
                "Expected something under acme.digicert.com."
            ),
            "details": details,
        }

    # ── 2. Fresh nonce ────────────────────────────────────
    new_nonce_url = directory.get("newNonce")
    try:
        nonce_resp = requests.head(new_nonce_url, timeout=15)
    except requests.exceptions.RequestException as e:
        return {
            "success": False,
            "message": f"Could not fetch a nonce from {new_nonce_url}: {e}",
            "details": details,
        }
    if "Replay-Nonce" not in nonce_resp.headers:
        return {
            "success": False,
            "message": (
                f"newNonce endpoint did not return a Replay-Nonce header "
                f"(HTTP {nonce_resp.status_code}). The server may not be a "
                "valid ACME directory."
            ),
            "details": details,
        }

    # ── 3. Provider-specific credential checks ────────────
    if provider_type == "letsencrypt":
        if not account_email:
            return {
                "success": False,
                "message": (
                    "Directory reachable, but no account email is configured. "
                    "Let's Encrypt requires an account email."
                ),
                "details": details,
            }
        try:
            client = ACMEv2Client(
                directory_url=directory_url,
                account_email=account_email,
                account_key_pem=account_key_pem or None,
            )
            account_url = client.register_account()
        except requests.exceptions.HTTPError as e:
            body = ""
            try:
                body = e.response.text if e.response is not None else ""
            except Exception:
                pass
            return {
                "success": False,
                "message": (
                    f"Account registration failed: {e}. "
                    f"{body[:300] if body else ''}"
                ).strip(),
                "details": details,
            }
        except Exception as e:
            return {
                "success": False,
                "message": f"Account registration failed: {e}",
                "details": details,
            }

        details["account_url"] = account_url
        return {
            "success": True,
            "message": (
                f"Connected to Let's Encrypt directory and "
                f"{'reused existing' if account_key_pem else 'registered new'} "
                f"account for {account_email}"
            ),
            "details": details,
        }

    if provider_type == "digicert":
        meta = details.get("meta") or {}
        eab_required = bool(meta.get("externalAccountRequired"))
        if eab_required and (not kid or not hmac_key):
            return {
                "success": False,
                "message": (
                    "DigiCert directory reachable, but it requires External "
                    "Account Binding and the Key ID / HMAC key are not "
                    "configured on this provider."
                ),
                "details": details,
            }
        return {
            "success": True,
            "message": (
                "Connected to DigiCert ACME directory. "
                + ("EAB credentials present." if (kid and hmac_key) else "No EAB credentials configured.")
            ),
            "details": details,
        }

    # Unknown provider — directory is at least valid ACME.
    return {
        "success": True,
        "message": "ACME directory reachable and exposes the required endpoints.",
        "details": details,
    }
