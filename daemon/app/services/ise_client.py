"""
Cisco ISE API Client — handles all ISE interactions.
"""

import logging
import re
import secrets
import string
import time

import requests
import urllib3
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from datetime import datetime

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = logging.getLogger(__name__)


def _encrypt_private_key(private_key_pem: str) -> "tuple[str, str]":
    """
    Re-serialize a PEM private key as an encrypted PEM blob.

    Cisco ISE's ``POST /api/v1/certs/system-certificate/import`` endpoint
    rejects unencrypted private keys with a generic "Security Check
    Failed" error. LetsEncrypt issues unencrypted keys, so we wrap the
    key with a one-shot random passphrase and send the passphrase in
    the ``password`` field of the import payload.

    Uses the traditional OpenSSL PEM encryption format (``Proc-Type:
    4,ENCRYPTED`` / ``DEK-Info`` headers) rather than PKCS#8
    EncryptedPrivateKeyInfo. The PKCS#8 format uses PBES2 with
    PBKDF2-SHA512 + AES-256-CBC, which some ISE versions cannot decrypt
    due to Java JCE policy restrictions. The traditional OpenSSL format
    uses a simpler key derivation that all ISE versions support.

    Returns ``(encrypted_pem, password)``. If the key is already in
    encrypted form the caller should skip this helper.
    """
    # 16-character alphanumeric passphrase — ISE rejects passwords that
    # are shorter than 8 chars or contain non-alphanumerics.
    alphabet = string.ascii_letters + string.digits
    password = "".join(secrets.choice(alphabet) for _ in range(16))

    key = serialization.load_pem_private_key(
        private_key_pem.encode("utf-8") if isinstance(private_key_pem, str)
        else private_key_pem,
        password=None,
    )
    encrypted_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.BestAvailableEncryption(
            password.encode("utf-8")
        ),
    ).decode("utf-8")
    return encrypted_pem, password


def _split_pem_chain(pem_chain: str) -> "list[str]":
    """Split a concatenated PEM chain into individual PEM blocks.

    Returns a list where the first element is the leaf certificate and
    the remaining elements are intermediate/root CA certificates.
    """
    return re.findall(
        r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
        pem_chain,
        re.DOTALL,
    )


def _get_aki(cert_obj: x509.Certificate) -> "bytes | None":
    """Extract the Authority Key Identifier (key_identifier bytes), or *None*."""
    try:
        ext = cert_obj.extensions.get_extension_for_class(
            x509.AuthorityKeyIdentifier
        )
        return ext.value.key_identifier
    except x509.ExtensionNotFound:
        return None


def _get_ski(cert_obj: x509.Certificate) -> "bytes | None":
    """Extract the Subject Key Identifier (digest bytes), or *None*."""
    try:
        ext = cert_obj.extensions.get_extension_for_class(
            x509.SubjectKeyIdentifier
        )
        return ext.value.digest
    except x509.ExtensionNotFound:
        return None


def _build_chain_from_downloaded(pem_blocks: "list[str]") -> "list[str]":
    """Build the ordered CA certificate chain from downloaded PEM blocks.

    Given a list of PEM blocks where the first element is the leaf
    certificate and the remaining elements are CA certificates (in the
    order returned by the ACME server), walk from the leaf upward by
    matching each certificate's Authority Key Identifier (AKI) to the
    Subject Key Identifier (SKI) of the next certificate.  When AKI/SKI
    are not available, fall back to Issuer → Subject name matching.

    Returns the ordered chain of CA certificates (**excluding** the
    leaf), from closest-to-leaf to closest-to-root.  This is the
    *actual* trust path embedded in the downloaded certificate chain,
    which may differ from a path discovered via AIA extensions.
    """
    if len(pem_blocks) < 2:
        return []

    # Parse every block into an x509 object.
    parsed: "list[tuple[str, x509.Certificate | None]]" = []
    for block in pem_blocks:
        try:
            cert = x509.load_pem_x509_certificate(
                (block.strip() + "\n").encode("utf-8")
            )
            parsed.append((block, cert))
        except Exception:
            parsed.append((block, None))

    if parsed[0][1] is None:
        # Cannot parse the leaf — fall back to positional order.
        return [b for b, _ in parsed[1:]]

    chain: "list[str]" = []
    current = parsed[0][1]  # start from the leaf
    used: "set[int]" = {0}

    for _ in range(len(parsed)):
        current_aki = _get_aki(current)
        best_block: "str | None" = None
        best_cert: "x509.Certificate | None" = None
        best_idx: "int | None" = None

        for i, (block, cert) in enumerate(parsed):
            if i in used or cert is None:
                continue

            # Primary: AKI → SKI (strongest match).
            if current_aki is not None:
                candidate_ski = _get_ski(cert)
                if candidate_ski is not None:
                    if current_aki == candidate_ski:
                        best_block, best_cert, best_idx = block, cert, i
                        break  # exact cryptographic match
                    continue  # SKI available but doesn't match — skip

            # Fallback: Issuer name → Subject name.
            if cert.subject == current.issuer:
                best_block, best_cert, best_idx = block, cert, i
                # Don't break — keep looking for an AKI/SKI match.

        if best_block is None or best_cert is None or best_idx is None:
            break

        chain.append(best_block)
        used.add(best_idx)
        current = best_cert

        # Self-signed → root CA reached.
        if best_cert.issuer == best_cert.subject:
            break

    if chain:
        logger.info(
            "Built certificate chain from downloaded blocks: "
            "%d CA certificate(s) (leaf excluded)", len(chain),
        )
    return chain


def _resolve_issuer_chain(pem_block: str) -> "list[str]":
    """Follow AIA CA Issuers URLs to discover parent certificates.

    ACME providers (e.g. Let's Encrypt) include intermediates in the
    downloaded chain but typically omit the root CA.  ISE requires the
    issuer of every imported certificate to already be present in its
    trusted store, so we need the full chain up to the root.

    Starting from *pem_block*, this function reads the Authority
    Information Access (AIA) extension, downloads the issuer
    certificate, and repeats until it reaches a self-signed root or
    no more AIA URLs are available.

    Returns a list of PEM-encoded certificates (excluding the input),
    ordered from closest issuer to root.
    """
    chain: "list[str]" = []
    seen: "set[str]" = set()
    current_pem = pem_block

    for iteration in range(5):  # safety limit to prevent infinite loops
        try:
            cert_obj = x509.load_pem_x509_certificate(
                (current_pem.strip() + "\n").encode("utf-8")
            )
            cn_attrs = cert_obj.subject.get_attributes_for_oid(
                x509.oid.NameOID.COMMON_NAME
            )
            current_cn = cn_attrs[0].value if cn_attrs else "(no CN)"
        except Exception as exc:
            logger.warning(
                "AIA chain resolution: failed to parse PEM certificate "
                "at iteration %d: %s", iteration, exc,
            )
            break

        # Self-signed → root CA reached, nothing more to fetch.
        if cert_obj.issuer == cert_obj.subject:
            logger.info(
                "AIA chain resolution: reached self-signed root CA '%s'",
                current_cn,
            )
            break

        # Extract CA Issuers URL from the AIA extension.
        try:
            aia = cert_obj.extensions.get_extension_for_class(
                x509.AuthorityInformationAccess
            )
            issuer_urls = [
                desc.access_location.value
                for desc in aia.value
                if desc.access_method
                == x509.oid.AuthorityInformationAccessOID.CA_ISSUERS
            ]
        except x509.ExtensionNotFound:
            logger.warning(
                "AIA chain resolution: certificate '%s' has no AIA extension; "
                "cannot discover its issuer. The root CA may need to be "
                "imported into ISE manually.",
                current_cn,
            )
            break

        if not issuer_urls:
            logger.warning(
                "AIA chain resolution: AIA extension on '%s' contains no "
                "CA Issuers URLs; cannot discover its issuer. The root CA "
                "may need to be imported into ISE manually.",
                current_cn,
            )
            break

        issuer_url = issuer_urls[0]
        if issuer_url in seen:
            break  # avoid loops
        seen.add(issuer_url)

        logger.info(
            "AIA chain resolution: fetching issuer of '%s' from %s",
            current_cn, issuer_url,
        )
        resp = None
        max_attempts = 3
        for attempt in range(1, max_attempts + 1):
            try:
                resp = requests.get(issuer_url, timeout=20)
                resp.raise_for_status()
                break  # success
            except Exception as exc:
                if attempt < max_attempts:
                    wait = 2 ** (attempt - 1)
                    logger.info(
                        "AIA chain resolution: attempt %d/%d failed for %s: "
                        "%s — retrying in %ds",
                        attempt, max_attempts, issuer_url, exc, wait,
                    )
                    time.sleep(wait)
                else:
                    # Extract issuer CN for a helpful message.
                    try:
                        iss_cn_hint = cert_obj.issuer.get_attributes_for_oid(
                            x509.oid.NameOID.COMMON_NAME
                        )
                        issuer_hint = iss_cn_hint[0].value if iss_cn_hint else str(cert_obj.issuer)
                    except Exception:
                        issuer_hint = "(unknown)"
                    logger.warning(
                        "AIA chain resolution: all %d attempts failed to "
                        "fetch issuer certificate for '%s' from %s: %s. "
                        "The issuer CA '%s' must be imported into ISE's "
                        "trusted certificate store manually.",
                        max_attempts, current_cn, issuer_url, exc,
                        issuer_hint,
                    )
        if resp is None:
            break

        # The response is typically DER-encoded; convert to PEM.
        body = resp.content
        if b"-----BEGIN CERTIFICATE-----" in body:
            issuer_pem = body.decode("utf-8").strip()
        else:
            try:
                issuer_cert = x509.load_der_x509_certificate(body)
                issuer_pem = issuer_cert.public_bytes(
                    serialization.Encoding.PEM
                ).decode("utf-8").strip()
            except Exception as exc:
                logger.warning(
                    "AIA chain resolution: could not parse certificate "
                    "fetched for '%s' from %s: %s. The root CA may need "
                    "to be imported into ISE manually.",
                    current_cn, issuer_url, exc,
                )
                break

        # Identify the resolved issuer for logging.
        try:
            iss_obj = x509.load_pem_x509_certificate(
                (issuer_pem + "\n").encode("utf-8")
            )
            iss_cn_attrs = iss_obj.subject.get_attributes_for_oid(
                x509.oid.NameOID.COMMON_NAME
            )
            issuer_cn = iss_cn_attrs[0].value if iss_cn_attrs else "(no CN)"
        except Exception:
            issuer_cn = "(unknown)"
            iss_obj = None

        # Verify the AIA-discovered certificate is the actual issuer by
        # comparing Authority Key Identifier (child) → Subject Key
        # Identifier (parent).  Let's Encrypt staging AIA URLs can
        # serve a certificate from a different chain path (e.g. a
        # cross-signed or re-keyed root) that does not match the
        # intermediates in the downloaded chain.
        if iss_obj is not None:
            current_aki = _get_aki(cert_obj)
            issuer_ski = _get_ski(iss_obj)
            if current_aki and issuer_ski and current_aki != issuer_ski:
                logger.warning(
                    "AIA chain resolution: certificate fetched from %s "
                    "(Subject: '%s', SKI: %s) does not match the "
                    "Authority Key Identifier (%s) of '%s'. The AIA URL "
                    "may be serving a stale or incorrect certificate. "
                    "Stopping chain resolution; the correct issuer CA "
                    "may need to be imported into ISE manually.",
                    issuer_url, issuer_cn,
                    issuer_ski.hex(),
                    current_aki.hex(),
                    current_cn,
                )
                break

        logger.info(
            "AIA chain resolution: discovered issuer '%s' for '%s'",
            issuer_cn, current_cn,
        )

        chain.append(issuer_pem)
        current_pem = issuer_pem

    if chain:
        logger.info(
            "AIA chain resolution: resolved %d additional certificate(s)",
            len(chain),
        )
    else:
        logger.info(
            "AIA chain resolution: no additional certificates discovered"
        )
    return chain


class ISEClient:
    """Handles all Cisco ISE API interactions."""

    def __init__(self, config: dict):
        self.host = config.get("ise_host", "")
        self.username = config.get("ise_username", "")
        self.password = config.get("ise_password", "")
        self.open_api_port = config.get("ise_open_api_port", 443)
        self.ers_port = config.get("ise_ers_port", 9060)

        self.base_url = f"https://{self.host}:{self.open_api_port}/api/v1"
        self.ers_base_url = f"https://{self.host}:{self.ers_port}/ers/config"

        self.session = requests.Session()
        self.session.auth = (self.username, self.password)
        self.session.verify = False
        self.session.headers.update({
            "Content-Type": "application/json",
            "Accept": "application/json"
        })

        self.ers_session = requests.Session()
        self.ers_session.auth = (self.username, self.password)
        self.ers_session.verify = False
        self.ers_session.headers.update({
            "Content-Type": "application/json",
            "Accept": "application/json"
        })

    def _fetch_csrf_token(self) -> "str | None":
        """Fetch a CSRF token from ISE for POST/PUT/DELETE requests.

        When CSRF protection is enabled on the ISE Open API, every
        mutating request must include a valid ``X-CSRF-Token`` header.
        A token is obtained by sending any GET request with the header
        ``X-CSRF-Token: fetch``; ISE returns the real token in the same
        response header.

        Returns the token string, or *None* if the server did not
        supply one (CSRF protection is disabled).
        """
        try:
            resp = self.session.get(
                f"{self.base_url}/certs/trusted-certificate",
                headers={"X-CSRF-Token": "fetch"},
                timeout=10,
            )
            return resp.headers.get("X-CSRF-Token")
        except Exception:
            return None

    def test_connection(self) -> dict:
        """Test connectivity to ISE."""
        try:
            url = f"{self.base_url}/certs/system-certificate/{self.host}"
            response = self.session.get(url, timeout=10)
            response.raise_for_status()
            return {"success": True, "message": "Connection successful"}
        except requests.exceptions.ConnectionError:
            return {"success": False, "message": f"Cannot connect to {self.host}"}
        except requests.exceptions.HTTPError as e:
            return {"success": False, "message": f"HTTP error: {e.response.status_code}"}
        except Exception as e:
            return {"success": False, "message": str(e)}

    def get_system_certificates(self, node_name: str) -> list:
        """Retrieve all system certificates from a specific ISE node."""
        url = f"{self.base_url}/certs/system-certificate/{node_name}"
        try:
            response = self.session.get(url, timeout=30)
            response.raise_for_status()
            return response.json().get("response", [])
        except Exception as e:
            logger.error(f"[{node_name}] Failed to retrieve certificates: {e}")
            raise

    def get_certificate_by_cn(self, common_name: str, node_name: str) -> dict:
        """Find a specific certificate by Common Name."""
        certs = self.get_system_certificates(node_name)
        for cert in certs:
            if common_name in cert.get("friendlyName", "") or \
               common_name in cert.get("subject", ""):
                return cert
        return None

    def check_certificate_expiry(self, common_name: str, threshold_days: int, node_name: str) -> dict:
        """Check certificate expiry on a specific node."""
        cert = self.get_certificate_by_cn(common_name, node_name)
        if not cert:
            return {
                "needs_renewal": True,
                "reason": "Certificate not found",
                "node": node_name
            }

        expiry_str = cert.get("expirationDate", "")
        try:
            expiry_date = datetime.strptime(expiry_str, "%Y-%m-%dT%H:%M:%S.%fZ")
        except ValueError:
            try:
                expiry_date = datetime.strptime(expiry_str, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                return {
                    "needs_renewal": True,
                    "reason": "Cannot parse expiry date",
                    "node": node_name
                }

        days_remaining = (expiry_date - datetime.utcnow()).days
        return {
            "needs_renewal": days_remaining <= threshold_days,
            "days_remaining": days_remaining,
            "expiry_date": expiry_str,
            "certificate_id": cert.get("id"),
            "friendly_name": cert.get("friendlyName"),
            "node": node_name
        }

    def initiate_acme_certificate_request(self, common_name, san_names, key_type,
                                           node_name, portal_group_tag) -> dict:
        """Initiate ACME certificate request."""
        url = f"{self.base_url}/certs/system-certificate/acme"
        payload = {
            "nodeName": node_name,
            "commonName": common_name,
            "subjectAlternativeNames": ",".join(san_names) if isinstance(san_names, list) else san_names,
            "keyType": key_type,
            "usedBy": "Portal",
            "portalGroupTag": portal_group_tag,
            "autoRenew": True,
            "allowWildcardCerts": "*" in common_name,
        }
        csrf_token = self._fetch_csrf_token()
        csrf_headers = {"X-CSRF-Token": csrf_token} if csrf_token else {}
        response = self.session.post(url, json=payload, headers=csrf_headers, timeout=30)
        response.raise_for_status()
        return response.json()

    def get_acme_challenge(self, request_id: str) -> dict:
        """Retrieve ACME DNS-01 challenge details."""
        url = f"{self.base_url}/certs/acme-challenge/{request_id}"
        response = self.session.get(url, timeout=30)
        response.raise_for_status()
        return response.json()

    def confirm_acme_challenge(self, request_id: str) -> dict:
        """Confirm DNS challenge has been fulfilled."""
        url = f"{self.base_url}/certs/acme-challenge/{request_id}/validate"
        csrf_token = self._fetch_csrf_token()
        csrf_headers = {"X-CSRF-Token": csrf_token} if csrf_token else {}
        response = self.session.post(url, headers=csrf_headers, timeout=30)
        response.raise_for_status()
        return response.json()

    def export_certificate(self, cert_id: str, node_name: str) -> dict:
        """Export certificate from a node."""
        url = f"{self.base_url}/certs/system-certificate/{node_name}/{cert_id}/export"
        response = self.session.get(url, timeout=30)
        response.raise_for_status()
        return response.json()

    def export_certificate_for_inspection(self, cert_id: str, node_name: str) -> "tuple":
        """
        Download a system certificate from ISE so it can be inspected.

        Only the certificate is exported (never the private key). Returns the
        raw response body plus the response object so the caller can decode
        whatever form ISE returned (PEM or a binary ZIP).

        The modern ISE (3.1+) Open API exposes a single endpoint for this:
        ``POST /api/v1/certs/system-certificate/export``. The response body is
        a binary ZIP archive containing the certificate.
        """
        post_url = f"{self.base_url}/certs/system-certificate/export"
        # Per the ISE Open API schema (see ciscoisesdk ExportSystemCertificate
        # request schema), ``id``, ``export`` and ``hostName`` are required.
        # ``hostName`` identifies the node that owns the certificate — without
        # it newer ISE builds reject the call with HTTP 400
        # ("HostName should not be null"). ``password`` must only be sent when
        # exporting the private key, and when sent it has to be at least 8
        # alphanumeric characters — an empty string is rejected with HTTP 400
        # by newer ISE builds.
        post_payload = {
            "id": cert_id,
            "export": "CERTIFICATE",  # cert only — never the private key
            "hostName": node_name,
        }
        # The export endpoint returns a binary ZIP, not JSON. The session's
        # default ``Accept: application/json`` header would make some ISE
        # versions reject the request, so override it for this call.
        csrf_token = self._fetch_csrf_token()
        headers = {"Accept": "application/octet-stream, application/zip, */*"}
        if csrf_token:
            headers["X-CSRF-Token"] = csrf_token
        try:
            response = self.session.post(
                post_url,
                json=post_payload,
                headers=headers,
                timeout=60,
                stream=True,
            )
            response.raise_for_status()
            return response.content, response
        except requests.exceptions.HTTPError as e:
            # Pull the ISE error body into the exception so the UI can show
            # the real reason (e.g. "password must be at least 8 chars")
            # instead of a bare "400 Client Error".
            detail = ""
            if e.response is not None:
                try:
                    detail = e.response.text.strip()
                except Exception:
                    detail = ""
            status = e.response.status_code if e.response is not None else "?"
            raise RuntimeError(
                f"POST {post_url} returned HTTP {status}"
                + (f": {detail}" if detail else "")
            ) from e
        except requests.exceptions.RequestException as e:
            raise RuntimeError(f"POST {post_url} failed: {e}") from e

    def _ensure_intermediates_trusted(self, pem_chain: str) -> None:
        """Upload intermediate and root CA certificates to ISE's trusted store.

        ISE must already trust every certificate in the chain above the
        leaf in order for ``system-certificate/import`` to succeed.
        ACME providers (e.g. Let's Encrypt) include the intermediates in
        the downloaded chain but typically omit the root CA.  ISE
        requires the issuer of every imported certificate to already be
        present in its trusted store, so we resolve the full chain up to
        the root and import certificates from root down.

        The chain is built by walking from the leaf upward through the
        **downloaded** certificates, matching each certificate's
        Authority Key Identifier to the next certificate's Subject Key
        Identifier.  This ensures the *actual* trust path from the ACME
        response is used, rather than an alternate path that AIA
        extensions may resolve to (a known issue with Let's Encrypt
        staging certificates whose AIA URLs can serve certificates from
        a different chain).

        AIA is only used as a last resort to discover the root CA when
        it is not included in the downloaded chain, and AIA-discovered
        certificates are verified against AKI/SKI before being accepted.

        If ISE already has a certificate, the call returns HTTP 409
        (conflict) — we silently ignore that.
        """
        blocks = _split_pem_chain(pem_chain)
        if len(blocks) <= 1:
            # No intermediates to upload.
            return

        # Build the actual trust path from the downloaded certificates
        # by following AKI → SKI / Issuer → Subject from the leaf.
        intermediates = _build_chain_from_downloaded(blocks)

        if not intermediates:
            # Fallback: use the positional order from the ACME response.
            intermediates = blocks[1:]

        # If the topmost certificate in the chain is not self-signed
        # (i.e. the root CA was not included in the download), try to
        # discover the root via AIA.  The AIA resolver now verifies
        # AKI/SKI to avoid importing a certificate from a different
        # chain path.
        try:
            top_cert = x509.load_pem_x509_certificate(
                (intermediates[-1].strip() + "\n").encode("utf-8")
            )
            if top_cert.issuer != top_cert.subject:
                extra = _resolve_issuer_chain(intermediates[-1])
                if extra:
                    intermediates.extend(extra)
        except Exception:
            pass

        # Import from root down so that each certificate's issuer is
        # already trusted by ISE when we upload the next one.
        intermediates = list(reversed(intermediates))

        # Log the full chain that will be imported (root-first order).
        total = len(intermediates)
        logger.info(
            "Will import %d CA certificate(s) into ISE trusted store "
            "(root-first order):", total,
        )
        for i, blk in enumerate(intermediates):
            try:
                c = x509.load_pem_x509_certificate(
                    (blk + "\n").encode("utf-8")
                )
                subj_attrs = c.subject.get_attributes_for_oid(
                    x509.oid.NameOID.COMMON_NAME
                )
                subj = subj_attrs[0].value if subj_attrs else "(no CN)"
                iss_attrs = c.issuer.get_attributes_for_oid(
                    x509.oid.NameOID.COMMON_NAME
                )
                iss = iss_attrs[0].value if iss_attrs else "(no CN)"
                logger.info(
                    "  [%d/%d] Subject: %s | Issuer: %s", i + 1, total, subj, iss,
                )
            except Exception:
                logger.info("  [%d/%d] (could not parse certificate)", i + 1, total)

        url = f"{self.base_url}/certs/trusted-certificate/import"

        for idx, pem_block in enumerate(intermediates):
            # Fetch a fresh CSRF token for each import: ISE invalidates the
            # token after every successful mutating request, so reusing one
            # token across multiple POSTs causes a 403 on the second import.
            csrf_token = self._fetch_csrf_token()
            csrf_headers = {"X-CSRF-Token": csrf_token} if csrf_token else {}

            # Derive a human-readable name from the certificate subject.
            try:
                cert_obj = x509.load_pem_x509_certificate(
                    (pem_block + "\n").encode("utf-8")
                )
                cn_attrs = cert_obj.subject.get_attributes_for_oid(
                    x509.oid.NameOID.COMMON_NAME
                )
                friendly = cn_attrs[0].value if cn_attrs else f"ACME-intermediate-{idx}"
            except Exception:
                friendly = f"ACME-intermediate-{idx}"

            # Sanitize the friendly name: ISE's trusted-certificate import
            # API rejects names containing parentheses and other special
            # characters with a generic "Security Check Failed" (HTTP 400).
            # Let's Encrypt staging CAs use names like
            # "(STAGING) Riddling Rhubarb R12" — the parentheses must be
            # stripped before sending the name to ISE.
            friendly = re.sub(r"[^A-Za-z0-9 _.\-]", "", friendly).strip()
            friendly = re.sub(r" {2,}", " ", friendly)
            if not friendly:
                friendly = f"ACME-intermediate-{idx}"

            payload = {
                "data": pem_block + "\n",
                "name": friendly,
                "description": "Imported automatically by ACME Manager",
                "allowBasicConstraintCAFalse": True,
                "allowOutOfDateCert": False,
                "allowSHA1Certificates": False,
                "trustForCertificateBasedAdminAuth": True,
                "trustForCiscoServicesAuth": True,
                "trustForClientAuth": True,
                "trustForIseAuth": True,
                "validateCertificateExtensions": False,
            }
            logger.info(
                "Importing CA certificate [%d/%d] '%s' into ISE trusted store...",
                idx + 1, total, friendly,
            )
            try:
                resp = self.session.post(url, json=payload, headers=csrf_headers, timeout=30)
                resp.raise_for_status()
                logger.info(
                    "Successfully imported CA [%d/%d] '%s'",
                    idx + 1, total, friendly,
                )
            except requests.exceptions.HTTPError as exc:
                status = exc.response.status_code if exc.response is not None else "?"
                if status == 409:
                    # Certificate already exists in ISE's trusted store.
                    logger.info(
                        "CA [%d/%d] '%s' already exists in ISE trusted store",
                        idx + 1, total, friendly,
                    )
                else:
                    detail = ""
                    if exc.response is not None:
                        try:
                            detail = exc.response.text.strip()
                        except Exception:
                            detail = ""
                    # Extract issuer CN for a more actionable error.
                    try:
                        iss_attrs = cert_obj.issuer.get_attributes_for_oid(
                            x509.oid.NameOID.COMMON_NAME
                        )
                        issuer_cn = iss_attrs[0].value if iss_attrs else str(cert_obj.issuer)
                    except Exception:
                        issuer_cn = "(unknown)"
                    logger.error(
                        "Failed to import CA [%d/%d] '%s' (HTTP %s): %s. "
                        "Issuer (parent CA): '%s'",
                        idx + 1, total, friendly, status,
                        detail or "(empty)", issuer_cn,
                    )
                    hint = (
                        f". Verify that the issuer CA '{issuer_cn}' is "
                        "already present in ISE's trusted certificate store. "
                        "If it is missing, import it manually before retrying."
                    )
                    raise RuntimeError(
                        f"Failed to import CA '{friendly}' "
                        f"into ISE trusted store (HTTP {status})"
                        + (f": {detail}" if detail else "")
                        + hint
                    ) from exc

    def import_certificate(self, cert_data: dict, node_name: str, portal_group_tag: str) -> dict:
        """
        Import a certificate to an ISE node.

        The modern ISE (3.1+) Open API exposes a single endpoint for this:
        ``POST /api/v1/certs/system-certificate/import``. The node is
        identified by the ``name`` field in the JSON body — it is **not**
        part of the URL path. Older ``/certs/system-certificate/{node}/import``
        paths do not accept POST and will return HTTP 405.
        """
        url = f"{self.base_url}/certs/system-certificate/import"

        # ISE's import endpoint rejects unencrypted private keys with a
        # generic "Security Check Failed" error. LetsEncrypt (and any
        # freshly generated key from our ACME client) returns the key in
        # plain PKCS#8 / unencrypted form, so we wrap it in an encrypted
        # blob here and send the generated passphrase in the ``password``
        # field. We detect whether encryption is needed by attempting to
        # load the key without a password — unencrypted keys load cleanly,
        # while encrypted ones raise TypeError regardless of format (PKCS#8
        # EncryptedPrivateKeyInfo or traditional OpenSSL Proc-Type header).
        private_key_pem = cert_data.get("privateKeyData")
        password = cert_data.get("password") or ""
        if private_key_pem:
            try:
                serialization.load_pem_private_key(
                    private_key_pem.encode("utf-8") if isinstance(private_key_pem, str)
                    else private_key_pem,
                    password=None,
                )
                # Loaded without a password → key is unencrypted → encrypt it.
                private_key_pem, password = _encrypt_private_key(private_key_pem)
            except TypeError:
                # Key is already encrypted; use caller-supplied password as-is.
                pass

        # ACME providers (e.g. Let's Encrypt) return a full certificate
        # chain (leaf + intermediates concatenated).  ISE's system-cert
        # import endpoint needs *only the leaf* in the ``data`` field —
        # sending the full chain causes "Security Check Failed" because
        # ISE tries to match the private key against the wrong cert.
        # However ISE must also be able to verify the full chain, which
        # requires the intermediates to be present in its trusted store.
        # We therefore upload intermediates first, then import the leaf.
        raw_cert = cert_data.get("certData") or cert_data.get("data") or ""
        if raw_cert:
            self._ensure_intermediates_trusted(raw_cert)
            blocks = _split_pem_chain(raw_cert)
            if blocks:
                raw_cert = blocks[0] + "\n"  # leaf only

        # Note: every ``allow*`` boolean must be supplied explicitly.
        # Newer ISE builds reject the request with HTTP 400
        # ("allowSHA1Certificates, must not be null" etc.) when any of
        # these fields are omitted.
        payload = {
            "name": node_name,
            "data": raw_cert or None,
            "privateKeyData": private_key_pem,
            "password": password,
            "portal": True,
            "portalGroupTag": portal_group_tag,
            "admin": False,
            "eap": False,
            "ims": False,
            "pxgrid": False,
            "radius": False,
            "saml": False,
            "allowExtendedValidity": True,
            "allowOutOfDateCert": False,
            "allowSHA1Certificates": False,
            "allowWildCardCertificates": True,
            "allowReplacementOfCertificates": True,
            "allowReplacementOfPortalGroupTag": True,
            "allowPortalTagTransferForSameSubject": True,
            "allowRoleTransferForSameSubject": True,
            "validateCertificateExtensions": False,
        }
        csrf_token = self._fetch_csrf_token()
        csrf_headers = {"X-CSRF-Token": csrf_token} if csrf_token else {}
        try:
            response = self.session.post(url, json=payload, headers=csrf_headers, timeout=30)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as e:
            # Surface ISE's error body so the UI shows the real reason
            # (e.g. "Certificate already exists") instead of a bare
            # "405 Client Error".
            detail = ""
            if e.response is not None:
                try:
                    detail = e.response.text.strip()
                except Exception:
                    detail = ""
            status = e.response.status_code if e.response is not None else "?"
            raise RuntimeError(
                f"POST {url} returned HTTP {status}"
                + (f": {detail}" if detail else "")
            ) from e

    def bind_certificate_to_portal(self, cert_id: str, portal_group_tag: str, node_name: str) -> dict:
        """Bind certificate to guest portal."""
        url = f"{self.base_url}/certs/system-certificate/{node_name}/{cert_id}"
        payload = {"usedBy": "Portal", "portalGroupTag": portal_group_tag}
        csrf_token = self._fetch_csrf_token()
        csrf_headers = {"X-CSRF-Token": csrf_token} if csrf_token else {}
        response = self.session.put(url, json=payload, headers=csrf_headers, timeout=30)
        response.raise_for_status()
        return response.json()

    def get_portal_group_tags(self, node_name: str = None) -> list:
        """
        Auto-discover portal group tags available in the ISE deployment.

        Strategy:
          1. Try the ERS portal endpoint (enumerates all portals and their
             certificateGroupTag).
          2. Fallback: scan system certificates on the given node and collect
             any ``portalGroupTag`` values present.
        Results always include the built-in default group tag.
        """
        tags = set()

        # Primary source: ERS portal API
        try:
            url = f"{self.ers_base_url}/portal"
            response = self.ers_session.get(url, timeout=30)
            response.raise_for_status()
            data = response.json()
            resources = data.get("SearchResult", {}).get("resources", [])
            for resource in resources:
                portal_id = resource.get("id", "")
                if not portal_id:
                    continue
                try:
                    detail_url = f"{self.ers_base_url}/portal/{portal_id}"
                    detail_resp = self.ers_session.get(detail_url, timeout=30)
                    detail_resp.raise_for_status()
                    portal = detail_resp.json().get("Portal", {})
                    settings = portal.get("settings", {}) or {}
                    portal_settings = settings.get("portalSettings", {}) or {}
                    tag = (
                        portal_settings.get("certificateGroupTag")
                        or portal.get("certificateGroupTag")
                    )
                    if tag:
                        tags.add(tag)
                except Exception as e:
                    logger.debug(f"Failed to fetch portal {portal_id}: {e}")
        except Exception as e:
            logger.debug(f"ERS portal discovery failed, will fall back to system certs: {e}")

        # Secondary source: scan system certs for portalGroupTag values
        if node_name:
            try:
                certs = self.get_system_certificates(node_name)
                for cert in certs:
                    tag = cert.get("portalGroupTag") or cert.get("portalTagTransferForSameSubject")
                    if tag:
                        tags.add(tag)
            except Exception as e:
                logger.debug(f"Fallback portal tag discovery from certs failed: {e}")

        tags.add("Default Portal Certificate Group")
        return sorted(tags)

    # ──────────────────────────────
    # ERS API — Node Discovery
    # ──────────────────────────────

    def test_ers_connection(self) -> dict:
        """Test connectivity to ISE ERS API."""
        try:
            url = f"{self.ers_base_url}/node"
            response = self.ers_session.get(url, timeout=10)
            response.raise_for_status()
            return {"success": True, "message": "ERS connection successful"}
        except requests.exceptions.ConnectionError:
            return {"success": False, "message": f"Cannot connect to ERS on {self.host}:{self.ers_port}"}
        except requests.exceptions.HTTPError as e:
            return {"success": False, "message": f"HTTP error: {e.response.status_code}"}
        except Exception as e:
            return {"success": False, "message": str(e)}

    def get_node_detail(self, node_id: str) -> dict:
        """Get full node details from ERS API."""
        url = f"{self.ers_base_url}/node/{node_id}"
        response = self.ers_session.get(url, timeout=30)
        response.raise_for_status()
        return response.json().get("Node", {})

    def _derive_roles(self, node_detail: dict) -> list:
        """Derive node roles from ERS node detail response."""
        roles = []
        if node_detail.get("papNode", False):
            roles.append("PAN")
        services = node_detail.get("nodeServiceTypes", "")

        def _normalize(value: str) -> str:
            return "".join(ch for ch in value.lower() if ch.isalnum())

        if isinstance(services, str):
            service_keys = [_normalize(s) for s in services.split(",") if s.strip()]
        elif isinstance(services, list):
            service_keys = [_normalize(s) for s in services if isinstance(s, str)]
        elif isinstance(services, dict):
            service_keys = [_normalize(k) for k in services.keys()]
        else:
            service_keys = []
        if service_keys:
            psn_indicators = ["session", "profiler", "deviceadmin", "sxp", "tcnac", "passiveidentity"]
            if any(ind in sk for sk in service_keys for ind in psn_indicators):
                roles.append("PSN")
            mon_indicators = ["monitoring"]
            if any(ind in sk for sk in service_keys for ind in mon_indicators):
                roles.append("MnT")
        if node_detail.get("pxGridNode", False):
            roles.append("pxGrid")
        if not roles:
            roles.append("PSN")
        return roles

    def discover_nodes(self) -> list:
        """Discover all nodes in the ISE deployment via ERS API."""
        url = f"{self.ers_base_url}/node"
        response = self.ers_session.get(url, timeout=30)
        response.raise_for_status()
        data = response.json()

        resources = data.get("SearchResult", {}).get("resources", [])
        nodes = []
        for resource in resources:
            node_id = resource.get("id", "")
            try:
                detail = self.get_node_detail(node_id)
                roles = self._derive_roles(detail)
                nodes.append({
                    "ers_id": node_id,
                    "name": detail.get("name", resource.get("name", "")),
                    "fqdn": detail.get("fqdn", detail.get("name", resource.get("name", ""))),
                    "roles": roles,
                    "is_primary_pan": detail.get("primaryPapNode", False),
                })
            except Exception as e:
                logger.warning(f"Failed to get details for node {resource.get('name')}: {e}")
                nodes.append({
                    "ers_id": node_id,
                    "name": resource.get("name", ""),
                    "fqdn": resource.get("name", ""),
                    "roles": ["unknown"],
                    "is_primary_pan": False,
                })

        return nodes
