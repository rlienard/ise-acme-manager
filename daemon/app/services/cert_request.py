"""
Live certificate request orchestrator.

Drives the end-to-end ACME request + ISE push flow for a single certificate
and streams progress events back to the caller as it goes. Used by the
Settings → Certificates → Request New Certificate subsection so the operator
can watch each phase (CSR build, challenge, DNS record, validation, import,
bind) unfold in real time.

The runner is deliberately independent from ``ACMERenewalEngine``: the
renewal engine iterates over stored ManagedCertificate rows on a threshold,
whereas this runner always issues a brand-new cert against whatever payload
the UI supplies, without writing anything to the managed-certificate table.
"""

import logging
import time
from datetime import datetime
from typing import Callable, List, Optional

from ..config import ConfigManager
from ..database import ACMEProvider, ISENode
from .acme_client import ACMEv2Client
from .dns_providers import build_dns_client, get_dns_provider
from .ise_client import ISEClient

logger = logging.getLogger(__name__)


Emit = Callable[[str, str, dict], None]


class CertificateRequestError(Exception):
    """Raised when the live request flow cannot proceed."""


class CertificateRequestRunner:
    """
    Execute the full "request a new certificate and push to ISE" flow.

    The runner is driven by an ``emit`` callback which receives structured
    progress events. Each event has a ``phase`` (machine-readable stage
    identifier), a ``level`` (info / success / warning / error), a human
    readable ``message`` and an optional ``data`` dict for extra context.

    The flow is almost identical to ``ACMERenewalEngine._renew_shared`` /
    ``_renew_shared_letsencrypt`` but with explicit logging at every step
    and without any threshold/skip logic — we always request a fresh cert.
    """

    def __init__(self, db, payload, emit: Emit):
        self.db = db
        self.payload = payload
        self._emit = emit

    # ── Event helpers ───────────────────────────────────────

    def log(self, level: str, message: str, phase: str = "info", data: Optional[dict] = None):
        """Emit a structured progress event."""
        self._emit(phase, level, {"message": message, "data": data or {}})

    def info(self, message: str, phase: str = "info", data: Optional[dict] = None):
        self.log("info", message, phase, data)

    def success(self, message: str, phase: str = "info", data: Optional[dict] = None):
        self.log("success", message, phase, data)

    def warning(self, message: str, phase: str = "warning", data: Optional[dict] = None):
        self.log("warning", message, phase, data)

    def error(self, message: str, phase: str = "error", data: Optional[dict] = None):
        self.log("error", message, phase, data)

    # ── Resolution helpers ──────────────────────────────────

    def _resolve_provider(self) -> ACMEProvider:
        provider = (
            self.db.query(ACMEProvider)
            .filter(ACMEProvider.id == self.payload.acme_provider_id)
            .first()
        )
        if provider is None:
            raise CertificateRequestError(
                f"ACME provider id {self.payload.acme_provider_id} not found"
            )
        return provider

    def _resolve_nodes(self) -> List[ISENode]:
        nodes = (
            self.db.query(ISENode)
            .filter(ISENode.id.in_(self.payload.node_ids))
            .all()
        )
        if not nodes:
            raise CertificateRequestError("No target ISE nodes selected")
        missing = set(self.payload.node_ids) - {n.id for n in nodes}
        if missing:
            raise CertificateRequestError(
                f"ISE node id(s) not found: {', '.join(str(m) for m in missing)}"
            )
        return nodes

    def _pick_primary(self, nodes: List[ISENode]) -> ISENode:
        for node in nodes:
            if node.is_primary:
                return node
        return nodes[0]

    # ── Main entry point ────────────────────────────────────

    def run(self):
        payload = self.payload
        cn = payload.common_name
        sans = payload.san_names or []
        mode = payload.certificate_mode.value if hasattr(payload.certificate_mode, "value") else str(payload.certificate_mode)

        self.info(
            f"Starting certificate request for {cn}",
            phase="start",
            data={
                "common_name": cn,
                "san_names": sans,
                "key_type": payload.key_type,
                "usage": payload.usage,
                "certificate_mode": mode,
                "portal_group_tag": payload.portal_group_tag,
            },
        )

        provider = self._resolve_provider()
        self.info(
            f"Using ACME provider '{provider.name}' ({provider.provider_type})",
            phase="provider",
            data={"provider_id": provider.id, "provider_type": provider.provider_type},
        )

        nodes = self._resolve_nodes()
        primary = self._pick_primary(nodes)
        secondaries = [n for n in nodes if n.id != primary.id]
        self.info(
            f"Target nodes: primary={primary.name}"
            + (f", secondaries={[n.name for n in secondaries]}" if secondaries else ""),
            phase="nodes",
        )

        # Build ISE client from persisted settings
        config = ConfigManager.get_flat(self.db)
        ise = ISEClient(config)

        # Build DNS client linked to the ACME provider, with legacy fallback
        dns = None
        if provider.dns_provider is not None:
            try:
                dns = build_dns_client(provider.dns_provider)
                self.info(
                    f"Using DNS provider '{provider.dns_provider.name}' "
                    f"({provider.dns_provider.provider_type})",
                    phase="dns_provider",
                )
            except Exception as e:
                self.warning(
                    f"Failed to build DNS client from provider "
                    f"'{provider.dns_provider.name}': {e}. Falling back to legacy config."
                )
        if dns is None:
            try:
                dns = get_dns_provider(config)
                self.info("Using legacy DNS provider from global settings", phase="dns_provider")
            except Exception as e:
                raise CertificateRequestError(
                    f"No DNS provider available for DNS-01 challenge: {e}"
                )

        # Dispatch to the right engine. LetsEncrypt is driven externally with
        # our own ACMEv2Client; DigiCert is driven by ISE's built-in ACME
        # client via the existing /certs/system-certificate/acme endpoint.
        if provider.provider_type == "letsencrypt":
            cert_info = self._run_letsencrypt(ise, dns, provider, primary)
        else:
            cert_info = self._run_digicert(ise, dns, provider, primary)

        # Distribute to secondaries (shared mode) or reissue (per-node mode)
        if mode == "per-node" and secondaries:
            self.info(
                "Per-node mode selected — requesting an independent certificate "
                "for each remaining node",
                phase="per_node",
            )
            for node in secondaries:
                try:
                    if provider.provider_type == "letsencrypt":
                        self._run_letsencrypt(ise, dns, provider, node)
                    else:
                        self._run_digicert(ise, dns, provider, node)
                except Exception as e:
                    self.error(f"Per-node request for {node.name} failed: {e}", phase="per_node")
        else:
            for node in secondaries:
                try:
                    self.info(
                        f"Distributing certificate to secondary node {node.name}",
                        phase="distribute",
                    )
                    # For LetsEncrypt, we have the original cert + private key
                    # from the ACME response. Re-use them directly on the
                    # secondary node — ISE's export API never returns the
                    # private key, so exporting from primary and re-importing
                    # would always fail with "Security Check Failed".
                    if provider.provider_type == "letsencrypt" and cert_info.get("cert_pem"):
                        ise.import_certificate(
                            {
                                "certData": cert_info["cert_pem"],
                                "privateKeyData": cert_info["key_pem"],
                            },
                            node.name,
                            payload.portal_group_tag,
                        )
                    else:
                        primary_cert = ise.get_certificate_by_cn(cn, primary.name)
                        if not primary_cert:
                            raise CertificateRequestError(
                                f"Primary certificate '{cn}' not found on {primary.name}"
                            )
                        cert_data = ise.export_certificate(primary_cert["id"], primary.name)
                        ise.import_certificate(cert_data, node.name, payload.portal_group_tag)
                    imported = ise.get_certificate_by_cn(cn, node.name)
                    if imported:
                        ise.bind_certificate_to_portal(
                            imported["id"], payload.portal_group_tag, node.name
                        )
                    self.success(
                        f"Certificate distributed to {node.name}",
                        phase="distribute",
                        data={"node": node.name},
                    )
                except Exception as e:
                    self.error(
                        f"Failed to distribute certificate to {node.name}: {e}",
                        phase="distribute",
                    )

        self.success(
            f"Certificate request for {cn} completed",
            phase="done",
            data={"common_name": cn, "certificate_id": cert_info.get("certificate_id")},
        )

    # ── DigiCert / ISE-managed ACME flow ────────────────────

    def _run_digicert(self, ise: ISEClient, dns, provider: ACMEProvider, node: ISENode) -> dict:
        payload = self.payload
        cn = payload.common_name

        self.info(
            f"Creating certificate request on ISE node {node.name}",
            phase="csr",
        )
        try:
            req = ise.initiate_acme_certificate_request(
                cn,
                payload.san_names,
                payload.key_type,
                node.name,
                payload.portal_group_tag,
            )
        except Exception as e:
            raise CertificateRequestError(
                f"ISE rejected the ACME request initialization: {e}"
            )
        request_id = req.get("id") or req.get("requestId")
        if not request_id:
            raise CertificateRequestError(
                f"ISE did not return a request id (response: {req})"
            )
        self.success(
            f"ISE accepted the ACME certificate request (id={request_id})",
            phase="csr",
        )

        self.info("Waiting for ISE to fetch the DNS-01 challenge…", phase="challenge")
        time.sleep(10)
        challenge = ise.get_acme_challenge(request_id)
        record_name = challenge.get("recordName")
        record_value = challenge.get("recordValue")
        self.success(
            f"Challenge received: {record_name}",
            phase="challenge",
            data={"record_name": record_name, "record_value": record_value},
        )

        dns_record_id = None
        try:
            self.info(
                f"Creating DNS TXT record {record_name} on the DNS provider",
                phase="dns_create",
            )
            dns_record_id = dns.create_txt_record(record_name, record_value)
            self.success(
                f"DNS TXT record created (id={dns_record_id})",
                phase="dns_create",
                data={"record_id": str(dns_record_id) if dns_record_id else None},
            )

            self.info("Waiting 90s for DNS propagation…", phase="dns_wait")
            time.sleep(90)

            self.info("Asking ISE to validate the DNS-01 challenge", phase="validate")
            ise.confirm_acme_challenge(request_id)
            self.success("Challenge validation submitted", phase="validate")

            self.info(
                f"Polling ISE for the issued certificate on {node.name}",
                phase="issue",
            )
            cert = self._wait_for_cert(ise, cn, node.name)
            if not cert:
                raise CertificateRequestError(
                    "Timed out waiting for the new certificate to appear on ISE"
                )
            self.success(
                f"Certificate issued and imported on {node.name} (id={cert.get('id')})",
                phase="issue",
                data={"certificate_id": cert.get("id")},
            )

            self.info(
                f"Binding certificate to portal group '{payload.portal_group_tag}'",
                phase="bind",
            )
            ise.bind_certificate_to_portal(cert["id"], payload.portal_group_tag, node.name)
            self.success("Certificate bound to portal", phase="bind")

            return {"certificate_id": cert.get("id")}
        finally:
            if dns_record_id:
                try:
                    self.info("Cleaning up DNS TXT record", phase="dns_cleanup")
                    dns.delete_txt_record(dns_record_id)
                    self.success("DNS TXT record cleaned up", phase="dns_cleanup")
                except Exception as e:
                    self.warning(f"Failed to delete DNS TXT record: {e}", phase="dns_cleanup")

    # ── LetsEncrypt (external ACMEv2Client) flow ────────────

    def _run_letsencrypt(self, ise: ISEClient, dns, provider: ACMEProvider, node: ISENode) -> dict:
        payload = self.payload
        cn = payload.common_name
        san_names = payload.san_names or []
        all_domains = [cn] + [s for s in san_names if s != cn]

        if "acme-staging" in (provider.directory_url or "").lower():
            self.warning(
                "This ACME provider is configured with a Let's Encrypt STAGING "
                "directory URL. Staging certificates use fake CA chains that "
                "cannot be imported into Cisco ISE. If this is a production "
                "deployment, update the provider's directory URL to "
                "https://acme-v02.api.letsencrypt.org/directory",
                phase="acme_directory",
            )

        self.info(
            f"Connecting to ACME directory {provider.directory_url}",
            phase="acme_directory",
        )
        client = ACMEv2Client(
            directory_url=provider.directory_url,
            account_email=provider.account_email or "",
            account_key_pem=provider.account_key or None,
        )

        self.info("Registering / reusing ACME account", phase="acme_account")
        try:
            client.register_account()
        except Exception as e:
            raise CertificateRequestError(f"ACME account registration failed: {e}")
        if not provider.account_key:
            provider.account_key = client.get_account_key_pem()
            self.db.commit()
            self.info(
                "Persisted freshly generated ACME account key on provider",
                phase="acme_account",
            )

        self.info(
            f"Creating ACME order for: {', '.join(all_domains)}",
            phase="acme_order",
        )
        try:
            order = client.create_order(all_domains)
        except Exception as e:
            raise CertificateRequestError(f"ACME order creation failed: {e}")
        self.success("ACME order created", phase="acme_order")

        dns_record_id = None
        try:
            for authz_url in order["authorizations"]:
                authz = client.get_authorization(authz_url)
                domain = authz["identifier"]["value"]

                self.info(
                    f"Processing DNS-01 challenge for {domain}",
                    phase="challenge",
                )
                challenge = client.get_dns01_challenge(authz)
                record_name = client.get_dns_record_name(domain)
                record_value = client.get_dns_txt_value(challenge["token"])
                self.success(
                    f"Challenge received: {record_name}",
                    phase="challenge",
                    data={"record_name": record_name, "record_value": record_value},
                )

                self.info(
                    f"Creating DNS TXT record {record_name} on the DNS provider",
                    phase="dns_create",
                )
                dns_record_id = dns.create_txt_record(record_name, record_value)
                self.success(
                    f"DNS TXT record created (id={dns_record_id})",
                    phase="dns_create",
                )

                self.info("Waiting 90s for DNS propagation…", phase="dns_wait")
                time.sleep(90)

                self.info("Notifying ACME server that DNS record is ready", phase="validate")
                client.respond_to_challenge(challenge["url"])

                self.info("Polling authorization until it becomes valid", phase="validate")
                client.poll_authorization(authz_url)
                self.success(f"Authorization valid for {domain}", phase="validate")

                if dns_record_id:
                    try:
                        self.info("Cleaning up DNS TXT record", phase="dns_cleanup")
                        dns.delete_txt_record(dns_record_id)
                        self.success("DNS TXT record cleaned up", phase="dns_cleanup")
                    except Exception as e:
                        self.warning(
                            f"Failed to delete DNS TXT record: {e}",
                            phase="dns_cleanup",
                        )
                    dns_record_id = None

            self.info("Finalizing order and downloading the signed certificate", phase="finalize")
            cert_pem, key_pem = client.finalize_order(
                order,
                cn,
                san_names,
                key_type=payload.key_type,
                subject=payload.subject or {},
            )
            self.success("Certificate signed by the ACME CA", phase="finalize")

            self.info(
                f"Importing certificate into ISE node {node.name}",
                phase="import",
            )
            ise.import_certificate(
                {"certData": cert_pem, "privateKeyData": key_pem},
                node.name,
                payload.portal_group_tag,
            )
            self.success(f"Certificate imported on {node.name}", phase="import")

            imported = ise.get_certificate_by_cn(cn, node.name)
            cert_id = imported.get("id") if imported else None
            if cert_id:
                self.info(
                    f"Binding certificate to portal group '{payload.portal_group_tag}'",
                    phase="bind",
                )
                ise.bind_certificate_to_portal(cert_id, payload.portal_group_tag, node.name)
                self.success("Certificate bound to portal", phase="bind")
            else:
                self.warning(
                    "Imported certificate not found after import — skipped portal bind",
                    phase="bind",
                )

            return {"certificate_id": cert_id, "cert_pem": cert_pem, "key_pem": key_pem}
        finally:
            if dns_record_id:
                try:
                    self.info("Cleaning up leftover DNS TXT record", phase="dns_cleanup")
                    dns.delete_txt_record(dns_record_id)
                    self.success("DNS TXT record cleaned up", phase="dns_cleanup")
                except Exception as e:
                    self.warning(
                        f"Failed to delete DNS TXT record: {e}",
                        phase="dns_cleanup",
                    )

    # ── Helpers ─────────────────────────────────────────────

    def _wait_for_cert(self, ise: ISEClient, cn: str, node_name: str, max_wait: int = 300, interval: int = 15):
        """Poll ISE until the new cert shows up (same logic as ACMERenewalEngine)."""
        elapsed = 0
        while elapsed < max_wait:
            cert = ise.get_certificate_by_cn(cn, node_name)
            if cert:
                return cert
            time.sleep(interval)
            elapsed += interval
            if elapsed % 60 == 0:
                self.info(
                    f"Still waiting for certificate on {node_name} ({elapsed}s elapsed)…",
                    phase="issue",
                )
        return None
