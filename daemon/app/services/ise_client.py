"""
Cisco ISE API Client — handles all ISE interactions.
"""

import logging
import requests
import urllib3
from datetime import datetime

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = logging.getLogger(__name__)


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
        response = self.session.post(url, json=payload, timeout=30)
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
        response = self.session.post(url, timeout=30)
        response.raise_for_status()
        return response.json()

    def export_certificate(self, cert_id: str, node_name: str) -> dict:
        """Export certificate from a node."""
        url = f"{self.base_url}/certs/system-certificate/{node_name}/{cert_id}/export"
        response = self.session.get(url, timeout=30)
        response.raise_for_status()
        return response.json()

    def import_certificate(self, cert_data: dict, node_name: str, portal_group_tag: str) -> dict:
        """Import certificate to a node."""
        url = f"{self.base_url}/certs/system-certificate/{node_name}/import"
        payload = {
            "certData": cert_data.get("certData"),
            "privateKeyData": cert_data.get("privateKeyData"),
            "usedBy": "Portal",
            "portalGroupTag": portal_group_tag,
            "allowExtendedValidity": True
        }
        response = self.session.post(url, json=payload, timeout=30)
        response.raise_for_status()
        return response.json()

    def bind_certificate_to_portal(self, cert_id: str, portal_group_tag: str, node_name: str) -> dict:
        """Bind certificate to guest portal."""
        url = f"{self.base_url}/certs/system-certificate/{node_name}/{cert_id}"
        payload = {"usedBy": "Portal", "portalGroupTag": portal_group_tag}
        response = self.session.put(url, json=payload, timeout=30)
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
