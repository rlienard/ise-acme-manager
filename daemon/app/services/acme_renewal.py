"""
ACME Certificate Renewal Orchestrator.
Handles the full renewal lifecycle for shared and per-node modes,
iterating over ManagedCertificate rows for multi-certificate support.
"""

import io
import time
import uuid
import logging
from datetime import datetime, timedelta

from ..database import (
    SessionLocal, RenewalHistory, DaemonStatus, ISENode,
    ManagedCertificate, RenewalStatus, DaemonState
)
from ..config import ConfigManager
from .ise_client import ISEClient
from .dns_providers import get_dns_provider
from .notifier import EmailNotifier

logger = logging.getLogger(__name__)


class ACMERenewalEngine:
    """Orchestrates certificate renewal across ISE nodes."""

    def run(self, trigger: str = "scheduled", mode_override: str = None, force: bool = False):
        """Main entry point — iterates over all enabled ManagedCertificate rows."""
        db = SessionLocal()
        run_id = str(uuid.uuid4())
        log_buffer = io.StringIO()
        handler = logging.StreamHandler(log_buffer)
        handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
        logger.addHandler(handler)

        try:
            # Update daemon state
            daemon_status = db.query(DaemonStatus).first()
            daemon_status.state = DaemonState.RUNNING
            daemon_status.current_action = f"Renewal run {run_id[:8]}"
            db.commit()

            # Load global config (for ISE/DNS/SMTP credentials)
            config = ConfigManager.get_flat(db)

            # Initialize shared services
            ise = ISEClient(config)
            dns = get_dns_provider(config)
            notifier = EmailNotifier(config)

            # Fetch enabled managed certificates
            managed_certs = (
                db.query(ManagedCertificate)
                .filter(ManagedCertificate.enabled == True)
                .all()
            )

            if not managed_certs:
                raise Exception("No enabled managed certificates configured")

            all_results = {}
            overall_statuses = []

            for managed_cert in managed_certs:
                cert_nodes = [n for n in managed_cert.nodes if n.enabled]
                if not cert_nodes:
                    logger.warning(f"Cert '{managed_cert.common_name}' has no enabled nodes — skipping")
                    continue

                # Build per-cert config overlay
                cert_config = dict(config)
                cert_config["common_name"] = managed_cert.common_name
                cert_config["san_names"] = managed_cert.san_names or []
                cert_config["key_type"] = managed_cert.key_type
                cert_config["portal_group_tag"] = managed_cert.portal_group_tag
                cert_config["certificate_mode"] = managed_cert.certificate_mode
                cert_config["renewal_threshold_days"] = managed_cert.renewal_threshold_days

                mode = mode_override or managed_cert.certificate_mode
                threshold = 9999 if force else managed_cert.renewal_threshold_days

                # Create history record for this cert
                history = RenewalHistory(
                    run_id=run_id,
                    status=RenewalStatus.IN_PROGRESS,
                    mode=mode,
                    trigger=trigger,
                    common_name=managed_cert.common_name,
                    started_at=datetime.utcnow(),
                    managed_certificate_id=managed_cert.id,
                )
                db.add(history)
                db.commit()

                try:
                    if mode == "shared":
                        results = self._renew_shared(ise, dns, cert_config, cert_nodes, threshold, db)
                    else:
                        results = self._renew_per_node(ise, dns, cert_config, cert_nodes, threshold, db)

                    statuses = [r.get("status") for r in results.values()]
                    if all(s in ("ok", "renewed") for s in statuses):
                        cert_status = RenewalStatus.SUCCESS
                    elif any(s == "renewed" for s in statuses):
                        cert_status = RenewalStatus.PARTIAL
                    elif all(s == "ok" for s in statuses):
                        cert_status = RenewalStatus.SKIPPED
                    else:
                        cert_status = RenewalStatus.FAILED

                except Exception as e:
                    logger.error(f"Cert '{managed_cert.common_name}' renewal failed: {e}")
                    results = {}
                    cert_status = RenewalStatus.FAILED
                    history.error_message = str(e)

                # Update history record
                history.status = cert_status
                history.completed_at = datetime.utcnow()
                history.duration_seconds = (history.completed_at - history.started_at).total_seconds()
                history.node_results = results
                history.log_output = log_buffer.getvalue()

                # Update managed cert last renewal info
                managed_cert.last_renewal_at = datetime.utcnow()
                managed_cert.last_renewal_status = cert_status.value

                # Update node statuses
                for node in cert_nodes:
                    node_result = results.get(node.name, {})
                    node.last_cert_check = datetime.utcnow()
                    if "days_remaining" in node_result:
                        node.cert_days_remaining = node_result["days_remaining"]
                    if "expiry_date" in node_result:
                        try:
                            node.cert_expiry_date = datetime.strptime(
                                node_result["expiry_date"], "%Y-%m-%dT%H:%M:%S.%fZ"
                            )
                        except (ValueError, TypeError):
                            pass
                    node.cert_status = node_result.get("status", "unknown")

                db.commit()

                all_results[managed_cert.common_name] = results
                overall_statuses.append(cert_status)

                # Notify per cert
                try:
                    notifier.send_renewal_report(results, managed_cert.common_name, mode)
                    history.notification_sent = True
                    db.commit()
                except Exception as e:
                    logger.error(f"Notification failed for '{managed_cert.common_name}': {e}")

            # Determine run-level overall status
            if not overall_statuses:
                run_overall = RenewalStatus.SKIPPED
            elif all(s in (RenewalStatus.SUCCESS, RenewalStatus.SKIPPED) for s in overall_statuses):
                run_overall = RenewalStatus.SUCCESS
            elif any(s == RenewalStatus.FAILED for s in overall_statuses):
                run_overall = RenewalStatus.PARTIAL
            else:
                run_overall = RenewalStatus.SUCCESS

            # Update daemon status
            daemon_status.state = DaemonState.IDLE
            daemon_status.current_action = None
            daemon_status.last_run_at = datetime.utcnow()
            daemon_status.last_run_status = run_overall.value
            daemon_status.total_renewals += 1
            if run_overall in (RenewalStatus.SUCCESS, RenewalStatus.SKIPPED):
                daemon_status.successful_renewals += 1
            else:
                daemon_status.failed_renewals += 1

            db.commit()

            logger.info(f"Renewal run {run_id[:8]} completed: {run_overall.value}")
            return {"run_id": run_id, "status": run_overall.value, "results": all_results}

        except Exception as e:
            logger.error(f"Renewal run failed: {e}")
            try:
                daemon_status = db.query(DaemonStatus).first()
                if daemon_status:
                    daemon_status.state = DaemonState.ERROR
                    daemon_status.current_action = None
                    daemon_status.last_error = str(e)
                    daemon_status.failed_renewals += 1
                db.commit()
            except Exception:
                pass
            raise
        finally:
            logger.removeHandler(handler)
            log_buffer.close()
            db.close()

    def _renew_shared(self, ise, dns, config, nodes, threshold, db):
        """Shared certificate renewal workflow."""
        results = {}
        cn = config.get("common_name", "")
        primary_name = None

        for node in nodes:
            if node.is_primary:
                primary_name = node.name
                break
        if not primary_name:
            primary_name = nodes[0].name

        secondary_nodes = [n for n in nodes if n.name != primary_name]

        expiry = ise.check_certificate_expiry(cn, threshold, primary_name)
        if not expiry["needs_renewal"]:
            results[primary_name] = {"status": "ok", **expiry}
            for node in secondary_nodes:
                sec_expiry = ise.check_certificate_expiry(cn, threshold, node.name)
                if sec_expiry["needs_renewal"]:
                    results[node.name] = self._distribute_cert(ise, config, cn, primary_name, node.name)
                else:
                    results[node.name] = {"status": "ok", **sec_expiry}
            return results

        dns_record_id = None
        try:
            req = ise.initiate_acme_certificate_request(
                cn, config.get("san_names", []), config.get("key_type", "RSA_2048"),
                primary_name, config.get("portal_group_tag", "")
            )
            request_id = req.get("id") or req.get("requestId")

            time.sleep(10)
            challenge = ise.get_acme_challenge(request_id)
            challenge_name = challenge.get("recordName")
            challenge_value = challenge.get("recordValue")

            dns_record_id = dns.create_txt_record(challenge_name, challenge_value)
            time.sleep(90)

            ise.confirm_acme_challenge(request_id)
            cert = self._wait_for_cert(ise, cn, primary_name)

            if cert:
                ise.bind_certificate_to_portal(
                    cert["id"], config.get("portal_group_tag", ""), primary_name
                )
                results[primary_name] = {"status": "renewed", "certificate_id": cert.get("id")}
            else:
                results[primary_name] = {"status": "failed", "error": "Timeout waiting for cert"}

        except Exception as e:
            results[primary_name] = {"status": "failed", "error": str(e)}
        finally:
            if dns_record_id:
                try:
                    dns.delete_txt_record(dns_record_id)
                except Exception:
                    pass

        if results.get(primary_name, {}).get("status") == "renewed":
            for node in secondary_nodes:
                results[node.name] = self._distribute_cert(ise, config, cn, primary_name, node.name)

        return results

    def _renew_per_node(self, ise, dns, config, nodes, threshold, db):
        """Per-node certificate renewal workflow."""
        results = {}
        cn = config.get("common_name", "")
        dns_record_id = None
        dns_created = False

        for node in nodes:
            name = node.name
            try:
                expiry = ise.check_certificate_expiry(cn, threshold, name)
                if not expiry["needs_renewal"]:
                    results[name] = {"status": "ok", **expiry}
                    continue

                req = ise.initiate_acme_certificate_request(
                    cn, config.get("san_names", []), config.get("key_type", "RSA_2048"),
                    name, config.get("portal_group_tag", "")
                )
                request_id = req.get("id") or req.get("requestId")

                time.sleep(10)
                challenge = ise.get_acme_challenge(request_id)
                challenge_name = challenge.get("recordName")
                challenge_value = challenge.get("recordValue")

                if not dns_created:
                    dns_record_id = dns.create_txt_record(challenge_name, challenge_value)
                    dns_created = True
                    time.sleep(90)

                ise.confirm_acme_challenge(request_id)
                cert = self._wait_for_cert(ise, cn, name)

                if cert:
                    ise.bind_certificate_to_portal(
                        cert["id"], config.get("portal_group_tag", ""), name
                    )
                    results[name] = {"status": "renewed", "certificate_id": cert.get("id")}
                else:
                    results[name] = {"status": "failed", "error": "Timeout"}

            except Exception as e:
                results[name] = {"status": "failed", "error": str(e)}

        if dns_record_id:
            try:
                dns.delete_txt_record(dns_record_id)
            except Exception:
                pass

        return results

    def _distribute_cert(self, ise, config, cn, primary_name, target_name):
        """Export cert from primary and import to target."""
        try:
            primary_cert = ise.get_certificate_by_cn(cn, primary_name)
            if not primary_cert:
                return {"status": "failed", "error": "Primary cert not found"}

            cert_data = ise.export_certificate(primary_cert["id"], primary_name)
            ise.import_certificate(cert_data, target_name, config.get("portal_group_tag", ""))

            imported = ise.get_certificate_by_cn(cn, target_name)
            if imported:
                ise.bind_certificate_to_portal(
                    imported["id"], config.get("portal_group_tag", ""), target_name
                )
            return {"status": "renewed", "certificate_id": imported.get("id") if imported else None}
        except Exception as e:
            return {"status": "failed", "error": str(e)}

    def _wait_for_cert(self, ise, cn, node_name, max_wait=300, interval=15):
        """Poll for new certificate."""
        elapsed = 0
        while elapsed < max_wait:
            cert = ise.get_certificate_by_cn(cn, node_name)
            if cert:
                expiry_str = cert.get("expirationDate", "")
                try:
                    expiry = datetime.strptime(expiry_str, "%Y-%m-%dT%H:%M:%S.%fZ")
                    if expiry > datetime.utcnow() + timedelta(days=60):
                        return cert
                except ValueError:
                    pass
            time.sleep(interval)
            elapsed += interval
        return None
