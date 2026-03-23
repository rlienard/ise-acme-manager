"""
Email notification service.
"""

import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

logger = logging.getLogger(__name__)


class EmailNotifier:
    def __init__(self, config: dict):
        self.smtp_server = config.get("smtp_server", "")
        self.smtp_port = config.get("smtp_port", 587)
        self.username = config.get("smtp_username", "")
        self.password = config.get("smtp_password", "")
        self.recipients = config.get("alert_recipients", [])

    def send(self, subject: str, body: str):
        if not self.smtp_server or not self.recipients:
            logger.warning("SMTP not configured — skipping notification")
            return

        msg = MIMEMultipart()
        msg["From"] = self.username
        msg["To"] = ", ".join(self.recipients)
        msg["Subject"] = f"[ISE ACME] {subject}"
        msg.attach(MIMEText(body, "html"))

        try:
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.username, self.password)
                server.send_message(msg)
            logger.info(f"Email sent: {subject}")
        except Exception as e:
            logger.error(f"Failed to send email: {e}")

    def send_renewal_report(self, results: dict, common_name: str, mode: str):
        all_success = all(r.get("status") in ("ok", "renewed") for r in results.values())
        rows = ""
        for node, result in results.items():
            status = result.get("status", "unknown")
            if status == "ok":
                icon, detail = "🟢", f"Valid — {result.get('days_remaining', '?')} days"
            elif status == "renewed":
                icon, detail = "🟢", "Renewed successfully"
            else:
                icon, detail = "🔴", f"Failed — {result.get('error', 'Unknown')}"
            rows += f"<tr><td>{icon} {node}</td><td>{status.upper()}</td><td>{detail}</td></tr>"

        body = f"""
        <h2>{'✅' if all_success else '⚠️'} ISE ACME Certificate Renewal Report</h2>
        <p><b>Mode:</b> {mode} | <b>CN:</b> {common_name} | <b>Time:</b> {datetime.now().isoformat()}</p>
        <table border="1" cellpadding="8" cellspacing="0">
        <tr style="background:#f0f0f0"><th>Node</th><th>Status</th><th>Details</th></tr>
        {rows}</table>"""

        subject = "All Nodes OK" if all_success else "⚠️ Some Nodes Failed"
        self.send(subject, body)
