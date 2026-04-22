"""
AzureGuard - Alert Manager
Sends email notifications for compliance failures.
"""

import os
import smtplib
import logging
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime

from .compliance_engine import ComplianceResult, Severity

logger = logging.getLogger(__name__)

SEVERITY_COLORS = {
    Severity.CRITICAL: "#DC2626",
    Severity.HIGH:     "#EA580C",
    Severity.MEDIUM:   "#D97706",
    Severity.LOW:      "#2563EB",
    Severity.INFO:     "#6B7280",
}

SEVERITY_EMOJI = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH:     "🟠",
    Severity.MEDIUM:   "🟡",
    Severity.LOW:      "🔵",
    Severity.INFO:     "⚪",
}


class AlertManager:
    """Sends email alerts for compliance failures."""

    def __init__(self):
        self.smtp_host = os.environ.get("SMTP_HOST", "smtp.gmail.com")
        self.smtp_port = int(os.environ.get("SMTP_PORT", "587"))
        self.smtp_user = os.environ.get("SMTP_USER", "")
        self.smtp_pass = os.environ.get("SMTP_PASS", "")
        self.alert_to  = os.environ.get("ALERT_EMAIL", self.smtp_user)

    def should_alert(self, result: ComplianceResult) -> bool:
        """Only alert on CRITICAL and HIGH failures."""
        return not result.passed and result.severity in (Severity.CRITICAL, Severity.HIGH)

    def send_alert_digest(self, results: list[ComplianceResult], score: dict) -> bool:
        """Send a single digest email with all current failures."""
        failures = [r for r in results if not r.passed and r.severity in (Severity.CRITICAL, Severity.HIGH)]
        if not failures:
            logger.info("No critical/high failures — no alert email sent.")
            return True

        subject = f"[AzureGuard] {len(failures)} compliance issue(s) — Score: {score['score']}/100"
        body = self._build_html(failures, score)

        return self._send_email(subject, body)

    def _build_html(self, failures: list[ComplianceResult], score: dict) -> str:
        score_color = "#16A34A" if score["score"] >= 80 else "#D97706" if score["score"] >= 60 else "#DC2626"

        rows = ""
        for f in sorted(failures, key=lambda x: list(Severity).index(x.severity)):
            color = SEVERITY_COLORS[f.severity]
            emoji = SEVERITY_EMOJI[f.severity]
            rows += f"""
            <tr>
              <td style="padding:10px 12px;border-bottom:1px solid #f0f0f0">
                <span style="background:{color};color:#fff;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600">{emoji} {f.severity.value.upper()}</span>
              </td>
              <td style="padding:10px 12px;border-bottom:1px solid #f0f0f0;font-weight:500">{f.rule_id}</td>
              <td style="padding:10px 12px;border-bottom:1px solid #f0f0f0">{f.resource_name}</td>
              <td style="padding:10px 12px;border-bottom:1px solid #f0f0f0;color:#555">{f.message}</td>
              <td style="padding:10px 12px;border-bottom:1px solid #f0f0f0;color:#2563EB;font-size:12px">{f.remediation}</td>
            </tr>"""

        return f"""
        <!DOCTYPE html><html><body style="font-family:Arial,sans-serif;max-width:900px;margin:0 auto;padding:20px;color:#333">
          <div style="background:#1e3a5f;color:#fff;padding:20px 24px;border-radius:8px 8px 0 0">
            <h1 style="margin:0;font-size:22px">🛡️ AzureGuard Compliance Report</h1>
            <p style="margin:4px 0 0;opacity:.8">{datetime.now().strftime('%Y-%m-%d %H:%M UTC')}</p>
          </div>
          <div style="background:#f8fafc;padding:20px 24px;border:1px solid #e2e8f0">
            <div style="display:inline-block;background:#fff;border-radius:8px;padding:16px 24px;border:2px solid {score_color}">
              <div style="font-size:13px;color:#666">Compliance Score</div>
              <div style="font-size:48px;font-weight:700;color:{score_color};line-height:1">{score['score']}</div>
              <div style="font-size:13px;color:#666">/100</div>
            </div>
            <div style="display:inline-block;margin-left:20px;vertical-align:top;padding-top:8px">
              <div>Total checks: <strong>{score['total']}</strong></div>
              <div style="color:#16A34A">✓ Passed: <strong>{score['passed']}</strong></div>
              <div style="color:#DC2626">✗ Failed: <strong>{score['failed']}</strong></div>
            </div>
          </div>
          <table style="width:100%;border-collapse:collapse;background:#fff;border:1px solid #e2e8f0;border-top:none">
            <thead>
              <tr style="background:#f1f5f9">
                <th style="padding:10px 12px;text-align:left;font-size:12px;color:#64748b">SEVERITY</th>
                <th style="padding:10px 12px;text-align:left;font-size:12px;color:#64748b">RULE</th>
                <th style="padding:10px 12px;text-align:left;font-size:12px;color:#64748b">RESOURCE</th>
                <th style="padding:10px 12px;text-align:left;font-size:12px;color:#64748b">FINDING</th>
                <th style="padding:10px 12px;text-align:left;font-size:12px;color:#64748b">REMEDIATION</th>
              </tr>
            </thead>
            <tbody>{rows}</tbody>
          </table>
          <div style="padding:12px;background:#f8fafc;border:1px solid #e2e8f0;border-top:none;font-size:12px;color:#888">
            Generated by AzureGuard · <a href="https://github.com/marlondlx/azureguard">github.com/marlondlx/azureguard</a>
          </div>
        </body></html>"""

    def _send_email(self, subject: str, html_body: str) -> bool:
        if not self.smtp_user or not self.smtp_pass:
            logger.warning("SMTP credentials not configured — email not sent.")
            return False
        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = self.smtp_user
            msg["To"] = self.alert_to
            msg.attach(MIMEText(html_body, "html"))

            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                server.ehlo()
                server.starttls()
                server.login(self.smtp_user, self.smtp_pass)
                server.sendmail(self.smtp_user, self.alert_to, msg.as_string())

            logger.info(f"Alert email sent to {self.alert_to}")
            return True
        except Exception as e:
            logger.error(f"Failed to send email: {e}")
            return False
