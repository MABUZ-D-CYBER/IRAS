"""
alert_system.py — SMTP Email Alert System with OWASP Integration
Layer 4: Alert Layer

OWASP Features:
  → OWASP classification in email subject
  → Detection indicators included
  → IOCs listed in email body
  → Response workflow status included
"""

import os
import smtplib
import ssl
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

ALERT_LEVELS = {"CRITICAL", "HIGH"}

_threshold = os.getenv("ALERT_THRESHOLD", "high").upper()
if _threshold == "MEDIUM":
    ALERT_LEVELS = {"CRITICAL", "HIGH", "MEDIUM"}
elif _threshold == "LOW":
    ALERT_LEVELS = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}

SEVERITY_COLORS = {
    "CRITICAL": "#ef4444",
    "HIGH": "#f97316",
    "MEDIUM": "#eab308",
    "LOW": "#22c55e",
}

OWASP_TYPE_LABELS = {
    "MALICIOUS_SKILL": "OWASP-AS-01: Malicious Skill Discovery",
    "DATA_BREACH": "OWASP-AS-02: Data Breach via Skill",
    "SUPPLY_CHAIN_ATTACK": "OWASP-AS-03: Supply Chain Attack",
    "SKILL_ABUSE": "OWASP-AS-04: Skill Abuse/Misuse",
    "CONFIGURATION_DRIFT": "OWASP-AS-05: Configuration Drift",
    "CREDENTIAL_THEFT": "OWASP-AS-06: Credential Theft"
}


def check_and_send_alert(incident: dict, analysis: dict) -> dict:
    """Check severity and send OWASP-aligned email alert."""
    severity = analysis.get("severity", incident.get("severity", "LOW"))

    if severity not in ALERT_LEVELS:
        return {
            "sent": False,
            "to_email": None,
            "reason": f"Severity '{severity}' is below alert threshold",
            "timestamp": datetime.now().isoformat(),
        }

    smtp_email = os.getenv("SMTP_EMAIL", "").strip()
    smtp_password = os.getenv("SMTP_PASSWORD", "").strip()
    proprietor = os.getenv("PROPRIETOR_EMAIL", "").strip()

    if not all([smtp_email, smtp_password, proprietor]):
        print(f"[ALERT] ⚠️ Email not configured — would have sent OWASP alert for "
              f"{severity} incident to {proprietor or 'PROPRIETOR_EMAIL not set'}")
        return {
            "sent": False,
            "to_email": proprietor or None,
            "reason": "SMTP credentials not configured in .env",
            "timestamp": datetime.now().isoformat(),
        }

    try:
        _send_owasp_email(incident, analysis, smtp_email, smtp_password, proprietor)
        print(f"[ALERT] ✅ OWASP email sent to {proprietor} for {severity} incident")
        return {
            "sent": True,
            "to_email": proprietor,
            "reason": f"{severity} incident — OWASP alert threshold met",
            "timestamp": datetime.now().isoformat(),
        }
    except Exception as e:
        print(f"[ALERT] ❌ Email send failed: {e}")
        return {
            "sent": False,
            "to_email": proprietor,
            "reason": f"Send failed: {e}",
            "timestamp": datetime.now().isoformat(),
        }


def _send_owasp_email(incident: dict, analysis: dict,
                       from_email: str, password: str, to_email: str) -> None:
    """Send OWASP-aligned HTML email alert."""
    severity = analysis.get("severity", "UNKNOWN")
    inc_type = incident.get("type", "Unknown Incident")
    inc_id = incident.get("incident_id", "N/A")
    timestamp = incident.get("timestamp", datetime.now().isoformat())
    dnn_score = incident.get("dnn", {}).get("threat_score", "N/A")
    dnn_label = incident.get("dnn", {}).get("label", "Unknown")
    source_ip = incident.get("source_ip", "N/A")
    dest_ip = incident.get("dest_ip", "N/A")
    port = incident.get("port", "N/A")
    explanation = analysis.get("explanation", "No explanation available.")
    root_cause = analysis.get("root_cause", "Unknown")
    steps = analysis.get("remediation_steps", [])
    tips = analysis.get("prevention_tips", [])

    # OWASP Fields
    owasp_type = analysis.get("owasp_incident_type", "UNKNOWN")
    owasp_label = OWASP_TYPE_LABELS.get(owasp_type, owasp_type)
    indicators = analysis.get("detection_indicators", [])
    iocs = analysis.get("iocs", [])
    workflow = analysis.get("response_workflow", {})

    color = SEVERITY_COLORS.get(severity, "#6b7280")

    steps_html = "".join(
        f"<li style='margin:8px 0; padding:8px; background:#1e293b; border-radius:6px;'>{s}</li>"
        for s in steps
    )
    tips_html = "".join(
        f"<li style='margin:6px 0; color:#94a3b8;'>• {t}</li>"
        for t in tips
    )
    indicators_html = "".join(
        f"<li style='margin:4px 0; color:#cbd5e1;'>{i}</li>"
        for i in indicators[:5]
    )
    iocs_html = "".join(
        f"<tr><td style='padding:4px 8px;'>{ioc.get('type', 'unknown')}</td>"
        f"<td style='padding:4px 8px; font-family:monospace;'>{ioc.get('value', 'N/A')}</td>"
        f"<td style='padding:4px 8px;'>{ioc.get('confidence', 'medium').upper()}</td></tr>"
        for ioc in iocs[:5]
    )

    html_body = f"""
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><title>OWASP Security Alert</title></head>
<body style="margin:0;padding:0;font-family:Arial,sans-serif;background:#0f172a;color:#e2e8f0;">
  <table width="100%" cellpadding="0" cellspacing="0" style="padding:24px;">
    <tr><td>
      <div style="max-width:680px;margin:0 auto;background:#1e293b;border-radius:12px;overflow:hidden;">

        <!-- Header -->
        <div style="background:{color};padding:24px 32px;text-align:center;">
          <h1 style="margin:0;font-size:20px;color:#fff;">
            🛡️ OWASP Incident Alert
          </h1>
          <p style="margin:6px 0 0;font-size:14px;color:rgba(255,255,255,0.9);">
            {severity} Severity — {owasp_label}
          </p>
        </div>

        <!-- Incident Summary -->
        <div style="padding:24px 32px;">
          <table width="100%" style="border-collapse:collapse;font-size:13px;">
            <tr><td style="padding:6px 12px;background:#0f172a;color:#94a3b8;width:140px;">⚠️ SEVERITY</td>
                <td style="padding:6px 12px;background:#0f172a;font-weight:bold;color:{color};">{severity}</td></tr>
            <tr><td style="padding:6px 12px;background:#0f172a;color:#94a3b8;">📋 TYPE</td>
                <td style="padding:6px 12px;background:#0f172a;">{inc_type}</td></tr>
            <tr><td style="padding:6px 12px;background:#0f172a;color:#94a3b8;">📅 TIMESTAMP</td>
                <td style="padding:6px 12px;background:#0f172a;">{timestamp}</td></tr>
            <tr><td style="padding:6px 12px;background:#0f172a;color:#94a3b8;">🤖 DNN SCORE</td>
                <td style="padding:6px 12px;background:#0f172a;font-family:monospace;">{dnn_score} ({dnn_label})</td></tr>
            <tr><td style="padding:6px 12px;background:#0f172a;color:#94a3b8;">🌐 SOURCE</td>
                <td style="padding:6px 12px;background:#0f172a;font-family:monospace;">{source_ip} → {dest_ip}:{port}</td></tr>
            <tr><td style="padding:6px 12px;background:#0f172a;color:#94a3b8;">🔢 INCIDENT ID</td>
                <td style="padding:6px 12px;background:#0f172a;font-family:monospace;">#{inc_id}</td></tr>
          </table>

          <!-- OWASP Classification -->
          <div style="margin-top:16px;background:#0f172a;padding:12px 16px;border-radius:6px;border-left:3px solid #a78bfa;">
            <strong style="color:#a78bfa;font-size:12px;">OWASP Classification:</strong>
            <span style="font-size:13px;">{owasp_label}</span>
          </div>

          <!-- Detection Indicators -->
          <div style="margin-top:16px;">
            <h3 style="color:#38bdf8;margin:0 0 8px;font-size:12px;text-transform:uppercase;letter-spacing:1px;">
              🚨 Detection Indicators
            </h3>
            <ul style="margin:0;padding-left:16px;">{indicators_html}</ul>
          </div>

          <!-- IOCs -->
          {f'''
          <div style="margin-top:16px;">
            <h3 style="color:#38bdf8;margin:0 0 8px;font-size:12px;text-transform:uppercase;letter-spacing:1px;">
              🎯 Indicators of Compromise (IOCs)
            </h3>
            <table style="width:100%;font-size:12px;border-collapse:collapse;">
              <tr><th style="text-align:left;padding:4px 8px;background:#0f172a;">Type</th>
                  <th style="text-align:left;padding:4px 8px;background:#0f172a;">Value</th>
                  <th style="text-align:left;padding:4px 8px;background:#0f172a;">Confidence</th></tr>
              {iocs_html}
            </table>
          </div>
          ''' if iocs_html else ''}

          <!-- Explanation -->
          <div style="margin-top:16px;">
            <h3 style="color:#38bdf8;margin:0 0 8px;font-size:12px;text-transform:uppercase;letter-spacing:1px;">
              📝 What Is Happening
            </h3>
            <p style="margin:0;color:#cbd5e1;line-height:1.6;font-size:13px;">{explanation}</p>
            <p style="margin:6px 0 0;color:#64748b;font-size:12px;"><strong>Root Cause:</strong> {root_cause}</p>
          </div>

          <!-- Response Workflow -->
          <div style="margin-top:16px;">
            <h3 style="color:#38bdf8;margin:0 0 8px;font-size:12px;text-transform:uppercase;letter-spacing:1px;">
              📋 OWASP Response Workflow
            </h3>
            <div style="font-size:12px;color:#94a3b8;">
              {f'✅ Detect: {workflow.get("detect", "Pending")}' if workflow.get("detect") else '⏳ Detect: Pending'}<br>
              {f'✅ Analyze: {workflow.get("analyze", "Pending")}' if workflow.get("analyze") else '⏳ Analyze: Pending'}<br>
              {f'✅ Contain: {workflow.get("contain", "Pending")}' if workflow.get("contain") else '⏳ Contain: Pending'}<br>
              {f'✅ Investigate: {workflow.get("investigate", "Pending")}' if workflow.get("investigate") else '⏳ Investigate: Pending'}<br>
              {f'✅ Remediate: {workflow.get("remediate", "Pending")}' if workflow.get("remediate") else '⏳ Remediate: Pending'}<br>
              {f'✅ Communicate: {workflow.get("communicate", "Pending")}' if workflow.get("communicate") else '⏳ Communicate: Pending'}
            </div>
          </div>

          <!-- Remediation -->
          <div style="margin-top:16px;">
            <h3 style="color:#38bdf8;margin:0 0 8px;font-size:12px;text-transform:uppercase;letter-spacing:1px;">
              🔧 Immediate Remediation Steps
            </h3>
            <ol style="margin:0;padding-left:20px;color:#cbd5e1;font-size:13px;">{steps_html}</ol>
          </div>

          <!-- Prevention -->
          <div style="margin-top:16px;">
            <h3 style="color:#38bdf8;margin:0 0 8px;font-size:12px;text-transform:uppercase;letter-spacing:1px;">
              🛡️ Prevention Tips
            </h3>
            <ul style="margin:0;padding:0;list-style:none;font-size:13px;">{tips_html}</ul>
          </div>
        </div>

        <!-- Footer -->
        <div style="padding:16px 32px;background:#0f172a;text-align:center;border-top:1px solid #334155;">
          <p style="margin:0;font-size:11px;color:#475569;">
            Full dashboard: <a href="http://127.0.0.1:5000" style="color:#38bdf8;">http://127.0.0.1:5000</a>
            &nbsp;|&nbsp; OWASP Agentic Skills Top 10
          </p>
        </div>

      </div>
    </td></tr>
  </table>
</body>
</html>
"""

    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"🚨 OWASP {severity} INCIDENT: {owasp_label} [#{inc_id}]"
    msg["From"] = from_email
    msg["To"] = to_email
    msg.attach(MIMEText(html_body, "html"))

    smtp_host = os.getenv("SMTP_HOST", "smtp.gmail.com")
    smtp_port = int(os.getenv("SMTP_PORT", 587))
    context = ssl.create_default_context()

    with smtplib.SMTP(smtp_host, smtp_port) as server:
        server.ehlo()
        server.starttls(context=context)
        server.login(from_email, password)
        server.sendmail(from_email, to_email, msg.as_string())


def test_email() -> dict:
    """Send a test email to verify SMTP configuration."""
    smtp_email = os.getenv("SMTP_EMAIL", "").strip()
    smtp_password = os.getenv("SMTP_PASSWORD", "").strip()
    proprietor = os.getenv("PROPRIETOR_EMAIL", "").strip()

    if not all([smtp_email, smtp_password, proprietor]):
        return {"success": False, "error": "Missing .env configuration"}

    try:
        msg = MIMEMultipart()
        msg["Subject"] = "🧪 OWASP Test Email from Incident Response System"
        msg["From"] = smtp_email
        msg["To"] = proprietor
        body = "This is a test email to confirm your OWASP-aligned SMTP settings are working correctly."
        msg.attach(MIMEText(body, "plain"))

        smtp_host = os.getenv("SMTP_HOST", "smtp.gmail.com")
        smtp_port = int(os.getenv("SMTP_PORT", 587))
        context = ssl.create_default_context()

        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.ehlo()
            server.starttls(context=context)
            server.login(smtp_email, smtp_password)
            server.sendmail(smtp_email, proprietor, msg.as_string())
        return {"success": True, "message": f"OWASP test email sent to {proprietor}"}
    except Exception as e:
        return {"success": False, "error": str(e)}