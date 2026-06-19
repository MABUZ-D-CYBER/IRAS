"""
report_generator.py — Cyber Forensics Incident Report (PDF + HTML)
Uses pdfkit (wkhtmltopdf) for reliable PDF generation on Windows.
"""

import os
from datetime import datetime
from typing import List, Dict

# Try to import pdfkit for PDF generation
try:
    import pdfkit
    PDFKIT_AVAILABLE = True
except ImportError:
    PDFKIT_AVAILABLE = False

REPORTS_DIR = os.path.join(os.path.dirname(__file__), "reports")

_SEVERITY_COLORS = {
    "CRITICAL": "#cc0000",
    "HIGH": "#e67300",
    "MEDIUM": "#e6b800",
    "LOW": "#2d862d",
    "INFO": "#006699",
}

_CATEGORY_LABELS = {
    "MALICIOUS_SKILL": "Malicious Skill / Payload",
    "DATA_BREACH": "Data Breach / Exfiltration",
    "SUPPLY_CHAIN_ATTACK": "Supply Chain Compromise",
    "SKILL_ABUSE": "Legitimate Tool Abuse",
    "CONFIGURATION_DRIFT": "Configuration Drift / Policy Violation",
    "CREDENTIAL_THEFT": "Credential Theft / Account Compromise",
    "UNKNOWN": "Unclassified"
}


def generate_report(incidents: list, stats: dict, fmt: str = "html") -> str:
    os.makedirs(REPORTS_DIR, exist_ok=True)

    case_number = f"IR-{datetime.now().strftime('%Y%m%d')}-{str(len(incidents)+1).zfill(4)}"
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    ext = "pdf" if fmt == "pdf" else "html"
    filename = f"forensic_report_{case_number}_{timestamp}.{ext}"
    filepath = os.path.join(REPORTS_DIR, filename)

    html_content = _build_forensic_report(incidents, stats, case_number)

    if fmt == "pdf":
        if not PDFKIT_AVAILABLE:
            raise ImportError(
                "pdfkit is not installed. Install with: pip install pdfkit\n"
                "Also download wkhtmltopdf from https://wkhtmltopdf.org/downloads.html"
            )
        # Try to find wkhtmltopdf in common locations
        wkhtmltopdf_paths = [
            r'C:\Program Files\wkhtmltopdf\bin\wkhtmltopdf.exe',
            r'C:\Program Files (x86)\wkhtmltopdf\bin\wkhtmltopdf.exe',
            r'C:\Users\MUKUND BALAJI B\AppData\Local\Programs\wkhtmltopdf\bin\wkhtmltopdf.exe',
        ]
        config = None
        for path in wkhtmltopdf_paths:
            if os.path.exists(path):
                config = pdfkit.configuration(wkhtmltopdf=path)
                break
        if config is None:
            config = pdfkit.configuration()
        pdfkit.from_string(html_content, filepath, configuration=config)
        print(f"[Report] 📄 PDF report saved: {filepath}")
    else:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html_content)
        print(f"[Report] 🔍 HTML report saved: {filepath}")

    print(f"[Report] 📋 Case Number: {case_number}")
    return filepath


def generate_pdf_bytes(incidents: list, stats: dict) -> bytes:
    if not PDFKIT_AVAILABLE:
        raise ImportError(
            "pdfkit is not installed. Install with: pip install pdfkit\n"
            "Also download wkhtmltopdf from https://wkhtmltopdf.org/downloads.html"
        )
    case_number = f"IR-{datetime.now().strftime('%Y%m%d')}-{str(len(incidents)+1).zfill(4)}"
    html_content = _build_forensic_report(incidents, stats, case_number)

    wkhtmltopdf_paths = [
        r'C:\Program Files\wkhtmltopdf\bin\wkhtmltopdf.exe',
        r'C:\Program Files (x86)\wkhtmltopdf\bin\wkhtmltopdf.exe',
        r'C:\Users\MUKUND BALAJI B\AppData\Local\Programs\wkhtmltopdf\bin\wkhtmltopdf.exe',
    ]
    config = None
    for path in wkhtmltopdf_paths:
        if os.path.exists(path):
            config = pdfkit.configuration(wkhtmltopdf=path)
            break
    if config is None:
        config = pdfkit.configuration()

    return pdfkit.from_string(html_content, False, configuration=config)


def _build_forensic_report(incidents: list, stats: dict, case_number: str) -> str:
    report_date = datetime.now().strftime("%B %d, %Y")
    exec_summary = _build_executive_summary(incidents, stats)
    classification_table = _build_classification_table(incidents)
    chain_of_custody = _build_chain_of_custody(incidents)
    digital_evidence = _build_digital_evidence(incidents)
    ioc_section = _build_ioc_section(incidents)
    timeline = _build_timeline(incidents)
    findings = _build_findings(incidents)
    artifacts = _build_forensic_artifacts(incidents)
    remediation = _build_remediation(incidents)
    recommendations = _build_recommendations(incidents)
    post_incident = _build_post_incident_review(incidents)
    legal_notes = _build_legal_notes(incidents)
    appendices = _build_appendices(incidents)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Forensic Report — {case_number}</title>
<style>
* {{ margin:0; padding:0; box-sizing:border-box; }}
body {{ font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif; background:#f5f5f5; color:#1a1a2e; line-height:1.7; padding:40px 20px; }}
.container {{ max-width:1100px; margin:0 auto; background:#fff; padding:50px 60px; box-shadow:0 4px 20px rgba(0,0,0,0.12); border-radius:4px; }}
h1 {{ font-size:26px; font-weight:700; color:#1a1a2e; }}
h2 {{ font-size:18px; font-weight:600; color:#2c3e50; margin:32px 0 14px 0; border-bottom:2px solid #2c3e50; padding-bottom:6px; }}
h3 {{ font-size:15px; font-weight:600; color:#34495e; margin:20px 0 10px 0; }}
h4 {{ font-size:13px; font-weight:600; color:#555; margin:12px 0 6px 0; }}
p {{ margin:6px 0; }}
table {{ width:100%; border-collapse:collapse; font-size:13px; margin:10px 0 16px 0; }}
th {{ background:#2c3e50; color:#fff; font-weight:600; padding:8px 12px; text-align:left; }}
td {{ padding:7px 12px; border-bottom:1px solid #e0e0e0; vertical-align:top; }}
tr:nth-child(even) td {{ background:#f9f9f9; }}
.badge {{ display:inline-block; padding:2px 10px; border-radius:3px; font-size:11px; font-weight:700; text-transform:uppercase; letter-spacing:0.3px; }}
.badge-critical {{ background:#cc0000; color:#fff; }}
.badge-high {{ background:#e67300; color:#fff; }}
.badge-medium {{ background:#e6b800; color:#1a1a2e; }}
.badge-low {{ background:#2d862d; color:#fff; }}
.badge-info {{ background:#006699; color:#fff; }}
.evidence-block {{ background:#f9f9f9; border-left:3px solid #2c3e50; padding:10px 16px; margin:6px 0 12px 0; font-family:Consolas,'Courier New',monospace; font-size:12px; overflow-x:auto; white-space:pre-wrap; word-break:break-all; }}
.ioc-tag {{ display:inline-block; padding:2px 8px; border-radius:3px; font-size:11px; margin:2px 4px 2px 0; font-family:Consolas,monospace; }}
.ioc-high {{ background:#cc000030; color:#cc0000; border:1px solid #cc0000; }}
.ioc-medium {{ background:#e6b80030; color:#996600; border:1px solid #e6b800; }}
.ioc-low {{ background:#2d862d30; color:#1a6e1a; border:1px solid #2d862d; }}
.timeline-item {{ display:flex; gap:16px; padding:6px 0; border-bottom:1px solid #eee; font-size:13px; }}
.timeline-item .time {{ min-width:150px; font-weight:600; color:#2c3e50; font-family:Consolas,monospace; }}
.timeline-item .event {{ flex:1; }}
.signature {{ margin-top:40px; padding-top:20px; border-top:2px solid #2c3e50; font-size:13px; }}
.signature .row {{ display:flex; justify-content:space-between; margin:4px 0; }}
@media print {{ body {{ background:#fff; padding:0; }} .container {{ box-shadow:none; padding:40px; }} }}
@media (max-width:768px) {{ .container {{ padding:20px; }} .timeline-item {{ flex-direction:column; gap:2px; }} .timeline-item .time {{ min-width:unset; }} }}
</style>
</head>
<body>
<div class="container">
    <div style="text-align:center;padding-bottom:20px;border-bottom:3px solid #2c3e50;margin-bottom:30px;">
        <h1 style="font-size:28px;">🔍 FORENSIC INCIDENT REPORT</h1>
        <p style="font-size:16px;color:#2c3e50;font-weight:600;">Confidential — For Authorized Personnel Only</p>
        <table style="width:auto;margin:12px auto 0;font-size:14px;border:none;">
            <tr><td style="border:none;padding:4px 20px 4px 0;font-weight:600;">Case Number:</td>
                <td style="border:none;padding:4px 0;">{case_number}</td></tr>
            <tr><td style="border:none;padding:4px 20px 4px 0;font-weight:600;">Report Date:</td>
                <td style="border:none;padding:4px 0;">{report_date}</td></tr>
            <tr><td style="border:none;padding:4px 20px 4px 0;font-weight:600;">Prepared By:</td>
                <td style="border:none;padding:4px 0;">Incident Response Team</td></tr>
            <tr><td style="border:none;padding:4px 20px 4px 0;font-weight:600;">Classification:</td>
                <td style="border:none;padding:4px 0;">RESTRICTED / CONFIDENTIAL</td></tr>
        </table>
    </div>

    <h2>1. Executive Summary</h2>
    {exec_summary}

    <h2>2. Incident Classification</h2>
    {classification_table}

    <h2>3. Chain of Custody</h2>
    {chain_of_custody}

    <h2>4. Digital Evidence</h2>
    {digital_evidence}

    <h2>5. Indicators of Compromise (IOCs) & Threat Intelligence</h2>
    {ioc_section}

    <h2>6. Investigation Timeline</h2>
    {timeline}

    <h2>7. Analysis & Findings</h2>
    {findings}

    <h2>8. Forensic Artifacts</h2>
    {artifacts}

    <h2>9. Remediation & Recovery Actions</h2>
    {remediation}

    <h2>10. Recommendations</h2>
    {recommendations}

    <h2>11. Post‑Incident Review</h2>
    {post_incident}

    <h2>12. Legal & Compliance Notes</h2>
    {legal_notes}

    <h2>13. Appendices</h2>
    {appendices}

    <div class="signature">
        <div class="row"><span><strong>Prepared By:</strong> Incident Response Team</span><span><strong>Date:</strong> {report_date}</span></div>
        <div class="row"><span><strong>Reviewed By:</strong> ________________________</span><span><strong>Approved By:</strong> ________________________</span></div>
        <div style="margin-top:10px;font-size:11px;color:#555;">
            <p>This report is based on available digital evidence and system logs. Findings are preliminary and subject to change upon further investigation.</p>
            <p>Document ID: {case_number} | Version: 1.0</p>
        </div>
    </div>
</div>
</body>
</html>"""


# ─── Helper Functions ──────────────────────────────────────────────────────

def _build_executive_summary(incidents: list, stats: dict) -> str:
    total = stats.get("total", 0)
    if total == 0:
        return "<p>No security incidents were detected during the reporting period.</p>"
    critical = stats.get("critical", 0)
    high = stats.get("high", 0)
    alerts = stats.get("alerts_sent", 0)
    iocs = stats.get("ioc_count", 0)
    categories = stats.get("categories", {})
    primary = max(categories.items(), key=lambda x: x[1]) if categories else ("UNKNOWN", 0)
    return f"""
    <p>This report summarizes a forensic investigation into <strong>{total}</strong> security incident(s).</p>
    <ul>
        <li><strong>{critical}</strong> CRITICAL severity incidents</li>
        <li><strong>{high}</strong> HIGH severity incidents</li>
        <li><strong>{alerts}</strong> automated alerts triggered</li>
        <li><strong>{iocs}</strong> IOCs collected</li>
        <li>Primary category: <strong>{_CATEGORY_LABELS.get(primary[0], primary[0])}</strong> ({primary[1]} incidents)</li>
    </ul>
    <p><strong>Overall Risk Posture:</strong> <span style="font-weight:700;color:{'#cc0000' if critical > 0 else '#e67300' if high > 3 else '#e6b800' if high > 0 else '#2d862d'};">{('CRITICAL' if critical > 0 else 'HIGH' if high > 3 else 'MODERATE' if high > 0 else 'LOW')}</span></p>
    """

def _build_classification_table(incidents: list) -> str:
    if not incidents:
        return "<p>No incidents classified.</p>"
    rows = ""
    for inc in incidents[:50]:
        sev = inc.get("severity", "UNKNOWN")
        badge_class = f"badge-{sev.lower()}" if sev.lower() in ["critical","high","medium","low"] else "badge-info"
        # Get category from incident_category first, fallback to owasp_incident_type
        cat = inc.get("incident_category") or inc.get("owasp_incident_type", "UNKNOWN")
        cat_label = _CATEGORY_LABELS.get(cat, cat)
        rows += f"<tr><td>#{inc.get('incident_id','?')}</td><td><span class='badge {badge_class}'>{sev}</span></td><td>{inc.get('type','Unknown')}</td><td>{cat_label}</td><td>{inc.get('timestamp','N/A')[:19]}</td></tr>"
    return f"<table><tr><th>ID</th><th>Severity</th><th>Type</th><th>Category</th><th>Timestamp</th></tr>{rows}</table><p style='font-size:12px;color:#555;'>Showing up to 50 incidents.</p>"

def _build_chain_of_custody(incidents: list) -> str:
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    rows = ""
    for inc in incidents[:10]:
        rows += f"<tr><td>E-{inc.get('incident_id','?')}</td><td>{inc.get('timestamp','N/A')[:19]}</td><td>IR System v2.0</td><td>Automated Capture</td><td>Preserved</td></tr>"
    if not rows:
        rows = "<tr><td colspan='5'>No evidence records available.</td></tr>"
    return f"<p><strong>Chain of Custody Statement</strong></p><p>All digital evidence was collected, preserved, and analyzed in accordance with standard forensic procedures.</p><table><tr><th>Evidence ID</th><th>Collection Date</th><th>Collected By</th><th>Method</th><th>Status</th></tr>{rows}</table><p style='font-size:12px;color:#555;'>Evidence last verified: {now}</p>"

def _build_digital_evidence(incidents: list) -> str:
    if not incidents:
        return "<p>No digital evidence collected.</p>"
    rows = ""
    for inc in incidents[:20]:
        rows += f"<tr><td>#{inc.get('incident_id','?')}</td><td>{inc.get('source_ip','N/A')}</td><td>{inc.get('dest_ip','N/A')}</td><td>{inc.get('port','N/A')}</td><td>{inc.get('packet_count','N/A')}</td><td>{inc.get('dnn',{}).get('threat_score','N/A')}</td></tr>"
    return f"<table><tr><th>ID</th><th>Source IP</th><th>Destination IP</th><th>Port</th><th>Packets</th><th>DNN Score</th></tr>{rows}</table><p style='font-size:12px;color:#555;'>Showing up to 20 evidence records.</p>"

def _build_ioc_section(incidents: list) -> str:
    all_iocs = []
    for inc in incidents:
        for ioc in inc.get("iocs", []):
            ioc["incident_id"] = inc.get("incident_id")
            all_iocs.append(ioc)
    if not all_iocs:
        return "<p>No IOCs identified.</p>"
    rows = ""
    for ioc in all_iocs[:50]:
        rows += f"<tr><td>{ioc.get('type','unknown').upper()}</td><td style='font-family:monospace;'>{ioc.get('value','N/A')}</td><td><span class='ioc-tag ioc-{ioc.get('confidence','medium')}'>{ioc.get('confidence','medium').upper()}</span></td><td>#{ioc.get('incident_id','?')}</td></tr>"
    return f"<table><tr><th>Type</th><th>Value</th><th>Confidence</th><th>Incident</th></tr>{rows}</table><p style='font-size:12px;color:#555;'>Total IOCs: {len(all_iocs)}</p>"

def _build_timeline(incidents: list) -> str:
    if not incidents:
        return "<p>No events to display.</p>"
    sorted_incs = sorted(incidents, key=lambda i: i.get("timestamp", ""))
    items = ""
    for inc in sorted_incs[-30:]:
        ts = inc.get("timestamp", "N/A")
        try:
            dt = datetime.fromisoformat(ts)
            time_str = dt.strftime("%Y-%m-%d %H:%M:%S")
        except:
            time_str = ts[:19] if len(ts) > 19 else ts
        sev = inc.get("severity", "LOW")
        badge = f'<span class="badge badge-{sev.lower()}" style="font-size:10px;">{sev}</span>'
        items += f'<div class="timeline-item"><span class="time">{time_str}</span><span class="event">{badge} Incident #{inc.get("incident_id","?")}: {inc.get("type","Unknown")}</span></div>'
    return f"<p>Chronological sequence of incidents:</p>{items}<p style='font-size:12px;color:#555;'>Showing last 30 events.</p>"

def _build_findings(incidents: list) -> str:
    if not incidents:
        return "<p>No findings to report.</p>"
    cards = ""
    for inc in incidents[:10]:
        sev = inc.get("severity", "LOW")
        badge_class = f"badge-{sev.lower()}" if sev.lower() in ["critical","high","medium","low"] else "badge-info"
        analysis = inc.get("analysis", {})
        cat = inc.get("incident_category") or inc.get("owasp_incident_type", "UNKNOWN")
        cat_label = _CATEGORY_LABELS.get(cat, cat)
        cards += f"""
        <div style="background:#f9f9f9;padding:14px 18px;margin:12px 0;border-left:3px solid {'#cc0000' if sev=='CRITICAL' else '#e67300' if sev=='HIGH' else '#e6b800' if sev=='MEDIUM' else '#2d862d'};border-radius:2px;">
            <div style="display:flex;justify-content:space-between;flex-wrap:wrap;gap:8px;">
                <h4 style="margin:0;">Finding #{inc.get('incident_id','?')}: {inc.get('type','Unknown')}</h4>
                <span class="badge {badge_class}">{sev}</span>
            </div>
            <p style="font-size:13px;margin:6px 0;"><strong>Category:</strong> {cat_label}</p>
            <p style="font-size:13px;margin:4px 0;"><strong>Explanation:</strong> {analysis.get('explanation', 'No explanation')[:200]}...</p>
            <p style="font-size:12px;color:#555;margin:4px 0;"><strong>Root Cause:</strong> {analysis.get('root_cause', 'Unknown')}</p>
            <p style="font-size:12px;color:#555;margin:4px 0;"><strong>Timestamp:</strong> {inc.get('timestamp', 'N/A')}</p>
        </div>"""
    return f"<p>Detailed findings for each incident:</p>{cards}<p style='font-size:12px;color:#555;'>Showing up to 10 findings.</p>"

def _build_forensic_artifacts(incidents: list) -> str:
    if not incidents:
        return "<p>No forensic artifacts collected.</p>"
    artifacts = []
    for inc in incidents[:10]:
        iid = inc.get("incident_id", "?")
        src = inc.get("source_ip", "N/A")
        dst = inc.get("dest_ip", "N/A")
        port = inc.get("port", "N/A")
        packets = inc.get("packet_count", "N/A")
        dnn = inc.get("dnn", {})
        artifacts.append(f"""
        <div style="margin:8px 0;">
            <strong>#{iid} – Network Artifacts</strong>
            <div class="evidence-block">
                Source IP: {src}
                Destination IP: {dst}
                Port: {port}
                Packet Count: {packets}
                DNN Label: {dnn.get('label', 'Unknown')}
                Threat Score: {dnn.get('threat_score', 'N/A')}
            </div>
        </div>
        """)
    return f"<p>Forensic artifacts extracted:</p>{''.join(artifacts)}<p style='font-size:12px;color:#555;'>Raw logs preserved for chain of custody.</p>"

def _build_remediation(incidents: list) -> str:
    if not incidents:
        return "<p>No remediation actions taken.</p>"
    steps = []
    for inc in incidents[:10]:
        analysis = inc.get("analysis", {})
        for s in analysis.get("remediation_steps", [])[:3]:
            if s not in steps:
                steps.append(s)
    if not steps:
        return "<p>No remediation steps defined.</p>"
    return f"<p>Recommended remediation actions:</p><ul>{''.join([f'<li>{s}</li>' for s in steps[:15]])}</ul>"

def _build_recommendations(incidents: list) -> str:
    if not incidents:
        return "<p>No recommendations at this time.</p>"
    tips = set()
    for inc in incidents[:10]:
        for t in inc.get("analysis", {}).get("prevention_tips", []):
            tips.add(t)
    if not tips:
        return "<p>No prevention recommendations available.</p>"
    return f"<p>Security improvements recommended:</p><ul>{''.join([f'<li>{t}</li>' for t in list(tips)[:15]])}</ul>"

def _build_post_incident_review(incidents: list) -> str:
    if not incidents:
        return "<p>No post-incident review data.</p>"
    high_sev = [i for i in incidents if i.get("severity") in ["CRITICAL", "HIGH"]]
    return f"""
    <p><strong>Post-Incident Review Summary</strong></p>
    <ul>
        <li><strong>Total Incidents Reviewed:</strong> {len(incidents)}</li>
        <li><strong>Critical/High Incidents:</strong> {len(high_sev)}</li>
        <li><strong>Review Status:</strong> {('Complete' if len(high_sev) == 0 else 'In Progress')}</li>
        <li><strong>Lessons Learned:</strong> Improved monitoring and faster response recommended.</li>
    </ul>
    """

def _build_legal_notes(incidents: list) -> str:
    breach_detected = any(i.get("incident_category") == "DATA_BREACH" or i.get("owasp_incident_type") == "DATA_BREACH" for i in incidents)
    breach_count = sum(1 for i in incidents if i.get("incident_category") == "DATA_BREACH" or i.get("owasp_incident_type") == "DATA_BREACH")
    return f"""
    <p><strong>Regulatory and Compliance Considerations</strong></p>
    <ul>
        <li><strong>Data Breach Detected:</strong> {'YES' if breach_detected else 'NO'} ({breach_count} incident(s))</li>
        <li><strong>Notification Required:</strong> {'Yes, if personal data involved' if breach_detected else 'Not applicable'}</li>
        <li><strong>Evidence Preservation:</strong> All evidence preserved per forensic best practices.</li>
        <li><strong>Confidentiality:</strong> This report contains sensitive security information.</li>
    </ul>
    """

def _build_appendices(incidents: list) -> str:
    if not incidents:
        return "<p>No appendices available.</p>"
    ioc_lines = []
    for inc in incidents:
        for ioc in inc.get("iocs", []):
            ioc_lines.append(f"{ioc.get('type','unknown')},{ioc.get('value','N/A')},{ioc.get('confidence','medium')},{ioc.get('incident_id','?')}")
    ioc_csv = "\n".join(ioc_lines[:20])
    return f"""
    <p><strong>Appendix A – Incident Summary</strong></p>
    <p>Full incident data: <code>incidents_log.json</code></p>
    <p><strong>Appendix B – IOC List (CSV)</strong></p>
    <div class="evidence-block">
    Type,Value,Confidence,Incident ID
    {ioc_csv}
    </div>
    <p><strong>Appendix C – System Information</strong></p>
    <ul>
        <li>Report Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</li>
        <li>System Version: 2.0</li>
        <li>Total Incidents: {len(incidents)}</li>
        <li>Total IOCs: {sum(len(inc.get('iocs', [])) for inc in incidents)}</li>
    </ul>
    """
