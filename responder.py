"""
responder.py — Incident Response & Logging (OWASP Enhanced)
Layer 5: Response & Logging Layer

OWASP Agentic Skills Top 10 Integration:
  → 8-Step Response Workflow Tracking
  → IOC Collection and Storage
  → Post-Incident Review Data
  → Communication Templates
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Optional

LOG_FILE = os.path.join(os.path.dirname(__file__), "incidents_log.json")


# ─── OWASP Response Workflow ──────────────────────────────────────────────

OWASP_WORKFLOW_STEPS = [
    {"step": 1, "name": "Detect", "status": "pending"},
    {"step": 2, "name": "Analyze & Classify", "status": "pending"},
    {"step": 3, "name": "Notify Stakeholders", "status": "pending"},
    {"step": 4, "name": "Contain & Mitigate", "status": "pending"},
    {"step": 5, "name": "Investigate", "status": "pending"},
    {"step": 6, "name": "Remediate", "status": "pending"},
    {"step": 7, "name": "Communicate", "status": "pending"},
    {"step": 8, "name": "Post-Incident Review", "status": "pending"}
]


# ─── Read / Write Helpers ──────────────────────────────────────────────────

def _load_log() -> list:
    """Load the incident log from disk"""
    if not os.path.exists(LOG_FILE):
        return []
    try:
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, list) else []
    except (json.JSONDecodeError, IOError):
        return []


def _save_log(incidents: list) -> None:
    """Persist the incident list back to disk"""
    with open(LOG_FILE, "w", encoding="utf-8") as f:
        json.dump(incidents, f, indent=2, ensure_ascii=False)


# ─── Public API ────────────────────────────────────────────────────────────

def save_incident(incident: dict) -> dict:
    """
    Save a fully processed incident with OWASP tracking.

    Args:
        incident: combined dict with 'dnn', 'analysis', 'alert' sub-dicts

    Returns:
        The saved incident dict with OWASP fields added
    """
    log = _load_log()

    # ── Assign unique ID ───────────────────────────────────────────────────
    incident_id = len(log) + 1
    incident["incident_id"] = incident_id

    # ── Ensure timestamp ──────────────────────────────────────────────────
    if "timestamp" not in incident:
        incident["timestamp"] = datetime.now().isoformat()

    # ── OWASP Response Workflow Tracking ──────────────────────────────────
    analysis = incident.get("analysis", {})
    workflow = analysis.get("response_workflow", {})

    # Build OWASP workflow status
    owasp_workflow = []
    for step in OWASP_WORKFLOW_STEPS:
        step_name = step["name"].lower()
        status = "complete" if workflow.get(step_name) else "pending"
        owasp_workflow.append({
            "step": step["step"],
            "name": step["name"],
            "status": status,
            "details": workflow.get(step_name, "")
        })

    # ── IOC Collection ────────────────────────────────────────────────────
    iocs = analysis.get("iocs", [])

    # ── Flatten for storage ──────────────────────────────────────────────
    flat = {
        "incident_id": incident_id,
        "timestamp": incident.get("timestamp"),
        "type": incident.get("type", "Unknown"),
        "severity": analysis.get("severity", incident.get("severity", "UNKNOWN")),
        "source_ip": incident.get("source_ip"),
        "dest_ip": incident.get("dest_ip"),
        "port": incident.get("port"),
        "packet_count": incident.get("packet_count"),
        "simulated": incident.get("simulated", False),

        # OWASP Fields
        "owasp_incident_type": analysis.get("owasp_incident_type", "SKILL_ABUSE"),
        "owasp_version": analysis.get("owasp_version", "Agentic Skills Top 10"),
        "detection_indicators": analysis.get("detection_indicators", []),
        "iocs": iocs,
        "response_workflow": owasp_workflow,

        # DNN output
        "dnn": incident.get("dnn", {}),

        # LLM analysis
        "analysis": analysis,

        # Email alert
        "alert": incident.get("alert", {"sent": False}),

        # Post-Incident Review (placeholder - will be completed later)
        "post_incident_review": {
            "completed": False,
            "timestamp": None,
            "lessons_learned": [],
            "improvements": []
        }
    }

    log.append(flat)
    _save_log(log)

    # ── Terminal Report ──────────────────────────────────────────────────
    _print_owasp_report(flat)

    return flat


def get_all_incidents() -> list:
    """Return all incidents, newest first"""
    return list(reversed(_load_log()))


def get_stats() -> dict:
    """Return summary statistics with OWASP metrics"""
    log = _load_log()

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    owasp_types = {}
    alerts_sent = 0
    dnn_scores = []
    ioc_count = 0

    for inc in log:
        sev = inc.get("severity", "LOW")
        counts[sev] = counts.get(sev, 0) + 1

        owasp_type = inc.get("owasp_incident_type", "UNKNOWN")
        owasp_types[owasp_type] = owasp_types.get(owasp_type, 0) + 1

        if inc.get("alert", {}).get("sent"):
            alerts_sent += 1

        score = inc.get("dnn", {}).get("threat_score")
        if score is not None:
            dnn_scores.append(score)

        ioc_count += len(inc.get("iocs", []))

    avg_score = round(sum(dnn_scores) / len(dnn_scores), 3) if dnn_scores else 0.0

    return {
        "total": len(log),
        "critical": counts.get("CRITICAL", 0),
        "high": counts.get("HIGH", 0),
        "medium": counts.get("MEDIUM", 0),
        "low": counts.get("LOW", 0),
        "alerts_sent": alerts_sent,
        "avg_dnn_score": avg_score,
        "owasp_types": owasp_types,
        "ioc_count": ioc_count
    }


def clear_log() -> None:
    """Delete all incidents"""
    _save_log([])
    print("[Responder] 🗑️ Incident log cleared")


def get_iocs(severity: Optional[str] = None) -> List[Dict]:
    """Get all collected Indicators of Compromise"""
    log = _load_log()
    iocs = []
    for inc in log:
        if severity and inc.get("severity") != severity:
            continue
        for ioc in inc.get("iocs", []):
            ioc["incident_id"] = inc.get("incident_id")
            ioc["timestamp"] = inc.get("timestamp")
            iocs.append(ioc)
    return iocs


# ─── OWASP Terminal Report ──────────────────────────────────────────────────

_SEVERITY_ICONS = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🟡",
    "LOW": "🟢",
}

def _print_owasp_report(inc: dict) -> None:
    """Pretty-print OWASP incident report to terminal"""
    sev = inc.get("severity", "UNKNOWN")
    icon = _SEVERITY_ICONS.get(sev, "⚪")
    analysis = inc.get("analysis", {})
    dnn = inc.get("dnn", {})
    alert = inc.get("alert", {})
    workflow = inc.get("response_workflow", [])

    print("\n" + "═" * 70)
    print(f"  {icon}  OWASP INCIDENT #{inc['incident_id']} | {sev} | {inc.get('type')}")
    print("═" * 70)
    print(f"  🕐  Time      : {inc.get('timestamp', 'N/A')}")
    print(f"  🌐  Source    : {inc.get('source_ip', 'N/A')} → {inc.get('dest_ip', 'N/A')}:{inc.get('port', 'N/A')}")
    print(f"  📦  Packets   : {inc.get('packet_count', 'N/A')}")
    print(f"  🤖  DNN Score : {dnn.get('threat_score', 'N/A')} ({dnn.get('label', 'N/A')})")
    print(f"  📋  OWASP Type: {inc.get('owasp_incident_type', 'N/A')}")

    # Detection Indicators
    indicators = inc.get("detection_indicators", [])
    if indicators:
        print("\n  🚨  Detection Indicators:")
        for ind in indicators:
            print(f"       • {ind}")

    # IOC's
    iocs = inc.get("iocs", [])
    if iocs:
        print("\n  🎯  Indicators of Compromise (IOCs):")
        for ioc in iocs:
            print(f"       • {ioc.get('type')}: {ioc.get('value')} (confidence: {ioc.get('confidence', 'medium')})")

    # Response Workflow
    if workflow:
        print("\n  📋  OWASP Response Workflow:")
        for step in workflow:
            status_icon = "✅" if step.get("status") == "complete" else "⏳"
            print(f"       {status_icon} Step {step.get('step')}: {step.get('name')}")

    print(f"\n  📧  Email Alert: {'✅ Sent' if alert.get('sent') else '❌ Not sent'}")
    print("═" * 70 + "\n")