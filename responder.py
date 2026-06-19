"""
responder.py — Incident Response & Logging
Layer 5: Response & Logging Layer

Stores incident data with unified 'incident_category' field.
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Optional

LOG_FILE = os.path.join(os.path.dirname(__file__), "incidents_log.json")

WORKFLOW_STEPS = [
    {"step": 1, "name": "Detect", "status": "pending"},
    {"step": 2, "name": "Analyze & Classify", "status": "pending"},
    {"step": 3, "name": "Notify Stakeholders", "status": "pending"},
    {"step": 4, "name": "Contain & Mitigate", "status": "pending"},
    {"step": 5, "name": "Investigate", "status": "pending"},
    {"step": 6, "name": "Remediate", "status": "pending"},
    {"step": 7, "name": "Communicate", "status": "pending"},
    {"step": 8, "name": "Post-Incident Review", "status": "pending"}
]


def _load_log() -> list:
    if not os.path.exists(LOG_FILE):
        return []
    try:
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, list) else []
    except (json.JSONDecodeError, IOError):
        return []


def _save_log(incidents: list) -> None:
    with open(LOG_FILE, "w", encoding="utf-8") as f:
        json.dump(incidents, f, indent=2, ensure_ascii=False)


def save_incident(incident: dict) -> dict:
    log = _load_log()
    incident_id = len(log) + 1
    incident["incident_id"] = incident_id
    if "timestamp" not in incident:
        incident["timestamp"] = datetime.now().isoformat()

    analysis = incident.get("analysis", {})
    workflow = analysis.get("response_workflow", {})

    # Build workflow status
    response_workflow = []
    for step in WORKFLOW_STEPS:
        step_name = step["name"].lower()
        status = "complete" if workflow.get(step_name) else "pending"
        response_workflow.append({
            "step": step["step"],
            "name": step["name"],
            "status": status,
            "details": workflow.get(step_name, "")
        })

    # ─── Extract category (prefer 'incident_category', fallback to 'owasp_incident_type') ───
    category = analysis.get("incident_category") or analysis.get("owasp_incident_type", "UNKNOWN")

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

        # ─── Unified category field ───
        "incident_category": category,

        "detection_indicators": analysis.get("detection_indicators", []),
        "iocs": analysis.get("iocs", []),
        "response_workflow": response_workflow,

        "dnn": incident.get("dnn", {}),
        "analysis": analysis,
        "alert": incident.get("alert", {"sent": False}),

        "post_incident_review": {
            "completed": False,
            "timestamp": None,
            "lessons_learned": [],
            "improvements": []
        }
    }

    # Keep old field for backward compatibility
    flat["owasp_incident_type"] = category

    log.append(flat)
    _save_log(log)
    _print_report(flat)
    return flat


def get_all_incidents() -> list:
    return list(reversed(_load_log()))


def get_stats() -> dict:
    log = _load_log()
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    categories = {}
    alerts_sent = 0
    dnn_scores = []
    ioc_count = 0

    for inc in log:
        sev = inc.get("severity", "LOW")
        counts[sev] = counts.get(sev, 0) + 1

        cat = inc.get("incident_category", "UNKNOWN")
        categories[cat] = categories.get(cat, 0) + 1

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
        "categories": categories,
        "ioc_count": ioc_count
    }


def clear_log() -> None:
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


def _print_report(inc: dict) -> None:
    sev = inc.get("severity", "UNKNOWN")
    icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(sev, "⚪")
    analysis = inc.get("analysis", {})
    dnn = inc.get("dnn", {})
    alert = inc.get("alert", {})

    print("\n" + "═" * 70)
    print(f"  {icon}  INCIDENT #{inc['incident_id']} | {sev} | {inc.get('type')}")
    print("═" * 70)
    print(f"  🕐  Time      : {inc.get('timestamp', 'N/A')}")
    print(f"  🌐  Source    : {inc.get('source_ip', 'N/A')} → {inc.get('dest_ip', 'N/A')}:{inc.get('port', 'N/A')}")
    print(f"  📦  Packets   : {inc.get('packet_count', 'N/A')}")
    print(f"  🤖  DNN Score : {dnn.get('threat_score', 'N/A')} ({dnn.get('label', 'N/A')})")
    print(f"  📋  Category  : {inc.get('incident_category', 'N/A')}")

    indicators = inc.get("detection_indicators", [])
    if indicators:
        print("\n  🚨  Detection Indicators:")
        for ind in indicators:
            print(f"       • {ind}")

    iocs = inc.get("iocs", [])
    if iocs:
        print("\n  🎯  IOCs:")
        for ioc in iocs:
            print(f"       • {ioc.get('type')}: {ioc.get('value')} (conf: {ioc.get('confidence', 'medium')})")

    workflow = inc.get("response_workflow", [])
    if workflow:
        print("\n  📋  Response Workflow:")
        for step in workflow:
            status_icon = "✅" if step.get("status") == "complete" else "⏳"
            print(f"       {status_icon} Step {step.get('step')}: {step.get('name')}")

    print(f"\n  📧  Email Alert: {'✅ Sent' if alert.get('sent') else '❌ Not sent'}")
    print("═" * 70 + "\n")
