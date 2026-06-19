"""
analyzer.py — LLM Incident Analyzer with Classification & Workflow
Inspired by OWASP Agentic Skills Top 10 but uses generic incident categories.

Features:
  → Incident Classification (CRITICAL/HIGH/MEDIUM/LOW)
  → Incident Category Mapping (MALICIOUS_SKILL, DATA_BREACH, etc.)
  → Detection Indicators
  → Indicators of Compromise (IOCs)
  → 8‑Step Response Workflow
"""

import os
import json
from datetime import datetime
from typing import Dict, List, Optional

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass


# ─── Severity Classification ────────────────────────────────────────────────

class SeverityLevel:
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


# ─── Incident Categories (generic) ──────────────────────────────────────────

INCIDENT_CATEGORIES = {
    "MALICIOUS_SKILL": {
        "id": "CAT-01",
        "name": "Malicious Skill / Payload",
        "description": "A malicious skill or component has been discovered.",
        "severity": SeverityLevel.HIGH,
        "detection_indicators": [
            "Automated scanner flags on installation",
            "User reports suspicious behavior",
            "Manual security review finds issues",
            "Threat intelligence indicates compromise",
            "Unusual network activity detected"
        ]
    },
    "DATA_BREACH": {
        "id": "CAT-02",
        "name": "Data Breach / Exfiltration",
        "description": "Sensitive data has been exfiltrated.",
        "severity": SeverityLevel.CRITICAL,
        "detection_indicators": [
            "Large outbound data transfers",
            "Unusual API calls to external domains",
            "Credential harvesting code detected",
            "Command injection patterns found"
        ]
    },
    "SUPPLY_CHAIN_ATTACK": {
        "id": "CAT-03",
        "name": "Supply Chain Compromise",
        "description": "Compromised dependencies could propagate malware.",
        "severity": SeverityLevel.HIGH,
        "detection_indicators": [
            "Dependency integrity check fails",
            "Known vulnerabilities in dependencies",
            "Behavioral changes after update"
        ]
    },
    "SKILL_ABUSE": {
        "id": "CAT-04",
        "name": "Legitimate Tool Abuse",
        "description": "Legitimate skill being used maliciously.",
        "severity": SeverityLevel.MEDIUM,
        "detection_indicators": [
            "Unusual access patterns",
            "Policy violations detected",
            "Excessive privilege usage"
        ]
    },
    "CONFIGURATION_DRIFT": {
        "id": "CAT-05",
        "name": "Configuration Drift / Policy Violation",
        "description": "Skill configuration deviates from secure baseline.",
        "severity": SeverityLevel.LOW,
        "detection_indicators": [
            "Configuration audit fails",
            "Security baseline violation",
            "Documentation discrepancy"
        ]
    },
    "CREDENTIAL_THEFT": {
        "id": "CAT-06",
        "name": "Credential Theft / Account Compromise",
        "description": "User credentials have been harvested.",
        "severity": SeverityLevel.CRITICAL,
        "detection_indicators": [
            "Credential access attempts",
            "API key rotation triggers",
            "Unusual authentication patterns"
        ]
    }
}


# ─── Response Workflow (8 steps) ──────────────────────────────────────────

RESPONSE_WORKFLOW = {
    "steps": [
        {"step": 1, "name": "Detect", "duration": "Immediate"},
        {"step": 2, "name": "Analyze & Classify", "duration": "30 minutes"},
        {"step": 3, "name": "Notify Stakeholders", "duration": "30 minutes"},
        {"step": 4, "name": "Contain & Mitigate", "duration": "1 hour"},
        {"step": 5, "name": "Investigate", "duration": "2-4 hours"},
        {"step": 6, "name": "Remediate", "duration": "1-3 days"},
        {"step": 7, "name": "Communicate", "duration": "Ongoing"},
        {"step": 8, "name": "Post-Incident Review", "duration": "1 week"}
    ]
}


# ─── Prompt Template ─────────────────────────────────────────────────────────

_SYSTEM_PROMPT = """\
You are a senior cybersecurity analyst AI. Analyze the given incident and provide a structured assessment.

Respond ONLY with a valid JSON object — no markdown, no extra text.

JSON structure (all fields required):
{
  "incident_category": "MALICIOUS_SKILL|DATA_BREACH|SUPPLY_CHAIN_ATTACK|SKILL_ABUSE|CONFIGURATION_DRIFT|CREDENTIAL_THEFT",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW",
  "detection_indicators": ["indicator1", "indicator2"],
  "explanation": "2-3 sentence description of what is happening",
  "root_cause": "1 sentence identifying the most likely root cause",
  "iocs": [
    {"type": "domain|ip_address|file_hash|url", "value": "example.com", "confidence": "high|medium|low"}
  ],
  "remediation_steps": [
    "Step 1: immediate action",
    "Step 2: containment action",
    "Step 3: recovery/cleanup action"
  ],
  "prevention_tips": [
    "Prevention tip 1",
    "Prevention tip 2",
    "Prevention tip 3"
  ],
  "response_workflow": {
    "detect": "How it was detected",
    "analyze": "Analysis findings",
    "contain": "Containment actions taken",
    "investigate": "Investigation steps",
    "remediate": "Remediation actions",
    "communicate": "Communication plan"
  }
}
"""


def _build_user_prompt(incident: dict, dnn: dict) -> str:
    return f"""Incident Details:
- Type: {incident.get("type", "Unknown")}
- Original Severity: {incident.get("severity", "UNKNOWN")}
- Source IP: {incident.get("source_ip", "N/A")}
- Destination IP: {incident.get("dest_ip", "N/A")}
- Port: {incident.get("port", "N/A")}
- Packet Count: {incident.get("packet_count", "N/A")}
- Timestamp: {incident.get("timestamp", datetime.now().isoformat())}

DNN Classification:
- Label: {dnn.get("label", "Unknown")}
- Threat Score: {dnn.get("threat_score", 0.0)}
- Probabilities: Normal={dnn.get("probabilities", {}).get("Normal", 0)}, \
Suspicious={dnn.get("probabilities", {}).get("Suspicious", 0)}, \
Malicious={dnn.get("probabilities", {}).get("Malicious", 0)}

Provide your cybersecurity analysis as JSON only."""


# ─── Main Analysis Function ──────────────────────────────────────────────────

def analyze_incident(incident: dict, dnn_result: dict) -> dict:
    """
    Analyze a network incident with comprehensive classification and workflow.

    Args:
        incident:   dict from detector.py or pcap pipeline
        dnn_result: dict from dnn_model.predict()

    Returns:
        Analysis dict with incident_category, severity, indicators, IOCs, workflow.
    """
    api_key = os.getenv("GROQ_API_KEY", "").strip()

    if api_key:
        try:
            result = _call_groq(api_key, incident, dnn_result)
            result["source"] = "groq"
            print(f"[LLM] ✅ Groq analysis: {result.get('incident_category')} — {result.get('severity')}")
            # Ensure category exists
            if "incident_category" not in result or not result["incident_category"]:
                result["incident_category"] = _default_category(dnn_result)
                print(f"[LLM] ℹ️ Added default category: {result['incident_category']}")
            return result
        except Exception as e:
            print(f"[LLM] ⚠️ Groq error: {e} — using fallback")

    # ── Rule-based fallback ──────────────────────────────────────────────────
    result = _fallback_analysis(incident, dnn_result)
    result["source"] = "fallback"
    # Safety check: ensure category is set
    if "incident_category" not in result or not result["incident_category"]:
        result["incident_category"] = _default_category(dnn_result)
        print(f"[LLM] ℹ️ Added default category: {result['incident_category']}")
    print(f"[LLM] ℹ️ Fallback: {result.get('incident_category')} — {result.get('severity')}")
    return result


def _default_category(dnn_result: dict) -> str:
    """Return a default category based on DNN label."""
    dnn_label = dnn_result.get("label", "Normal")
    if dnn_label == "Malicious":
        return "MALICIOUS_SKILL"
    elif dnn_label == "Suspicious":
        return "SKILL_ABUSE"
    else:
        return "CONFIGURATION_DRIFT"


# ─── Groq Call ───────────────────────────────────────────────────────────────

def _call_groq(api_key: str, incident: dict, dnn: dict) -> dict:
    import urllib.request

    payload = json.dumps({
        "model": "llama-3.3-70b-versatile",
        "max_tokens": 1200,
        "temperature": 0.3,
        "messages": [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": _build_user_prompt(incident, dnn)},
        ]
    }).encode("utf-8")

    req = urllib.request.Request(
        "https://api.groq.com/openai/v1/chat/completions",
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
        method="POST",
    )

    with urllib.request.urlopen(req, timeout=20) as resp:
        body = json.loads(resp.read())

    raw_text = body["choices"][0]["message"]["content"].strip()

    if raw_text.startswith("```"):
        raw_text = raw_text.split("```")[1]
        if raw_text.startswith("json"):
            raw_text = raw_text[4:]

    return json.loads(raw_text)


# ─── Rule-based Fallback ─────────────────────────────────────────────────────

_FALLBACK_LIBRARY = {
    "DDoS Attack Suspected": {
        "incident_category": "SKILL_ABUSE",
        "severity": "HIGH",
        "detection_indicators": [
            "Unusual network activity detected",
            "Large volume of traffic from multiple sources",
            "Service degradation or denial"
        ],
        "explanation": "A large volume of traffic from multiple sources is flooding the target, causing denial of service. This pattern matches a distributed attack designed to exhaust server resources.",
        "root_cause": "Coordinated botnet sending high-rate packet floods to overwhelm network bandwidth.",
        "iocs": [
            {"type": "ip_address", "value": "Multiple sources", "confidence": "high"},
            {"type": "domain", "value": "DDoS attack pattern", "confidence": "medium"}
        ],
        "remediation_steps": [
            "Step 1: Enable rate limiting on your firewall immediately to drop excess traffic.",
            "Step 2: Block the top source IP ranges identified in traffic logs using firewall ACLs.",
            "Step 3: Contact your ISP to activate upstream DDoS scrubbing / traffic filtering."
        ],
        "prevention_tips": [
            "Deploy a CDN with built-in DDoS protection (e.g., Cloudflare, AWS Shield).",
            "Configure automatic IP blacklisting triggered by packet-rate thresholds.",
            "Enable traffic anomaly alerts on your router and edge firewall."
        ],
        "response_workflow": {
            "detect": "Traffic anomaly detection triggered by packet rate exceeding threshold",
            "analyze": "Identified as coordinated DDoS attack from multiple source IPs",
            "contain": "Rate limiting enabled, top source IPs blocked",
            "investigate": "Traffic logs analyzed for attack patterns",
            "remediate": "ISP DDoS scrubbing activated",
            "communicate": "Incident report generated for stakeholders"
        }
    },
    "SQL Injection Attempt": {
        "incident_category": "SKILL_ABUSE",
        "severity": "CRITICAL",
        "detection_indicators": [
            "Command injection patterns found",
            "Suspicious SQL code in request parameters",
            "Database error responses"
        ],
        "explanation": "Malicious SQL code has been detected in HTTP request parameters targeting your database. An attacker is attempting to bypass authentication or extract sensitive data.",
        "root_cause": "Unsanitised user input in web application forms being passed directly to the database.",
        "iocs": [
            {"type": "ip_address", "value": "Attacker source IP", "confidence": "high"},
            {"type": "url", "value": "SQL injection payload", "confidence": "high"}
        ],
        "remediation_steps": [
            "Step 1: Block the attacking IP immediately on your WAF or firewall.",
            "Step 2: Review and sanitize all database queries using parameterised statements.",
            "Step 3: Rotate database credentials and audit recent access logs for breaches."
        ],
        "prevention_tips": [
            "Implement a Web Application Firewall (WAF) with SQL injection rules.",
            "Always use prepared statements and ORM frameworks — never raw SQL with user input.",
            "Enable database activity monitoring and alert on unusual query patterns."
        ],
        "response_workflow": {
            "detect": "WAF flagged SQL injection attempt in HTTP request",
            "analyze": "Confirmed as SQL injection targeting authentication endpoint",
            "contain": "Attacking IP blocked, request rejected",
            "investigate": "Database logs reviewed for successful exploitation",
            "remediate": "Input validation added, credentials rotated",
            "communicate": "Security team notified, incident documented"
        }
    },
    "Brute Force Login Attempt": {
        "incident_category": "CREDENTIAL_THEFT",
        "severity": "HIGH",
        "detection_indicators": [
            "Credential access attempts detected",
            "Multiple authentication failures",
            "Unusual authentication patterns"
        ],
        "explanation": "A high volume of authentication failures from a single IP or IP range indicates an automated brute-force attack against user accounts. The attacker is systematically testing password combinations.",
        "root_cause": "Automated credential stuffing or dictionary attack targeting SSH, RDP, or web login endpoints.",
        "iocs": [
            {"type": "ip_address", "value": "Attacker source IP", "confidence": "high"},
            {"type": "domain", "value": "Login endpoint", "confidence": "medium"}
        ],
        "remediation_steps": [
            "Step 1: Block the attacking source IP(s) in your firewall immediately.",
            "Step 2: Lock accounts that have experienced more than 10 failed login attempts.",
            "Step 3: Force a password reset for all accounts targeted during the attack window."
        ],
        "prevention_tips": [
            "Enable multi-factor authentication (MFA) on all remote access services.",
            "Implement account lockout policies after 5 failed attempts.",
            "Use fail2ban or equivalent to automatically ban IPs after repeated failures."
        ],
        "response_workflow": {
            "detect": "Authentication failure rate exceeded threshold",
            "analyze": "Identified as brute force attack from single IP",
            "contain": "Source IP blocked, affected accounts locked",
            "investigate": "Authentication logs reviewed for successful breaches",
            "remediate": "MFA enforced, password policies strengthened",
            "communicate": "Affected users notified"
        }
    },
    "Port Scan Detected": {
        "incident_category": "MALICIOUS_SKILL",
        "severity": "MEDIUM",
        "detection_indicators": [
            "Systematic port scanning pattern",
            "Multiple connection attempts to different ports",
            "Reconnaissance activity detected"
        ],
        "explanation": "A systematic sweep of multiple ports from a single source IP indicates active reconnaissance. The attacker is mapping your network to find open services and potential entry points.",
        "root_cause": "Attacker performing reconnaissance before launching a targeted attack on open services.",
        "iocs": [
            {"type": "ip_address", "value": "Scanning source IP", "confidence": "high"},
            {"type": "domain", "value": "Port scan pattern", "confidence": "medium"}
        ],
        "remediation_steps": [
            "Step 1: Block the scanning IP immediately using your perimeter firewall.",
            "Step 2: Review which ports are currently open — close any that are unnecessary.",
            "Step 3: Check logs for any subsequent connection attempts to discovered open ports."
        ],
        "prevention_tips": [
            "Implement port knocking or single-packet authorisation for sensitive services.",
            "Use a network IDS/IPS (Snort, Suricata) to detect and block scan patterns.",
            "Adopt a default-deny firewall policy — only whitelist required ports."
        ],
        "response_workflow": {
            "detect": "IDS flagged port scanning pattern",
            "analyze": "Confirmed as reconnaissance activity",
            "contain": "Scanning IP blocked, unnecessary ports closed",
            "investigate": "Logs reviewed for follow-up activity",
            "remediate": "Firewall rules updated, IDS signatures enhanced",
            "communicate": "Security team notified"
        }
    },
    "Malware Download Detected": {
        "incident_category": "MALICIOUS_SKILL",
        "severity": "CRITICAL",
        "detection_indicators": [
            "Outbound traffic to known malware distribution server",
            "Suspicious file download detected",
            "Command and control communication"
        ],
        "explanation": "Outbound traffic to a known malware distribution server has been detected. A system on your network may already be compromised and downloading additional malicious payloads.",
        "root_cause": "An infected host initiated a callback to a command-and-control (C2) server to retrieve malware.",
        "iocs": [
            {"type": "ip_address", "value": "C2 server IP", "confidence": "high"},
            {"type": "domain", "value": "Malware distribution domain", "confidence": "high"},
            {"type": "file_hash", "value": "Malware payload hash", "confidence": "high"}
        ],
        "remediation_steps": [
            "Step 1: Immediately isolate the affected host from the network.",
            "Step 2: Block the destination IP/domain at the firewall and DNS resolver.",
            "Step 3: Perform full malware scan on the isolated host and reimage if necessary."
        ],
        "prevention_tips": [
            "Deploy endpoint detection and response (EDR) tools on all workstations.",
            "Enable DNS filtering to block known malicious domains.",
            "Keep all software and OS patches up to date to close exploit entry points."
        ],
        "response_workflow": {
            "detect": "Network traffic flagged for suspicious outbound connection",
            "analyze": "Confirmed as malware download from known C2 server",
            "contain": "Host isolated, C2 domain blocked at DNS level",
            "investigate": "Host scanned for malware, logs reviewed for data exfiltration",
            "remediate": "Host reimaged, security patches applied",
            "communicate": "Incident response team notified, report generated"
        }
    },
    "DNS Tunneling Detected": {
        "incident_category": "DATA_BREACH",
        "severity": "HIGH",
        "detection_indicators": [
            "Unusually high DNS query volume",
            "Large payload sizes in DNS requests",
            "Data exfiltration via DNS protocol"
        ],
        "explanation": "Unusually high DNS query volume with large payload sizes detected. Attackers use DNS tunneling to smuggle data out of your network inside seemingly legitimate DNS requests.",
        "root_cause": "Data exfiltration via DNS protocol exploiting allowed outbound port 53 traffic.",
        "iocs": [
            {"type": "domain", "value": "Suspicious DNS queries", "confidence": "high"},
            {"type": "ip_address", "value": "Internal host generating queries", "confidence": "high"}
        ],
        "remediation_steps": [
            "Step 1: Block the suspicious DNS queries at your resolver and firewall.",
            "Step 2: Identify the internal host generating the queries and isolate it.",
            "Step 3: Investigate what data may have been exfiltrated during the activity window."
        ],
        "prevention_tips": [
            "Deploy a DNS security solution (e.g., Cisco Umbrella, Cloudflare Gateway).",
            "Monitor DNS response sizes — legitimate queries rarely exceed 512 bytes.",
            "Restrict outbound DNS to only your authorised resolvers."
        ],
        "response_workflow": {
            "detect": "DNS traffic anomaly detected (high query volume/large payload)",
            "analyze": "Confirmed as DNS tunneling data exfiltration",
            "contain": "DNS queries blocked, internal host isolated",
            "investigate": "Data exfiltration scope assessed, logs reviewed",
            "remediate": "DNS security deployed, outbound DNS restricted",
            "communicate": "Data breach notification prepared"
        }
    },
    "Unauthorized Access Attempt": {
        "incident_category": "CREDENTIAL_THEFT",
        "severity": "HIGH",
        "detection_indicators": [
            "Unusual login patterns detected",
            "Access from unexpected IP or time",
            "Suspicious authentication activity"
        ],
        "explanation": "An authentication attempt from an unexpected IP address or at an unusual time has been detected. This could indicate stolen credentials or an insider threat.",
        "root_cause": "Compromised credentials or an attacker exploiting a publicly accessible authentication service.",
        "iocs": [
            {"type": "ip_address", "value": "Unauthorized access source IP", "confidence": "high"},
            {"type": "domain", "value": "Authentication service target", "confidence": "medium"}
        ],
        "remediation_steps": [
            "Step 1: Immediately revoke or suspend the affected user account.",
            "Step 2: Reset credentials for all users who may have been exposed.",
            "Step 3: Review audit logs to determine what data or systems were accessed."
        ],
        "prevention_tips": [
            "Enforce MFA on all external-facing login portals.",
            "Implement geo-blocking for logins from unexpected countries.",
            "Use conditional access policies that flag logins outside normal working hours."
        ],
        "response_workflow": {
            "detect": "Authentication from unexpected location/time flagged",
            "analyze": "Confirmed as unauthorized access attempt using compromised credentials",
            "contain": "Account suspended, credentials revoked",
            "investigate": "Access logs reviewed for data exposure",
            "remediate": "MFA enforced, conditional access policies implemented",
            "communicate": "Affected user notified"
        }
    },
    # ── PCAP Analysis mapping ──
    "PCAP Analysis": {
        "incident_category": "SKILL_ABUSE",   # will be overridden by DNN label later
        "severity": "MEDIUM",
        "detection_indicators": [
            "Network packet capture analysis",
            "Traffic pattern review"
        ],
        "explanation": "Analysis of network traffic from a PCAP file. No specific threat pattern was identified by the DNN, but activity may still require review.",
        "root_cause": "Traffic pattern analysis from captured packets.",
        "iocs": [],
        "remediation_steps": [
            "Step 1: Review the packet capture for any suspicious activity.",
            "Step 2: If no threats found, archive the capture for future reference.",
            "Step 3: Continue monitoring network traffic."
        ],
        "prevention_tips": [
            "Regularly capture and review network traffic.",
            "Implement real‑time monitoring to complement periodic captures."
        ],
        "response_workflow": {
            "detect": "PCAP file uploaded and processed",
            "analyze": "Traffic analysed by DNN and LLM",
            "contain": "No containment needed (if no threat)",
            "investigate": "Further investigation if suspicious",
            "remediate": "Apply mitigations if required",
            "communicate": "Report generated"
        }
    }
}


def _fallback_analysis(incident: dict, dnn: dict) -> dict:
    inc_type = incident.get("type", "")
    dnn_label = dnn.get("label", "Unknown")
    dnn_score = dnn.get("threat_score", 0.0)

    # Try exact match on incident type first
    template = _FALLBACK_LIBRARY.get(inc_type)

    # Map DNN label to default severity
    severity_map = {
        "Malicious": "CRITICAL",
        "Suspicious": "HIGH",
        "Normal": "LOW"
    }
    default_severity = severity_map.get(dnn_label, "MEDIUM")

    if template:
        # If it's PCAP Analysis, override category based on DNN label
        if inc_type == "PCAP Analysis":
            if dnn_label == "Malicious":
                template["incident_category"] = "MALICIOUS_SKILL"
                template["severity"] = "HIGH"
            elif dnn_label == "Suspicious":
                template["incident_category"] = "SKILL_ABUSE"
                template["severity"] = "MEDIUM"
            else:
                template["incident_category"] = "CONFIGURATION_DRIFT"
                template["severity"] = "LOW"
        return template

    # Generic template for unknown types
    category = "MALICIOUS_SKILL" if dnn_label == "Malicious" else \
               "SKILL_ABUSE" if dnn_label == "Suspicious" else \
               "CONFIGURATION_DRIFT"

    severity = default_severity

    return {
        "incident_category": category,
        "severity": severity,
        "detection_indicators": [
            "Automated scanner flagged unusual activity",
            f"DNN classification: {dnn_label}",
            f"Threat score: {dnn_score:.2f}"
        ],
        "explanation": f"A {severity.lower()} security event has been detected. The DNN classified this as '{dnn_label}' with a threat score of {dnn_score:.2f}.",
        "root_cause": "Unusual network activity detected by DNN analysis.",
        "iocs": [
            {"type": "ip_address", "value": incident.get("source_ip", "Unknown"), "confidence": "medium"}
        ],
        "remediation_steps": [
            "Step 1: Log the event for further investigation.",
            "Step 2: Review logs for additional context.",
            "Step 3: Monitor for recurrence."
        ],
        "prevention_tips": [
            "Review and harden your security posture.",
            "Implement continuous monitoring.",
            "Conduct regular security assessments."
        ],
        "response_workflow": {
            "detect": "DNN classification triggered alert",
            "analyze": "Incident analyzed using framework",
            "contain": "Incident logged for investigation",
            "investigate": "Logs reviewed for context",
            "remediate": "Security improvements identified",
            "communicate": "Stakeholders notified"
        }
    }
