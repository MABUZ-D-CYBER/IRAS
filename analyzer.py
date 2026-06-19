"""
analyzer.py — LLM Incident Analyzer with OWASP Agentic Skills Top 10
Layer 3: DNN AI Analysis — uses Groq LLaMA 3.3 70B

OWASP Agentic Skills Top 10 Integration:
  → Severity Classification (CRITICAL/HIGH/MEDIUM/LOW)
  → Incident Type Mapping to OWASP Scenarios
  → Detection Indicators
  → Response Workflow Steps
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


# ─── OWASP Severity Classification ──────────────────────────────────────────

class OWASPSeverity:
    """OWASP Agentic Skills Top 10 Severity Levels"""
    CRITICAL = "CRITICAL"   # Active exploitation, mass deployment, data exfiltration
    HIGH = "HIGH"           # Confirmed malicious skill, widespread exposure
    MEDIUM = "MEDIUM"       # Suspicious behavior, potential vulnerability
    LOW = "LOW"             # Minor finding, no immediate risk


# ─── OWASP Incident Types ──────────────────────────────────────────────────

OWASP_INCIDENT_TYPES = {
    "MALICIOUS_SKILL": {
        "id": "OWASP-AS-01",
        "name": "Malicious Skill Discovery",
        "description": "A malicious skill has been discovered in a registry.",
        "severity": OWASPSeverity.HIGH,
        "detection_indicators": [
            "Automated scanner flags on installation",
            "User reports suspicious behavior",
            "Manual security review finds issues",
            "Threat intelligence indicates compromise",
            "Unusual network activity detected"
        ]
    },
    "DATA_BREACH": {
        "id": "OWASP-AS-02",
        "name": "Data Breach via Skill",
        "description": "A skill has been used to exfiltrate sensitive user data.",
        "severity": OWASPSeverity.CRITICAL,
        "detection_indicators": [
            "Large outbound data transfers",
            "Unusual API calls to external domains",
            "Credential harvesting code detected",
            "Command injection patterns found"
        ]
    },
    "SUPPLY_CHAIN_ATTACK": {
        "id": "OWASP-AS-03",
        "name": "Supply Chain Attack Detection",
        "description": "Compromised dependencies could propagate malware.",
        "severity": OWASPSeverity.HIGH,
        "detection_indicators": [
            "Dependency integrity check fails",
            "Known vulnerabilities in dependencies",
            "Behavioral changes after update"
        ]
    },
    "SKILL_ABUSE": {
        "id": "OWASP-AS-04",
        "name": "Skill Abuse / Misuse",
        "description": "Legitimate skill being used maliciously.",
        "severity": OWASPSeverity.MEDIUM,
        "detection_indicators": [
            "Unusual access patterns",
            "Policy violations detected",
            "Excessive privilege usage"
        ]
    },
    "CONFIGURATION_DRIFT": {
        "id": "OWASP-AS-05",
        "name": "Configuration Drift",
        "description": "Skill configuration deviates from secure baseline.",
        "severity": OWASPSeverity.LOW,
        "detection_indicators": [
            "Configuration audit fails",
            "Security baseline violation",
            "Documentation discrepancy"
        ]
    },
    "CREDENTIAL_THEFT": {
        "id": "OWASP-AS-06",
        "name": "Credential Theft via Skill",
        "description": "Skill harvested user credentials.",
        "severity": OWASPSeverity.CRITICAL,
        "detection_indicators": [
            "Credential access attempts",
            "API key rotation triggers",
            "Unusual authentication patterns"
        ]
    }
}


# ─── OWASP Response Workflow ────────────────────────────────────────────────

OWASP_RESPONSE_WORKFLOW = {
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
You are a senior cybersecurity analyst AI specializing in AI agent skill security.
Analyze the given incident using the OWASP Agentic Skills Top 10 framework.

Respond ONLY with a valid JSON object — no markdown, no extra text.

JSON structure (all fields required):
{
  "owasp_incident_type": "MALICIOUS_SKILL|DATA_BREACH|SUPPLY_CHAIN_ATTACK|SKILL_ABUSE|CONFIGURATION_DRIFT|CREDENTIAL_THEFT",
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
- Threat Score: {dnn.get("threat_score", 0.0)} (0.0 = safe, 1.0 = critical)
- Probabilities: Normal={dnn.get("probabilities", {}).get("Normal", 0)}, \
Suspicious={dnn.get("probabilities", {}).get("Suspicious", 0)}, \
Malicious={dnn.get("probabilities", {}).get("Malicious", 0)}

Provide your OWASP-aligned cybersecurity analysis as JSON only."""


# ─── Main Analysis Function ──────────────────────────────────────────────────

def analyze_incident(incident: dict, dnn_result: dict) -> dict:
    """
    Analyze a network incident using OWASP Agentic Skills Top 10 framework.

    Args:
        incident:   dict from detector.py or pcap pipeline
        dnn_result: dict from dnn_model.predict()

    Returns:
        OWASP-aligned analysis with severity, indicators, IOC's, and workflow
    """
    api_key = os.getenv("GROQ_API_KEY", "").strip()

    if api_key:
        try:
            result = _call_groq(api_key, incident, dnn_result)
            result["source"] = "groq"
            result["owasp_version"] = "Agentic Skills Top 10"
            print(f"[LLM] ✅ OWASP analysis: {result.get('owasp_incident_type')} — {result.get('severity')}")
            return result
        except Exception as e:
            print(f"[LLM] ⚠️ Groq error: {e} — using OWASP fallback")

    # ── OWASP Rule-based fallback ──────────────────────────────────────────
    result = _owasp_fallback_analysis(incident, dnn_result)
    result["source"] = "fallback"
    result["owasp_version"] = "Agentic Skills Top 10"
    print(f"[LLM] ℹ️ OWASP fallback: {result.get('owasp_incident_type')} — {result.get('severity')}")
    return result


# ─── Groq Call ───────────────────────────────────────────────────────────────

def _call_groq(api_key: str, incident: dict, dnn: dict) -> dict:
    """Call Groq API and parse JSON response"""
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

    # Strip markdown fences if present
    if raw_text.startswith("```"):
        raw_text = raw_text.split("```")[1]
        if raw_text.startswith("json"):
            raw_text = raw_text[4:]

    return json.loads(raw_text)


# ─── OWASP Rule-based Fallback ─────────────────────────────────────────────

_OWASP_FALLBACK_LIBRARY = {
    "DDoS Attack Suspected": {
        "owasp_incident_type": "SKILL_ABUSE",
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
        "owasp_incident_type": "SKILL_ABUSE",
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
        "owasp_incident_type": "CREDENTIAL_THEFT",
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
        "owasp_incident_type": "MALICIOUS_SKILL",
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
        "owasp_incident_type": "MALICIOUS_SKILL",
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
        "owasp_incident_type": "DATA_BREACH",
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
        "owasp_incident_type": "CREDENTIAL_THEFT",
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
    }
}


# ─── OWASP Fallback Analysis ──────────────────────────────────────────────

def _owasp_fallback_analysis(incident: dict, dnn: dict) -> dict:
    """
    OWASP-aligned rule-based analysis used when Groq is unavailable.
    """
    inc_type = incident.get("type", "")
    dnn_label = dnn.get("label", "Unknown")
    dnn_score = dnn.get("threat_score", 0.0)

    # Try exact match on incident type first
    template = _OWASP_FALLBACK_LIBRARY.get(inc_type)

    # Map DNN label to OWASP severity
    severity_map = {
        "Malicious": "CRITICAL",
        "Suspicious": "HIGH",
        "Normal": "LOW"
    }
    default_severity = severity_map.get(dnn_label, "MEDIUM")

    if template is None:
        # Create a basic OWASP template
        owasp_type = "SKILL_ABUSE"
        if dnn_label == "Malicious":
            owasp_type = "MALICIOUS_SKILL"
        elif dnn_label == "Suspicious":
            owasp_type = "SKILL_ABUSE"

        return {
            "owasp_incident_type": owasp_type,
            "severity": default_severity,
            "detection_indicators": [
                "Automated scanner flagged unusual activity",
                "DNN classification: " + dnn_label,
                f"Threat score: {dnn_score:.2f}"
            ],
            "explanation": f"A {default_severity.lower()} security event has been detected. The DNN classified this as '{dnn_label}' with a threat score of {dnn_score:.2f}.",
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
                "analyze": "Incident analyzed using OWASP framework",
                "contain": "Incident logged for investigation",
                "investigate": "Logs reviewed for context",
                "remediate": "Security improvements identified",
                "communicate": "Stakeholders notified"
            }
        }

    return {
        "owasp_incident_type": template.get("owasp_incident_type", "SKILL_ABUSE"),
        "severity": template.get("severity", default_severity),
        "detection_indicators": template.get("detection_indicators", []),
        "explanation": template.get("explanation", "No explanation available."),
        "root_cause": template.get("root_cause", "Unknown"),
        "iocs": template.get("iocs", []),
        "remediation_steps": template.get("remediation_steps", []),
        "prevention_tips": template.get("prevention_tips", []),
        "response_workflow": template.get("response_workflow", {})
    }