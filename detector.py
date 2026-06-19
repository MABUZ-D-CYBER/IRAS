"""
detector.py — Simulated Incident Detection with OWASP Mapping
Layer 1: Input Layer

OWASP Agentic Skills Top 10 Integration:
  → Incident types mapped to OWASP-AS-01 to OWASP-AS-06
  → Detection indicators included
  → Severity aligned with OWASP classification
"""

import random
from datetime import datetime

# ── OWASP-Aligned Incident Library ──────────────────────────────────────────

INCIDENT_TYPES = [
    # OWASP-AS-01: Malicious Skill Discovery
    {"type": "Malware Download Detected", "owasp_type": "MALICIOUS_SKILL", "severity": "CRITICAL", "base_score": 0.95},
    {"type": "Suspicious File Execution", "owasp_type": "MALICIOUS_SKILL", "severity": "HIGH", "base_score": 0.78},

    # OWASP-AS-02: Data Breach via Skill
    {"type": "Data Exfiltration Suspected", "owasp_type": "DATA_BREACH", "severity": "CRITICAL", "base_score": 0.92},
    {"type": "DNS Tunneling Detected", "owasp_type": "DATA_BREACH", "severity": "HIGH", "base_score": 0.75},

    # OWASP-AS-03: Supply Chain Attack
    {"type": "Dependency Integrity Check Failed", "owasp_type": "SUPPLY_CHAIN_ATTACK", "severity": "HIGH", "base_score": 0.80},
    {"type": "Suspicious Dependency Update", "owasp_type": "SUPPLY_CHAIN_ATTACK", "severity": "MEDIUM", "base_score": 0.55},

    # OWASP-AS-04: Skill Abuse/Misuse
    {"type": "DDoS Attack Suspected", "owasp_type": "SKILL_ABUSE", "severity": "CRITICAL", "base_score": 0.90},
    {"type": "SQL Injection Attempt", "owasp_type": "SKILL_ABUSE", "severity": "CRITICAL", "base_score": 0.91},
    {"type": "Unauthorized Access Attempt", "owasp_type": "SKILL_ABUSE", "severity": "HIGH", "base_score": 0.78},
    {"type": "Port Scan Detected", "owasp_type": "SKILL_ABUSE", "severity": "HIGH", "base_score": 0.75},

    # OWASP-AS-05: Configuration Drift
    {"type": "CPU Usage Spike", "owasp_type": "CONFIGURATION_DRIFT", "severity": "LOW", "base_score": 0.20},
    {"type": "Disk Space Critical", "owasp_type": "CONFIGURATION_DRIFT", "severity": "LOW", "base_score": 0.22},

    # OWASP-AS-06: Credential Theft
    {"type": "Brute Force Login Attempt", "owasp_type": "CREDENTIAL_THEFT", "severity": "HIGH", "base_score": 0.80},
    {"type": "Ransomware Activity Detected", "owasp_type": "CREDENTIAL_THEFT", "severity": "CRITICAL", "base_score": 0.97},
    {"type": "Suspicious Outbound Traffic", "owasp_type": "CREDENTIAL_THEFT", "severity": "MEDIUM", "base_score": 0.50},
    {"type": "Failed Authentication Spike", "owasp_type": "CREDENTIAL_THEFT", "severity": "MEDIUM", "base_score": 0.55},
    {"type": "ARP Spoofing Detected", "owasp_type": "CREDENTIAL_THEFT", "severity": "MEDIUM", "base_score": 0.60},
    {"type": "Unusual Login Time", "owasp_type": "CREDENTIAL_THEFT", "severity": "LOW", "base_score": 0.25},
]

DEST_IPS = [
    "192.168.1.10", "192.168.1.20", "192.168.1.100",
    "10.0.0.5", "10.0.0.50", "172.16.0.1"
]


def detect_simulated_incident() -> dict:
    """Simulate incident detection with OWASP mapping."""
    template = random.choice(INCIDENT_TYPES)
    variation = random.uniform(-0.05, 0.05)
    threat_score = round(max(0.0, min(1.0, template["base_score"] + variation)), 3)

    src_ip = (
        f"{random.randint(1, 223)}."
        f"{random.randint(0, 255)}."
        f"{random.randint(0, 255)}."
        f"{random.randint(1, 254)}"
    )

    attack_ports = {
        "DDoS Attack Suspected": [80, 443],
        "SQL Injection Attempt": [3306, 5432, 1433],
        "Malware Download Detected": [80, 443, 8080],
        "Brute Force Login Attempt": [22, 3389, 21],
        "Port Scan Detected": [0],
        "Unauthorized Access Attempt": [22, 3389],
        "DNS Tunneling Detected": [53],
        "Data Exfiltration Suspected": [443, 8443],
        "Ransomware Activity Detected": [445, 3389, 22],
        "Suspicious Outbound Traffic": [80, 443, 53],
        "Failed Authentication Spike": [22, 3389, 21, 389],
        "ARP Spoofing Detected": [0],
        "Unusual Login Time": [22, 3389],
        "CPU Usage Spike": [0],
        "Disk Space Critical": [0],
        "Dependency Integrity Check Failed": [443, 80],
        "Suspicious Dependency Update": [443, 80],
        "Suspicious File Execution": [22, 3389, 445],
    }
    ports = attack_ports.get(template["type"], [80, 443, 22, 53])
    chosen_port = random.choice(ports) if ports != [0] else random.randint(1, 65535)

    packet_ranges = {
        "CRITICAL": (5000, 100000),
        "HIGH": (500, 10000),
        "MEDIUM": (50, 1000),
        "LOW": (1, 50),
    }
    pkt_min, pkt_max = packet_ranges[template["severity"]]

    return {
        "type": template["type"],
        "owasp_type": template["owasp_type"],
        "severity": template["severity"],
        "source_ip": src_ip,
        "dest_ip": random.choice(DEST_IPS),
        "port": chosen_port,
        "packet_count": random.randint(pkt_min, pkt_max),
        "threat_score": threat_score,
        "timestamp": datetime.now().isoformat(),
        "simulated": True,
    }