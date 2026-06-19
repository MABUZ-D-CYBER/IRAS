# 🛡️ Incident Response Automation System 

An AI-powered network incident detection and response system that captures real network packets, classifies threats using a Deep Neural Network, generates remediation guidance via LLM, sends automated email alerts, and produces detailed HTML incident reports.

---

## 📚 Table of Contents

- [What's New in v2.0](#-whats-new-in-v20)
- [System Architecture](#-system-architecture)
- [Project Structure](#-project-structure)
- [New Components Explained](#-new-components-explained)
- [Configuration](#-configuration)
- [Installation](#-installation)
- [Data Flow](#-data-flow)
- [Implementation Phases](#-implementation-phases)
- [Tools Inspiration](#-tools-inspiration-mapping)
- [Sample Outputs](#-sample-outputs)
- [Tech Stack](#-tech-stack)
- [Author](#-author)

---

## 🔄 What's New in v2.0

| Feature | v1.0 (Existing) | v2.0 (Updated) |
|---|---|---|
| Input Source | Simulated incidents | ✅ Real PCAP packet capture (Npcap) |
| AI Method | LLM prompt analysis | ✅ DNN algorithm + LLM combined |
| AI Output | Text analysis | ✅ Analysis + Remedies/Suggestions |
| Alert System | Terminal print only | ✅ SMTP Email alerts to proprietor |
| Report | JSON log only | ✅ Detailed HTML incident report |
| Dashboard | Basic web UI | ✅ Enhanced dashboard with all layers |

---

## 🏗️ System Architecture

```
╔══════════════════════════════════════════════════════════════════════╗
║           INCIDENT RESPONSE AUTOMATION SYSTEM v2.0                   ║
║     Inspired by Darktrace | Cortex XDR | Npcap                       ║
╠══════════════════════════════════════════════════════════════════════╣
║                                                                        ║
║  ┌─────────────────────────────────────────────────────────────────┐  ║
║  │  LAYER 1 — INPUT LAYER                                          │  ║
║  │  [Live Network]──►[Npcap Packet Capture]──►[PCAP Files]        │  ║
║  │  [Simulated Incidents]──────────────────►[detector.py]         │  ║
║  │                          ▼                                       │  ║
║  │              [pcap_reader.py] — parses packet data               │  ║
║  └──────────────────────────┬────────────────────────────────────-─┘  ║
║                             │ Raw Packet Features                      ║
║                             ▼                                          ║
║  ┌─────────────────────────────────────────────────────────────────┐  ║
║  │  LAYER 2 — PACKET CAPTURE LAYER                                 │  ║
║  │  Protocol │ Src IP │ Dst IP │ Port │ Payload Size               │  ║
║  │  Flags    │ TTL    │ Freq   │ Timing│ Anomaly Score             │  ║
║  │                          ▼                                       │  ║
║  │         [feature_extractor.py] — builds feature vectors          │  ║
║  └──────────────────────────┬────────────────────────────────────-─┘  ║
║                             │ Feature Vectors                          ║
║                             ▼                                          ║
║  ┌─────────────────────────────────────────────────────────────────┐  ║
║  │  LAYER 3 — DNN AI ANALYSIS LAYER                                │  ║
║  │  ┌────────────────────────────────────────────────────────┐    │  ║
║  │  │  Deep Neural Network (DNN)                             │    │  ║
║  │  │  Input Layer → Hidden Layers → Output Layer            │    │  ║
║  │  │  Classifies: Normal / Suspicious / Malicious           │    │  ║
║  │  │  Scores:     0.0 (safe) → 1.0 (critical threat)       │    │  ║
║  │  └────────────────────────────────────────────────────────┘    │  ║
║  │                          ▼                                       │  ║
║  │  ┌────────────────────────────────────────────────────────┐    │  ║
║  │  │  LLM Analysis (Groq — LLaMA 3.3 70B)  [analyzer.py]  │    │  ║
║  │  │  → Severity Classification                             │    │  ║
║  │  │  → Root Cause Explanation                              │    │  ║
║  │  │  → 3-Step Remediation Guide  ← NEW                    │    │  ║
║  │  │  → Preventive Suggestions    ← NEW                    │    │  ║
║  │  └────────────────────────────────────────────────────────┘    │  ║
║  └──────────────────────────┬────────────────────────────────────-─┘  ║
║                             │ Analysis + Remedies                      ║
║                             ▼                                          ║
║  ┌─────────────────────────────────────────────────────────────────┐  ║
║  │  LAYER 4 — ALERT LAYER  ← NEW                                  │  ║
║  │  CRITICAL / HIGH ──►[SMTP Email Alert]──►[Proprietor Inbox]    │  ║
║  │  MEDIUM           ──►[Dashboard Notification]                  │  ║
║  │  LOW              ──►[Log Only]                                 │  ║
║  └──────────────────────────┬────────────────────────────────────-─┘  ║
║                             ▼                                          ║
║  ┌─────────────────────────────────────────────────────────────────┐  ║
║  │  LAYER 5 — RESPONSE & LOGGING LAYER  (Enhanced)                 │  ║
║  │  responder.py — Terminal print + JSON log + Incident ID         │  ║
║  └──────────────────────────┬────────────────────────────────────-─┘  ║
║                             ▼                                          ║
║  ┌─────────────────────────────────────────────────────────────────┐  ║
║  │  LAYER 6 — REPORT GENERATION LAYER  ← NEW                      │  ║
║  │  report_generator.py — HTML report: Summary + Timeline +        │  ║
║  │  Charts + Remedies │ Saved as: report_YYYY-MM-DD.html           │  ║
║  └──────────────────────────┬────────────────────────────────────-─┘  ║
║                             ▼                                          ║
║  ┌─────────────────────────────────────────────────────────────────┐  ║
║  │  LAYER 7 — WEB DASHBOARD  (Enhanced)                            │  ║
║  │  app.py + dashboard.html                                        │  ║
║  │  • Real-time incident table    • Severity stats cards           │  ║
║  │  • Download Report button ← NEW  • Email Alert Status ← NEW    │  ║
║  └─────────────────────────────────────────────────────────────────┘  ║
╚══════════════════════════════════════════════════════════════════════╝
```

---

## 📁 Project Structure

```
incident-response-automation/
│
├── .env                        ← API keys + Email config (secret)
├── .gitignore                  ← Protects secrets
│
├── ── INPUT & CAPTURE LAYER ──
├── detector.py                 ← EXISTING: Simulated incident detection
├── pcap_reader.py              ← NEW: Reads .pcap files via Npcap/Scapy
├── feature_extractor.py        ← NEW: Extracts network features from packets
│
├── ── AI ANALYSIS LAYER ──
├── dnn_model.py                ← NEW: Deep Neural Network classifier
├── analyzer.py                 ← EXISTING (enhanced): LLM analysis + remedies
│
├── ── ALERT LAYER ──
├── alert_system.py             ← NEW: SMTP email alerts to proprietor
│
├── ── RESPONSE & LOGGING ──
├── responder.py                ← EXISTING (enhanced): Log + respond
├── incidents_log.json          ← EXISTING: Persistent storage
│
├── ── REPORT GENERATION ──
├── report_generator.py         ← NEW: HTML detailed report generator
├── reports/                    ← NEW: Folder for generated reports
│   └── report_2026-06-17.html
│
├── ── WEB DASHBOARD ──
├── app.py                      ← EXISTING (enhanced): Flask dashboard
├── main.py                     ← EXISTING (enhanced): Entry point
│
└── templates/
    └── dashboard.html          ← EXISTING (enhanced): Web UI
```

---

## 🔧 New Components Explained

### 1. `pcap_reader.py` — Packet Capture Layer

Reads real network traffic from `.pcap` files captured by Npcap using the `scapy` Python library.

```
Npcap (captures traffic) → saves .pcap file → pcap_reader.py reads it
```

**Output:** List of packet dictionaries containing IP, port, and protocol info.

---

### 2. `feature_extractor.py` — Feature Engineering

Converts raw packet data into numerical vectors the DNN can process.

**Features extracted:**
- Packet count per second
- Unique IP addresses seen
- Port scanning detection
- Unusual protocol flags
- Payload size anomalies

---

### 3. `dnn_model.py` — Deep Neural Network

Classifies network traffic as `Normal / Suspicious / Malicious` using a neural network, similar to how Darktrace learns patterns of normal behaviour and flags deviations.

```
Features In → DNN → Threat Score (0.0 to 1.0) + Classification Out
```

**Library:** `scikit-learn` or `tensorflow`

---

### 4. `alert_system.py` — Email Alert System

Sends automatic SMTP email to the proprietor when a `CRITICAL` or `HIGH` severity incident is detected.

```
Incident Detected → Severity Check → If CRITICAL/HIGH → Send Email
```

**Library:** Python built-in `smtplib`

---

### 5. `report_generator.py` — Detailed HTML Report

Generates a professional HTML incident report inspired by Cortex XDR investigation reports.

**Report contents:**
- Executive Summary
- Incident Timeline
- Severity Breakdown
- Per-incident AI Analysis + Remedies
- Recommended Actions

---

## ⚙️ Configuration

Copy `.env.example` to `.env` and fill in your credentials:

```env
# Existing
GROQ_API_KEY=your-groq-key-here

# Email Alert Config (New)
SMTP_EMAIL=your-email@gmail.com
SMTP_PASSWORD=your-app-password-here
PROPRIETOR_EMAIL=owner@example.com
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587

# Alert Threshold (New)
ALERT_THRESHOLD=high
```

> ⚠️ **Never commit `.env` to version control.** It is listed in `.gitignore`.

---

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/your-username/incident-response-automation.git
cd incident-response-automation

# Install dependencies
pip install groq python-dotenv flask   # Existing
pip install scapy                       # PCAP packet reading
pip install scikit-learn                # DNN / ML model
pip install numpy pandas                # Numerical & data processing
pip install reportlab                   # PDF report generation (optional)
pip install secure-smtplib              # Secure email sending
```

> **Note:** Npcap must also be installed separately on Windows from [npcap.com](https://npcap.com) to enable live packet capture.

---

## 🔄 Data Flow

```
STEP 1: INPUT
   (A) Npcap captures live network packets → saves as .pcap file
   (B) Simulated incidents from detector.py
          │
          ▼
STEP 2: PACKET PROCESSING
   pcap_reader.py reads the .pcap file
   feature_extractor.py converts packets → feature vectors
          │
          ▼
STEP 3: DNN ANALYSIS
   dnn_model.py classifies: Normal / Suspicious / Malicious
   Returns: threat_score (0.0–1.0) + classification label
          │
          ▼
STEP 4: LLM ANALYSIS  (Enhanced)
   analyzer.py → Groq LLaMA 3.3 70B
   Returns: severity + explanation + 3 remediation steps + prevention tips
          │
          ▼
STEP 5: ALERT CHECK
   alert_system.py checks severity
   CRITICAL / HIGH → sends email to proprietor via SMTP
          │
          ▼
STEP 6: LOGGING
   responder.py saves full incident to incidents_log.json
   Includes: DNN score + LLM analysis + remedies + alert status
          │
          ▼
STEP 7: REPORT GENERATION
   report_generator.py creates detailed HTML report
   Saved to: reports/report_YYYY-MM-DD.html
          │
          ▼
STEP 8: DASHBOARD
   app.py serves updated dashboard
   Shows: all incidents + stats + email alert status + download report button
```

---

## 📊 Implementation Phases

### ✅ Phase 1 — Complete (v1.0)

- [x] Simulated incident detection
- [x] LLM analysis via Groq
- [x] Terminal response output
- [x] JSON incident logging
- [x] Basic Flask web dashboard

### 🔜 Phase 2 — In Progress (v2.0)

| Step | Task | File | Priority |
|---|---|---|---|
| 1 | Install Npcap + Scapy | `pcap_reader.py` | High |
| 2 | Build feature extractor | `feature_extractor.py` | High |
| 3 | Build DNN classifier | `dnn_model.py` | High |
| 4 | Enhance analyzer with remedies | `analyzer.py` | High |
| 5 | Build SMTP email alerts | `alert_system.py` | High |
| 6 | Build report generator | `report_generator.py` | Medium |
| 7 | Enhance dashboard | `dashboard.html` | Medium |

### 🔮 Phase 3 — Future

- Real-time continuous packet monitoring
- ML model training on real-world datasets
- Multi-recipient email notification list
- Mobile push notifications
- Integration with real SIEM tools

---

## 🛠️ Tools Inspiration Mapping

| Our Implementation | Inspired By | How It's Similar |
|---|---|---|
| `pcap_reader.py` + Npcap | **Npcap** (npcap.com) | Captures real network packets at OS level |
| `dnn_model.py` | **Darktrace** Self-Learning AI | DNN learns normal vs. anomalous patterns |
| `analyzer.py` + remedies | **Cortex XDR** (cortex.io) | AI provides root cause + remediation playbook |
| `alert_system.py` SMTP | Industry standard | Immediate notification like SOC alert systems |
| `report_generator.py` | **Cortex XDR** investigation reports | Detailed per-incident analysis reports |

---

## 🎯 Layer Summary

| Layer | Name | Status | Key File(s) |
|---|---|---|---|
| Layer 1 | Input Layer | ✅ Existing + 🆕 PCAP | `detector.py`, `pcap_reader.py` |
| Layer 2 | Packet Capture | 🆕 New | `feature_extractor.py`, Npcap |
| Layer 3 | DNN AI Analysis | 🆕 New | `dnn_model.py`, `analyzer.py` |
| Layer 4 | Alert System | 🆕 New | `alert_system.py` (SMTP) |
| Layer 5 | Response & Logging | ✅ Existing | `responder.py` |
| Layer 6 | Report Generation | 🆕 New | `report_generator.py` |
| Layer 7 | Web Dashboard | ✅ Existing + Enhanced | `app.py`, `dashboard.html` |

---

## 📋 Sample Outputs

<details>
<summary>📧 Email Alert Sample</summary>

```
Subject: 🚨 CRITICAL INCIDENT DETECTED — DDoS Attack Suspected

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🛡️ INCIDENT RESPONSE AUTOMATION SYSTEM
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

⚠️  SEVERITY   : CRITICAL
📋  TYPE       : DDoS Attack Suspected
📅  TIMESTAMP  : 2026-06-17 09:34:22
🤖  DNN SCORE  : 0.94 (Malicious)
🔢  INCIDENT ID: #7

📝 WHAT IS HAPPENING:
Unusual traffic spike of 10,000 requests/second detected.
Likely a distributed denial-of-service attack targeting
the main web server.

🔧 IMMEDIATE REMEDIATION STEPS:
1. Enable rate limiting on the firewall immediately
2. Block the top source IPs identified in traffic logs
3. Contact ISP to activate DDoS mitigation service

🛡️ PREVENTION TIPS:
• Deploy a CDN with built-in DDoS protection (Cloudflare)
• Set up automatic IP blacklisting rules
• Enable traffic anomaly alerts on your router

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Full report available at: http://127.0.0.1:5000
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

</details>

<details>
<summary>📄 HTML Report Structure</summary>

```
INCIDENT RESPONSE AUTOMATION REPORT
Date: 2026-06-17 | Total Incidents: 12

━━━━━━━━━━━━━━━━━━━━━━━━━━━
EXECUTIVE SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━
Total Incidents    : 12
Critical           : 3
High               : 5
Medium             : 4
Email Alerts Sent  : 8
Avg DNN Score      : 0.72

━━━━━━━━━━━━━━━━━━━━━━━━━━━
INCIDENT TIMELINE
━━━━━━━━━━━━━━━━━━━━━━━━━━━
09:12 — [CRITICAL] DDoS Attack Suspected     (Score: 0.94)
09:23 — [HIGH]     Unauthorized Login         (Score: 0.81)
09:45 — [MEDIUM]   Disk Space Low             (Score: 0.45)

━━━━━━━━━━━━━━━━━━━━━━━━━━━
DETAILED INCIDENT ANALYSIS
━━━━━━━━━━━━━━━━━━━━━━━━━━━
Incident #7 | DDoS Attack Suspected | CRITICAL
DNN Classification : Malicious (0.94)
AI Analysis        : [Full Groq LLM analysis]
Remediation Steps  : [3 steps]
Prevention Tips    : [Suggestions]
Email Alert        : SENT ✅
```

</details>

---

## 💻 Tech Stack

| Component | Technology |
|---|---|
| Language | Python 3.8+ |
| Web Framework | Flask |
| LLM Provider | Groq (LLaMA 3.3 70B) |
| Packet Capture | Npcap + Scapy |
| ML / DNN | scikit-learn / TensorFlow |
| Data Processing | NumPy, Pandas |
| Email | Python `smtplib` (SMTP) |
| Report Output | HTML / ReportLab (PDF) |

---

## 👤 Author

*Architecture v2.0 — Inspired by Darktrace, Cortex XDR, and Npcap*
