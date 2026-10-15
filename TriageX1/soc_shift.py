#!/usr/bin/env python3
import os
import re
import math
import json
import uuid
import ipaddress
import base64
import hashlib
import urllib.parse
import email
from email import policy
from collections import Counter
from datetime import datetime, timezone
import requests
from dotenv import load_dotenv

load_dotenv()

HISTORY_FILE = "shift_history.json"

EVENT_IDS = {
    "4624": ("Successful Logon", "Check Logon Type (Type 3 = Network/SMB, Type 10 = RDP, Type 2 = Interactive)."),
    "4625": ("Failed Logon", "Multiple hits indicate Brute Force or Password Spraying. Check Source IP."),
    "4648": ("Logon with Explicit Credentials", "User ran 'RunAs' or moved laterally using alternate credentials."),
    "4672": ("Special Privileges Assigned", "Admin-level privileges assigned to a new session."),
    "4688": ("Process Creation", "Inspect CommandLine, ParentProcessName, and User context."),
    "4697": ("Service Installed", "New service installed on the system (Persistence / Privilege Escalation)."),
    "4698": ("Scheduled Task Created", "Check task command/script path (Persistence)."),
    "4720": ("User Account Created", "Verify who created the account and if a change ticket exists."),
    "4726": ("User Account Deleted", "Account removed. Check if attacker is covering tracks."),
    "4732": ("Member Added to Local Group", "High priority if added to 'Administrators' or 'Remote Desktop Users'."),
    "4740": ("Account Locked Out", "Triggered by repeated bad passwords. Check CallerComputerName."),
    "1102": ("Audit Log Cleared", "CRITICAL: Security event log was wiped (Defense Evasion)."),
    "7045": ("New Service Installed (System)", "Check Service File Name for suspicious binaries or PowerShell."),
    "1": ("Sysmon: Process Creation", "Includes file hashes and full CommandLine/ParentCommandLine."),
    "3": ("Sysmon: Network Connection", "Outbound/Inbound connection mapped to a specific Process and Port."),
    "11": ("Sysmon: FileCreate", "File created or dropped on disk (Malware droppers/downloads)."),
    "22": ("Sysmon: DNS Query", "Process performed a DNS lookup. Check domain for C2 activity.")
}

MITRE_RULES = [
    {"id": "T1059.001", "tactic": "Execution", "name": "Command & Scripting: PowerShell", "pattern": r"powershell|pwsh|-enc|-w\s+hidden|downloadstring|downloadfile|iex\b"},
    {"id": "T1059.003", "tactic": "Execution", "name": "Windows Command Shell (cmd.exe)", "pattern": r"cmd\.exe|/c\s+|whoami|net\s+user"},
    {"id": "T1070.001", "tactic": "Defense Evasion", "name": "Clear Windows Event Logs", "pattern": r"\b1102\b|wevtutil\s+cl|clear-eventlog"},
    {"id": "T1027", "tactic": "Defense Evasion", "name": "Obfuscated Files or Information", "pattern": r"-enc\b|frombase64string|%[0-9a-fA-F]{2}"},
    {"id": "T1110", "tactic": "Credential Access", "name": "Brute Force / Password Spraying", "pattern": r"\b4625\b|\b4740\b|failed\s+login|authentication\s+failure"},
    {"id": "T1543.003", "tactic": "Persistence", "name": "Create or Modify Windows Service", "pattern": r"\b4697\b|\b7045\b|sc\.exe\s+create|new-service"},
    {"id": "T1053.005", "tactic": "Persistence", "name": "Scheduled Task / Job", "pattern": r"\b4698\b|schtasks"},
    {"id": "T1136.001", "tactic": "Persistence", "name": "Create Account: Local Account", "pattern": r"\b4720\b|net\s+user\s+.*\s+/add"},
    {"id": "T1078", "tactic": "Privilege Escalation", "name": "Valid Accounts / Group Modification", "pattern": r"\b4732\b|\b4672\b|localgroup\s+administrators"},
    {"id": "T1190", "tactic": "Initial Access", "name": "Exploit Public-Facing Application (SQLi/XSS)", "pattern": r"union\s+select|or\s+1=1|<script>|/etc/passwd|\.\./\.\./"},
    {"id": "T1071.001", "tactic": "Command and Control", "name": "Application Layer Protocol: Web Traffic", "pattern": r"https?://[^\s\"'<>]+"}
]

def get_api_keys():
    load_dotenv(override=True)
    return {
        "vt": os.getenv("VT_API_KEY", "").strip(),
        "abuse": os.getenv("ABUSE_API_KEY", "").strip(),
        "gemini": os.getenv("GEMINI_API_KEY", "").strip(),
        "webhook": os.getenv("DISCORD_WEBHOOK_URL", "").strip()
    }

def defang(text: str) -> str:
    text = re.sub(r"http", "hxxp", text, flags=re.IGNORECASE)
    return text.replace(".", "[.]")

def load_history() -> list:
    if not os.path.exists(HISTORY_FILE):
        return []
    try:
        with open(HISTORY_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []

def save_to_history(entry: dict):
    history = load_history()
    history.insert(0, entry)
    with open(HISTORY_FILE, "w", encoding="utf-8") as f:
        json.dump(history[:100], f, indent=2)

def clear_history():
    if os.path.exists(HISTORY_FILE):
        os.remove(HISTORY_FILE)

def try_decode_payloads(raw_text: str):
    decoded_findings = []
    if "%" in raw_text:
        unquoted = urllib.parse.unquote(raw_text)
        if unquoted != raw_text:
            decoded_findings.append({"type": "URL Decoded", "value": unquoted.strip()})

    b64_matches = re.findall(r'(?:[A-Za-z0-9+/]{4}){5,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?', raw_text)
    for match in set(b64_matches):
        try:
            raw_bytes = base64.b64decode(match)
            if b"\x00" in raw_bytes:
                decoded_str = raw_bytes.decode("utf-16le", errors="ignore").strip()
                if len(decoded_str) > 4 and decoded_str.isprintable():
                    decoded_findings.append({"type": "PowerShell Base64 (UTF-16LE)", "value": decoded_str})
            else:
                decoded_str = raw_bytes.decode("utf-8", errors="ignore").strip()
                if len(decoded_str) > 4 and decoded_str.isprintable():
                    decoded_findings.append({"type": "Base64 (UTF-8)", "value": decoded_str})
        except Exception:
            pass
    return decoded_findings

def map_mitre_attack(text: str) -> list:
    matched = []
    seen = set()
    for rule in MITRE_RULES:
        if re.search(rule["pattern"], text, re.IGNORECASE):
            if rule["id"] not in seen:
                seen.add(rule["id"])
                matched.append({
                    "id": rule["id"],
                    "tactic": rule["tactic"],
                    "name": rule["name"],
                    "url": f"https://attack.mitre.org/techniques/{rule['id'].replace('.', '/')}/"
                })
    return matched

def enrich_ip(ip: str) -> dict:
    keys = get_api_keys()
    vt_key, abuse_key = keys["vt"], keys["abuse"]

    country, isp = "Unknown", "Unknown"
    abuse_score_num = 0
    abuse_score_str = "No Key"
    vt_mal_num = 0
    vt_detections = "No Key"
    verdict = "CLEAN"

    try:
        geo = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,city,isp,hosting,proxy", timeout=5).json()
        if geo.get("status") == "success":
            country = f"{geo.get('country')} ({geo.get('city')})"
            isp = geo.get("isp", "Unknown")
            if geo.get("proxy") or geo.get("hosting"):
                verdict = "SUSPICIOUS"
    except Exception:
        pass

    if abuse_key:
        try:
            headers = {"Key": abuse_key, "Accept": "application/json"}
            res = requests.get("https://api.abuseipdb.com/api/v2/check", headers=headers, params={"ipAddress": ip, "maxAgeInDays": "90"}, timeout=6)
            if res.status_code == 200:
                data = res.json().get("data", {})
                abuse_score_num = data.get("abuseConfidenceScore", 0)
                reports = data.get("totalReports", 0)
                abuse_score_str = f"{abuse_score_num}% ({reports} reports)"
                if data.get("isp"):
                    isp = data.get("isp")
                if abuse_score_num >= 50:
                    verdict = "CRITICAL"
                elif abuse_score_num > 0 and verdict == "CLEAN":
                    verdict = "SUSPICIOUS"
        except Exception:
            abuse_score_str = "Timeout"

    if vt_key:
        try:
            headers = {"x-apikey": vt_key}
            res = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", headers=headers, timeout=6)
            if res.status_code == 200:
                stats = res.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                vt_mal_num = stats.get("malicious", 0)
                total = sum(stats.values()) if stats else 0
                vt_detections = f"{vt_mal_num}/{total} Malicious"
                if vt_mal_num >= 3:
                    verdict = "CRITICAL"
                elif vt_mal_num > 0 and verdict == "CLEAN":
                    verdict = "SUSPICIOUS"
        except Exception:
            vt_detections = "Timeout"

    return {
        "ip": ip,
        "defanged_ip": defang(ip),
        "location": country,
        "isp": isp,
        "abuse": abuse_score_str,
        "abuse_num": abuse_score_num,
        "vt": vt_detections,
        "vt_num": vt_mal_num,
        "verdict": verdict
    }

def check_vt_hash(file_hash: str) -> dict:
    vt_key = get_api_keys()["vt"]
    if not vt_key:
        return {"hash": file_hash, "vt": "No API Key", "vt_num": 0, "label": "N/A", "verdict": "UNVERIFIED"}

    try:
        headers = {"x-apikey": vt_key}
        res = requests.get(f"https://www.virustotal.com/api/v3/files/{file_hash}", headers=headers, timeout=6)
        if res.status_code == 200:
            attrs = res.json().get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            mal = stats.get("malicious", 0)
            total = sum(stats.values()) if stats else 0
            label = attrs.get("popular_threat_classification", {}).get("suggested_threat_label", "Generic/Malware")
            verdict = "CRITICAL" if mal >= 5 else ("SUSPICIOUS" if mal > 0 else "CLEAN")
            return {"hash": file_hash, "vt": f"{mal}/{total} Malicious", "vt_num": mal, "label": label, "verdict": verdict}
        elif res.status_code == 404:
            return {"hash": file_hash, "vt": "0 (Not Found in VT)", "vt_num": 0, "label": "Unknown File", "verdict": "UNKNOWN"}
    except Exception:
        pass
    return {"hash": file_hash, "vt": "API Error", "vt_num": 0, "label": "N/A", "verdict": "ERROR"}

def analyze_alert_data(raw_text: str) -> dict:
    decoded_items = try_decode_payloads(raw_text)
    combined_text = raw_text + "\n" + "\n".join([item["value"] for item in decoded_items])

    ip_candidates = set(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', combined_text))
    internal_ips, external_ips = [], []
    for ip in ip_candidates:
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_private or ip_obj.is_loopback:
                internal_ips.append(ip)
            else:
                external_ips.append(ip)
        except ValueError:
            pass

    sha256s = set(re.findall(r'\b[A-Fa-f0-9]{64}\b', combined_text))
    md5s = set(re.findall(r'\b[A-Fa-f0-9]{32}\b', combined_text))
    all_hashes = list(sha256s) + list(md5s)
    urls = [defang(u) for u in set(re.findall(r'https?://[^\s"\'<>)+]+', combined_text, re.IGNORECASE))]

    events = []
    event_matches = re.findall(r'(?:EventCode|EventID|Event ID|id)[\s:=]+(\d{1,4})\b', raw_text, re.IGNORECASE)
    for eid in set(event_matches):
        if eid in EVENT_IDS:
            events.append({"id": eid, "name": EVENT_IDS[eid][0], "desc": EVENT_IDS[eid][1]})

    mitre_matches = map_mitre_attack(combined_text)
    ip_intel = [enrich_ip(ip) for ip in external_ips]
    hash_intel = [check_vt_hash(h) for h in all_hashes]

    risk_score = 0
    if decoded_items:
        risk_score += 25
    risk_score += min(len(mitre_matches) * 10, 30)
    for ip_i in ip_intel:
        if ip_i["verdict"] == "CRITICAL":
            risk_score += 40
        elif ip_i["verdict"] == "SUSPICIOUS":
            risk_score += 20
    for h_i in hash_intel:
        if h_i["verdict"] == "CRITICAL":
            risk_score += 50
        elif h_i["verdict"] == "SUSPICIOUS":
            risk_score += 25
    if any(e["id"] == "1102" for e in events):
        risk_score += 35
    risk_score = min(risk_score, 100)

    if risk_score >= 70:
        overall_severity = "CRITICAL"
    elif risk_score >= 35:
        overall_severity = "SUSPICIOUS"
    else:
        overall_severity = "CLEAN / LOW"

    fw_commands = ["# --- AUTOMATED SOAR CONTAINMENT PLAYBOOK ---"]
    if external_ips:
        for ip in external_ips:
            fw_commands.append(f"# Block External IOC ({ip}) on Linux Perimeter / iptables:")
            fw_commands.append(f"sudo iptables -A INPUT -s {ip} -j DROP && sudo iptables -A OUTPUT -d {ip} -j DROP")
            fw_commands.append(f"# Block External IOC ({ip}) on Windows Firewall (PowerShell):")
            fw_commands.append(f"New-NetFirewallRule -DisplayName 'SOAR-Block-{ip}' -Direction Outbound -RemoteAddress {ip} -Action Block")
    else:
        fw_commands.append("# No external public IPs identified for perimeter firewall block.")

    if internal_ips:
        fw_commands.append(f"\n# Isolate Compromised Internal Host ({internal_ips[0]}) via Windows Defender / EDR:")
        fw_commands.append(f"Invoke-Command -ComputerName {internal_ips[0]} -ScriptBlock {{ Stop-Process -Name 'powershell' -Force -ErrorAction SilentlyContinue }}")

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    int_str = ", ".join(internal_ips) if internal_ips else "N/A"
    ext_str = " ; ".join([f"{i['defanged_ip']} ({i['location']} | Abuse: {i['abuse']} | VT: {i['vt']})" for i in ip_intel]) if ip_intel else "N/A"
    hash_str = " ; ".join([f"{h['hash']} (VT: {h['vt']} | {h['label']})" for h in hash_intel]) if hash_intel else "N/A"
    url_str = ", ".join(urls) if urls else "N/A"
    mitre_str = ", ".join([f"{m['id']} ({m['name']})" for m in mitre_matches]) if mitre_matches else "None mapped"
    dec_str = decoded_items[0]["value"] if decoded_items else "None detected"

    escalation_ticket = f"""[SOC Tier 1 Escalation Summary - {now}]
• Alert Severity & Risk Score: {overall_severity} ({risk_score}/100)
• MITRE ATT&CK Mapping: {mitre_str}
• Impacted Internal Host(s): {int_str}
• External IP Intelligence: {ext_str}
• File Hash Reputation: {hash_str}
• Extracted Defanged URL(s): {url_str}
• Decoded Payload / Command: {dec_str}
• Recommended Action: Execute SOAR containment playbook, isolate host ({int_str}) if active C2 is confirmed, and block external IOCs on perimeter firewall."""

    closure_ticket = f"""[SOC Tier 1 Triage Notes - {now}]
• Alert reviewed and investigated by SOC Tier 1 (Calculated Risk Score: {risk_score}/100).
• Affected Internal Host(s): {int_str}
• External Indicator(s): {ext_str}
• Assessment: Activity verified as expected baseline / authorized behavior. Threat intelligence checks returned no actionable malicious indicators.
• Action Taken: Closing alert as Benign / False Positive."""

    result = {
        "id": str(uuid.uuid4())[:8],
        "timestamp": now,
        "risk_score": risk_score,
        "severity": overall_severity,
        "raw_preview": raw_text.strip().splitlines()[0][:80] if raw_text.strip() else "Alert Log",
        "raw_text": raw_text,
        "internal_ips": internal_ips,
        "external_ips": external_ips,
        "urls": urls,
        "hashes": all_hashes,
        "decoded": decoded_items,
        "events": events,
        "mitre": mitre_matches,
        "ip_intel": ip_intel,
        "hash_intel": hash_intel,
        "soar_playbook": "\n".join(fw_commands),
        "escalation_ticket": escalation_ticket,
        "closure_ticket": closure_ticket
    }

    save_to_history(result)
    return result

# ==========================================
# AI SOC CO-PILOT (GEMINI API + HEURISTIC FALLBACK)
# ==========================================
def generate_ai_copilot_analysis(alert_data: dict) -> dict:
    gemini_key = get_api_keys()["gemini"]
    prompt = f"""You are a Senior SOC Tier 3 Incident Responder assisting a Tier 1 Analyst.
Analyze the following triaged alert telemetry and provide a concise, actionable briefing in 3 bulleted sections:
1. ATTACK STORYLINE (What is happening & root cause)
2. TIER 1 VERIFICATION CHECKLIST (What logs/processes to verify next)
3. IMMEDIATE REMEDIATION STEPS

Telemetry:
- Severity: {alert_data.get('severity')} (Risk Score: {alert_data.get('risk_score')}/100)
- Internal Hosts: {alert_data.get('internal_ips')}
- External IPs & Reputation: {alert_data.get('ip_intel')}
- File Hashes & VT Labels: {alert_data.get('hash_intel')}
- Decoded Payloads: {alert_data.get('decoded')}
- MITRE ATT&CK Mapped: {alert_data.get('mitre')}
- Raw Log Snippet: {alert_data.get('raw_text')[:600]}"""

    if gemini_key:
        try:
            url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={gemini_key}"
            payload = {"contents": [{"parts": [{"text": prompt}]}]}
            res = requests.post(url, json=payload, timeout=12)
            if res.status_code == 200:
                text = res.json()["candidates"][0]["content"]["parts"][0]["text"]
                return {"source": "Google Gemini 2.5 Flash AI", "analysis": text}
        except Exception:
            pass

    # Built-in Expert Heuristic AI Fallback (Works offline or without API key)
    mitre_list = [f"{m['id']} ({m['name']})" for m in alert_data.get("mitre", [])]
    decoded_list = [d["value"] for d in alert_data.get("decoded", [])]
    hosts = ", ".join(alert_data.get("internal_ips", [])) or "Target Workstation"
    ext_ips = ", ".join(alert_data.get("external_ips", [])) or "External C2"

    heuristic_report = f"""[1] ATTACK STORYLINE & ROOT CAUSE ANALYSIS:
• Telemetry indicates a {alert_data.get('severity')} severity incident (Risk Score: {alert_data.get('risk_score')}/100) targeting internal host ({hosts}).
• Observed adversary tactics align with MITRE ATT&CK: {', '.join(mitre_list) if mitre_list else 'Anomalous System Activity'}.
• {'Deobfuscated payload reveals active command execution / staging: ' + decoded_list[0] if decoded_list else 'No obfuscated Base64 command detected; review raw process tree.'}

[2] SOC TIER 1 VERIFICATION CHECKLIST:
• Query SIEM / EDR for parent-child process lineage on host ({hosts}) within ±15 minutes of alert timestamp.
• Check outbound network connections to ({ext_ips}) across firewall/proxy logs to confirm if data exfiltration or payload download succeeded (HTTP 200 OK).
• Verify whether the user account associated with this session recently experienced failed logons (Event ID 4625) or privilege escalation (Event ID 4672).

[3] IMMEDIATE CONTAINMENT & REMEDIATION:
• Isolate host ({hosts}) via EDR network containment if malicious child process execution is confirmed.
• Apply the generated SOAR firewall rules to block ({ext_ips}) and blacklist any identified SHA-256 hashes across endpoint protection."""

    return {"source": "TriageX Built-in Neural Heuristic Engine", "analysis": heuristic_report}

# ==========================================
# DISCORD / SLACK SOAR WEBHOOK DISPATCHER
# ==========================================
def send_soar_webhook(alert_data: dict) -> dict:
    webhook_url = get_api_keys()["webhook"]
    if not webhook_url:
        return {"status": "error", "message": "No DISCORD_WEBHOOK_URL configured in .env file."}

    color = 15548997 if alert_data.get("severity") == "CRITICAL" else (16753920 if alert_data.get("severity") == "SUSPICIOUS" else 1096065)
    mitre_str = ", ".join([f"{m['id']} ({m['tactic']})" for m in alert_data.get("mitre", [])]) or "None"
    int_hosts = ", ".join(alert_data.get("internal_ips", [])) or "N/A"
    ext_ips = ", ".join([i["defanged_ip"] for i in alert_data.get("ip_intel", [])]) or "None"

    payload = {
        "username": "TriageX SOAR Bot",
        "embeds": [{
            "title": f"🚨 [{alert_data.get('severity')}] SOC Alert Triaged (Risk Score: {alert_data.get('risk_score')}/100)",
            "description": f"**Preview:** `{alert_data.get('raw_preview')}`",
            "color": color,
            "fields": [
                {"name": "🏠 Internal Host(s)", "value": f"`{int_hosts}`", "inline": True},
                {"name": "🌍 External IOC(s)", "value": f"`{ext_ips}`", "inline": True},
                {"name": "🎯 MITRE ATT&CK", "value": f"`{mitre_str}`", "inline": False},
                {"name": "🕒 Timestamp", "value": alert_data.get("timestamp"), "inline": True}
            ]
        }]
    }
    try:
        r = requests.post(webhook_url, json=payload, timeout=6)
        if r.status_code in [200, 204]:
            return {"status": "success", "message": "Alert dispatched to SOC Discord channel successfully!"}
        return {"status": "error", "message": f"Webhook returned HTTP {r.status_code}"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

# ==========================================
# STATIC MALWARE SANDBOX & EML PARSER
# ==========================================
def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return round(-sum((count / length) * math.log2(count / length) for count in counts.values()), 2)

def identify_magic_bytes(data: bytes) -> str:
    if data.startswith(b"MZ"):
        return "Windows PE Executable (.exe / .dll)"
    if data.startswith(b"\x7fELF"):
        return "Linux ELF Executable"
    if data.startswith(b"%PDF"):
        return "PDF Document"
    if data.startswith(b"PK\x03\x04"):
        return "ZIP Archive / Office OpenXML (.docx/.xlsx)"
    if data.startswith(b"\xd0\xcf\x11\xe0"):
        return "Microsoft Office OLE2 Compound File (.doc/.xls - Macro Capable)"
    return "Text / Script / Unknown Binary"

def analyze_suspicious_file(filename: str, file_bytes: bytes) -> dict:
    md5_hash = hashlib.md5(file_bytes).hexdigest()
    sha256_hash = hashlib.sha256(file_bytes).hexdigest()
    size_kb = round(len(file_bytes) / 1024, 2)
    entropy = calculate_entropy(file_bytes)
    magic_type = identify_magic_bytes(file_bytes)

    ext_lower = os.path.splitext(filename)[1].lower()
    spoof_warning = ("Windows PE" in magic_type and ext_lower not in [".exe", ".dll", ".sys", ".scr"])

    ascii_strings = re.findall(rb"[ -~]{5,}", file_bytes)
    decoded_strings = [s.decode("ascii", errors="ignore") for s in ascii_strings]
    full_str_blob = "\n".join(decoded_strings)

    suspicious_apis = [
        "VirtualAlloc", "VirtualProtect", "CreateRemoteThread", "WriteProcessMemory",
        "LoadLibrary", "GetProcAddress", "URLDownloadToFile", "WinExec", "ShellExecute",
        "powershell", "cmd.exe", "regsvr32", "rundll32", "WScript.Shell", "IsDebuggerPresent"
    ]
    found_apis = [api for api in suspicious_apis if re.search(rf"\b{re.escape(api)}\b", full_str_blob, re.IGNORECASE)]
    extracted_urls = [defang(u) for u in set(re.findall(r'https?://[^\s"\'<>]+', full_str_blob, re.IGNORECASE))][:15]
    extracted_ips = list(set(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', full_str_blob)))[:15]

    vt_info = check_vt_hash(sha256_hash)
    packing_status = "HIGH ENTROPY (Likely Packed / Encrypted Malware)" if entropy >= 7.0 else "Normal Entropy (Unpacked)"

    return {
        "filename": filename,
        "size_kb": f"{size_kb} KB",
        "md5": md5_hash,
        "sha256": sha256_hash,
        "magic_type": magic_type,
        "spoof_warning": spoof_warning,
        "entropy": entropy,
        "packing_status": packing_status,
        "suspicious_apis": found_apis,
        "urls": extracted_urls,
        "ips": extracted_ips,
        "vt": vt_info
    }

def analyze_eml_bytes(file_bytes: bytes) -> dict:
    msg = email.message_from_bytes(file_bytes, policy=policy.default)
    sender = msg.get("From", "N/A")
    reply_to = msg.get("Reply-To", "N/A")
    return_path = msg.get("Return-Path", "N/A")
    subject = msg.get("Subject", "N/A")
    auth_results = msg.get("Authentication-Results", "N/A")

    body_text = ""
    attachments = []
    for part in msg.walk():
        filename = part.get_filename()
        if filename:
            payload = part.get_payload(decode=True)
            if payload:
                sha256 = hashlib.sha256(payload).hexdigest()
                vt_info = check_vt_hash(sha256)
                attachments.append({
                    "filename": filename,
                    "sha256": sha256,
                    "vt": vt_info["vt"],
                    "verdict": vt_info["verdict"]
                })
        elif part.get_content_type() in ["text/plain", "text/html"]:
            try:
                body_text += part.get_content()
            except Exception:
                pass

    urls = [defang(u) for u in set(re.findall(r'https?://[^\s"\'<>]+', body_text))]
    return {
        "from": sender,
        "reply_to": reply_to,
        "spoofed": (reply_to != "N/A" and reply_to != sender),
        "return_path": return_path,
        "subject": subject,
        "auth": auth_results,
        "urls": urls,
        "attachments": attachments
    }
