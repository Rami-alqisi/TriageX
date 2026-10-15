!/usr/bin/env python3
from flask import Flask, request, jsonify, render_template_string
import soc_shift

app = Flask(__name__)

HTML_THEME = """
<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <title>TriageX // AI-Driven SOC & Mini-SOAR Platform</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Inter:wght@400;600;700&display=swap" rel="stylesheet">
    <style>
        body {
            background-color: #070b14;
            color: #e2e8f0;
            font-family: 'Inter', sans-serif;
            background-image: radial-gradient(circle at 50% 0%, #0f172a 0%, #070b14 75%);
        }
        .mono { font-family: 'JetBrains Mono', monospace; }
        .cyber-card {
            background: rgba(15, 23, 42, 0.85);
            border: 1px solid #1e293b;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.5);
            backdrop-filter: blur(8px);
        }
        .cyber-border-cyan { border-left: 4px solid #06b6d4; }
        .cyber-border-red { border-left: 4px solid #ef4444; }
        .cyber-border-green { border-left: 4px solid #10b981; }
        .cyber-border-purple { border-left: 4px solid #a855f7; }
        .glow-btn {
            background: linear-gradient(90deg, #0891b2 0%, #2563eb 100%);
            box-shadow: 0 0 15px rgba(6, 182, 212, 0.4);
            transition: all 0.2s ease;
        }
        .glow-btn:hover {
            box-shadow: 0 0 25px rgba(6, 182, 212, 0.7);
            transform: translateY(-1px);
        }
        .ai-btn {
            background: linear-gradient(90deg, #7e22ce 0%, #ec4899 100%);
            box-shadow: 0 0 15px rgba(168, 85, 247, 0.4);
            transition: all 0.2s ease;
        }
        .ai-btn:hover {
            box-shadow: 0 0 25px rgba(236, 72, 153, 0.7);
            transform: translateY(-1px);
        }
        .tab-active {
            border-bottom: 2px solid #06b6d4;
            color: #06b6d4;
            background: rgba(6, 182, 212, 0.08);
        }
        @media print {
            header, #nav-tabs, #input-box, .no-print { display: none !important; }
            body { background: #fff !important; color: #000 !important; }
            .cyber-card { background: #fff !important; border: 1px solid #ccc !important; box-shadow: none !important; color: #000 !important; }
        }
    </style>
</head>
<body class="min-h-screen flex flex-col">

    <!-- Top Tactical Navbar -->
    <header class="border-b border-slate-800 bg-slate-950/90 px-6 py-4 flex justify-between items-center sticky top-0 z-50">
        <div class="flex items-center space-x-3">
            <div class="h-3 w-3 rounded-full bg-cyan-400 animate-pulse"></div>
            <h1 class="text-xl font-bold tracking-wider mono text-white">TRIAGEX <span class="text-cyan-400 font-normal text-sm">// AI-DRIVEN SOAR & THREAT INTEL PLATFORM</span></h1>
        </div>
        <div class="flex items-center space-x-5 text-xs mono">
            <div class="flex items-center space-x-1.5">
                <span class="text-slate-400">VT:</span>
                <span class="px-2 py-0.5 rounded {{ 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40' if keys.vt else 'bg-red-500/20 text-red-400 border border-red-500/40' }}">
                    {{ 'ONLINE' if keys.vt else 'NO KEY' }}
                </span>
            </div>
            <div class="flex items-center space-x-1.5">
                <span class="text-slate-400">ABUSEIPDB:</span>
                <span class="px-2 py-0.5 rounded {{ 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40' if keys.abuse else 'bg-red-500/20 text-red-400 border border-red-500/40' }}">
                    {{ 'ONLINE' if keys.abuse else 'NO KEY' }}
                </span>
            </div>
            <div class="flex items-center space-x-1.5">
                <span class="text-slate-400">AI CO-PILOT:</span>
                <span class="px-2 py-0.5 rounded bg-purple-500/20 text-purple-300 border border-purple-500/40">
                    {{ 'GEMINI API' if keys.gemini else 'HEURISTIC ENGINE' }}
                </span>
            </div>
            <div id="utc-clock" class="text-cyan-400 bg-slate-900 px-3 py-1.5 rounded border border-slate-800 font-semibold"></div>
        </div>
    </header>

    <!-- Navigation Tabs -->
    <div id="nav-tabs" class="bg-slate-900/60 border-b border-slate-800 px-6 flex space-x-2 text-sm font-semibold overflow-x-auto">
        <button onclick="switchTab('triage')" id="tab-triage" class="px-5 py-3 tab-active transition">⚡ SIEM Alert & SOAR Triage</button>
        <button onclick="switchTab('sandbox')" id="tab-sandbox" class="px-5 py-3 text-slate-400 hover:text-white transition">🔬 Static Malware Sandbox</button>
        <button onclick="switchTab('phish')" id="tab-phish" class="px-5 py-3 text-slate-400 hover:text-white transition">📧 Phishing (.eml) Inspector</button>
        <button onclick="switchTab('history'); loadShiftHistory();" id="tab-history" class="px-5 py-3 text-slate-400 hover:text-white transition flex items-center space-x-2">
            <span>📊 Analytics & Shift Handover</span>
            <span id="history-count" class="bg-cyan-500/20 text-cyan-400 border border-cyan-500/40 text-xs px-2 py-0.2 rounded-full mono">0</span>
        </button>
        <button onclick="switchTab('events')" id="tab-events" class="px-5 py-3 text-slate-400 hover:text-white transition">🪟 Event ID Matrix</button>
        <button onclick="switchTab('decoder')" id="tab-decoder" class="px-5 py-3 text-slate-400 hover:text-white transition">🔓 Payload Decoder</button>
    </div>

    <!-- Main Workspace -->
    <main class="flex-1 max-w-7xl w-full mx-auto p-6 space-y-6">

        <!-- TAB 1: SIEM ALERT & SOAR TRIAGE -->
        <div id="view-triage" class="space-y-6">
            <div id="input-box" class="cyber-card rounded-xl p-5">
                <div class="flex justify-between items-center mb-3">
                    <label class="text-sm font-semibold text-cyan-400 mono uppercase tracking-wider">Raw SIEM Log / Incident Telemetry Input</label>
                    <button onclick="document.getElementById('raw-alert').value=''" class="text-xs text-slate-400 hover:text-red-400 mono">Clear Input</button>
                </div>
                <textarea id="raw-alert" rows="5" class="w-full bg-slate-950 border border-slate-800 rounded-lg p-4 text-sm mono text-emerald-300 focus:outline-none focus:border-cyan-500" placeholder="Paste raw Splunk, QRadar, Wazuh, or Sysmon log here..."></textarea>
                <div class="mt-4 flex justify-between items-center">
                    <span class="text-xs text-slate-400 mono">Pipeline: Auto-IOC Extraction + Deobfuscation + MITRE ATT&CK + AI Co-Pilot + SOAR</span>
                    <button onclick="runAlertTriage()" id="btn-analyze" class="glow-btn text-white font-semibold px-6 py-2.5 rounded-lg text-sm mono">
                        ⚡ EXECUTE SOAR TRIAGE
                    </button>
                </div>
            </div>

            <!-- Dynamic Results Container -->
            <div id="triage-results" class="hidden space-y-6">
                <!-- Top Risk Score & Action Buttons Banner -->
                <div class="grid grid-cols-5 gap-4">
                    <div class="cyber-card cyber-border-purple rounded-lg p-4">
                        <div class="text-xs text-slate-400 mono">THREAT RISK SCORE</div>
                        <div class="flex items-baseline space-x-2 mt-1">
                            <span id="m-risk" class="text-3xl font-extrabold text-purple-400 mono">0</span>
                            <span class="text-xs text-slate-400 mono">/ 100</span>
                        </div>
                    </div>
                    <div class="cyber-card cyber-border-cyan rounded-lg p-4">
                        <div class="text-xs text-slate-400 mono">INTERNAL / EXTERNAL IPs</div>
                        <div class="text-xl font-bold text-white mono mt-1"><span id="m-int">0</span> In / <span id="m-ext" class="text-red-400">0</span> Ext</div>
                    </div>
                    <div class="cyber-card cyber-border-green rounded-lg p-4">
                        <div class="text-xs text-slate-400 mono">MITRE TECHNIQUES</div>
                        <div id="m-mitre" class="text-2xl font-bold text-emerald-400 mono mt-1">0</div>
                    </div>
                    <div class="cyber-card rounded-lg p-3 flex flex-col justify-center space-y-2 no-print">
                        <button onclick="runAICoPilot()" id="btn-ai" class="ai-btn text-white font-bold py-2 px-3 rounded text-xs mono">
                            🧠 Ask AI SOC Co-Pilot
                        </button>
                    </div>
                    <div class="cyber-card rounded-lg p-3 flex flex-col justify-center space-y-2 no-print">
                        <button onclick="sendWebhookAlert()" id="btn-webhook" class="bg-indigo-600/30 hover:bg-indigo-600 text-indigo-300 hover:text-white border border-indigo-500/40 text-xs mono py-1.5 px-2 rounded transition">
                            🔔 Push to Discord SOAR
                        </button>
                        <button onclick="window.print()" class="bg-cyan-500/20 hover:bg-cyan-500/40 text-cyan-300 border border-cyan-500/40 text-xs mono py-1 px-2 rounded transition">
                            📄 Export PDF Report
                        </button>
                    </div>
                </div>

                <!-- AI SOC Co-Pilot Output Box -->
                <div id="ai-box" class="hidden cyber-card border border-purple-500/60 rounded-xl p-5 bg-purple-950/10">
                    <div class="flex justify-between items-center mb-3">
                        <span class="text-sm font-bold text-purple-300 mono">🧠 AI SOC CO-PILOT INCIDENT BRIEFING</span>
                        <span id="ai-source" class="text-xs bg-purple-500/20 text-purple-300 px-2.5 py-0.5 rounded border border-purple-500/40 mono"></span>
                    </div>
                    <pre id="ai-content" class="bg-slate-950 p-4 rounded border border-purple-500/30 text-xs mono text-slate-200 whitespace-pre-wrap leading-relaxed"></pre>
                </div>

                <!-- MITRE ATT&CK Automated Mapping -->
                <div id="mitre-box" class="hidden cyber-card cyber-border-purple rounded-xl p-5">
                    <h3 class="text-sm font-bold text-purple-400 mono mb-3">🎯 MITRE ATT&CK® FRAMEWORK MAPPING</h3>
                    <div id="mitre-cards" class="grid grid-cols-3 gap-3"></div>
                </div>

                <!-- Decoded Payloads Box -->
                <div id="decoded-box" class="hidden cyber-card border border-red-500/50 rounded-xl p-5 bg-red-950/10">
                    <h3 class="text-sm font-bold text-red-400 mono mb-2">🚨 DEOBFUSCATED HIDDEN PAYLOAD</h3>
                    <div id="decoded-content" class="space-y-2"></div>
                </div>

                <!-- External IP Threat Intel Table -->
                <div class="cyber-card rounded-xl p-5">
                    <h3 class="text-sm font-bold text-cyan-400 mono mb-4">🌐 EXTERNAL IP THREAT INTELLIGENCE (ABUSEIPDB + VIRUSTOTAL)</h3>
                    <div class="overflow-x-auto">
                        <table class="w-full text-left text-sm mono">
                            <thead class="text-xs text-slate-400 border-b border-slate-800">
                                <tr>
                                    <th class="pb-3">DEFANGED IP</th>
                                    <th class="pb-3">LOCATION</th>
                                    <th class="pb-3">ISP / ORG</th>
                                    <th class="pb-3">ABUSEIPDB</th>
                                    <th class="pb-3">VIRUSTOTAL</th>
                                    <th class="pb-3">VERDICT</th>
                                </tr>
                            </thead>
                            <tbody id="ip-table-body" class="divide-y divide-slate-800/60"></tbody>
                        </table>
                    </div>
                </div>

                <!-- File Hash Threat Intel Table -->
                <div id="hash-card" class="hidden cyber-card rounded-xl p-5">
                    <h3 class="text-sm font-bold text-cyan-400 mono mb-4">🦠 FILE HASH REPUTATION (VIRUSTOTAL)</h3>
                    <table class="w-full text-left text-sm mono">
                        <thead class="text-xs text-slate-400 border-b border-slate-800">
                            <tr>
                                <th class="pb-3">FILE HASH</th>
                                <th class="pb-3">VT DETECTIONS</th>
                                <th class="pb-3">THREAT LABEL</th>
                                <th class="pb-3">VERDICT</th>
                            </tr>
                        </thead>
                        <tbody id="hash-table-body" class="divide-y divide-slate-800/60"></tbody>
                    </table>
                </div>

                <!-- SOAR Playbook & Remediation Commands -->
                <div class="cyber-card cyber-border-cyan rounded-xl p-5">
                    <div class="flex justify-between items-center mb-3">
                        <span class="text-sm font-bold text-cyan-400 mono">⚡ SOAR AUTOMATED CONTAINMENT & FIREWALL PLAYBOOK</span>
                        <button onclick="copyText('soar-playbook')" class="no-print bg-slate-800 hover:bg-cyan-600 text-xs mono px-3 py-1 rounded text-white transition">📋 Copy Commands</button>
                    </div>
                    <pre id="soar-playbook" class="bg-slate-950 p-4 rounded border border-slate-800 text-xs mono text-emerald-300 whitespace-pre-wrap overflow-x-auto"></pre>
                </div>

                <!-- Event IDs & Extracted Entities -->
                <div class="grid grid-cols-2 gap-6">
                    <div class="cyber-card rounded-xl p-5 space-y-3">
                        <h3 class="text-sm font-bold text-cyan-400 mono">🏠 INTERNAL HOSTS & DEFANGED URLS</h3>
                        <div class="text-xs text-slate-400 mono">Internal Hosts:</div>
                        <pre id="int-list" class="bg-slate-950 p-3 rounded border border-slate-800 text-xs mono text-slate-200"></pre>
                        <div class="text-xs text-slate-400 mono">Defanged URLs:</div>
                        <pre id="url-list" class="bg-slate-950 p-3 rounded border border-slate-800 text-xs mono text-amber-300 overflow-x-auto"></pre>
                    </div>
                    <div class="cyber-card rounded-xl p-5">
                        <h3 class="text-sm font-bold text-cyan-400 mono mb-3">🪟 DETECTED EVENT ID GUIDANCE</h3>
                        <div id="event-list" class="space-y-3 text-sm"></div>
                    </div>
                </div>

                <!-- Ticket Generators -->
                <div class="grid grid-cols-2 gap-6">
                    <div class="cyber-card cyber-border-red rounded-xl p-5">
                        <div class="flex justify-between items-center mb-3">
                            <span class="text-sm font-bold text-red-400 mono">🚨 TIER 2 ESCALATION TICKET</span>
                            <button onclick="copyText('esc-ticket')" class="no-print bg-slate-800 hover:bg-cyan-600 text-xs mono px-3 py-1 rounded text-white transition">📋 Copy Note</button>
                        </div>
                        <pre id="esc-ticket" class="bg-slate-950 p-4 rounded border border-slate-800 text-xs mono text-slate-300 whitespace-pre-wrap"></pre>
                    </div>
                    <div class="cyber-card cyber-border-green rounded-xl p-5">
                        <div class="flex justify-between items-center mb-3">
                            <span class="text-sm font-bold text-emerald-400 mono">✅ FALSE POSITIVE CLOSURE TICKET</span>
                            <button onclick="copyText('cls-ticket')" class="no-print bg-slate-800 hover:bg-cyan-600 text-xs mono px-3 py-1 rounded text-white transition">📋 Copy Note</button>
                        </div>
                        <pre id="cls-ticket" class="bg-slate-950 p-4 rounded border border-slate-800 text-xs mono text-slate-300 whitespace-pre-wrap"></pre>
                    </div>
                </div>
            </div>
        </div>

        <!-- TAB 2: STATIC MALWARE SANDBOX -->
        <div id="view-sandbox" class="hidden space-y-6">
            <div class="cyber-card cyber-border-purple rounded-xl p-6">
                <h3 class="text-sm font-bold text-purple-400 mono mb-2">🔬 STATIC MALWARE FILE SANDBOX & FORENSIC TRIAGE</h3>
                <p class="text-xs text-slate-400 mb-4">Safely inspect suspicious binaries, scripts, or documents (.exe, .dll, .pdf, .ps1, .docm, .elf) without executing them. Computes Shannon Entropy, verifies Magic Bytes, extracts Win32 API calls/IOC strings, and queries VirusTotal.</p>
                <input type="file" id="sandbox-file" class="block w-full text-sm text-slate-400 file:mr-4 file:py-2 file:px-4 file:rounded file:border-0 file:text-sm file:font-semibold file:bg-purple-600 file:text-white hover:file:bg-purple-500"/>
                <button onclick="runMalwareSandbox()" id="btn-sandbox" class="glow-btn text-white font-semibold px-6 py-2 rounded-lg text-sm mono mt-4">🧬 ANALYZE FILE ARTIFACT</button>
            </div>
            <div id="sandbox-results" class="hidden space-y-6"></div>
        </div>

        <!-- TAB 3: PHISHING ANALYZER -->
        <div id="view-phish" class="hidden space-y-6">
            <div class="cyber-card rounded-xl p-6">
                <h3 class="text-sm font-bold text-cyan-400 mono mb-4">📧 UPLOAD SUSPICIOUS EMAIL (.EML)</h3>
                <input type="file" id="eml-file" accept=".eml" class="block w-full text-sm text-slate-400 file:mr-4 file:py-2 file:px-4 file:rounded file:border-0 file:text-sm file:font-semibold file:bg-cyan-600 file:text-white hover:file:bg-cyan-500"/>
                <button onclick="runPhishTriage()" class="glow-btn text-white font-semibold px-6 py-2 rounded-lg text-sm mono mt-4">🔍 ANALYZE .EML FILE</button>
            </div>
            <div id="phish-results" class="hidden cyber-card rounded-xl p-6 space-y-4"></div>
        </div>

        <!-- TAB 4: ANALYTICS & SHIFT HANDOVER -->
        <div id="view-history" class="hidden space-y-6">
            <div class="grid grid-cols-2 gap-6">
                <div class="cyber-card rounded-xl p-5">
                    <h3 class="text-sm font-bold text-cyan-400 mono mb-3">📊 SHIFT ALERTS BY SEVERITY</h3>
                    <div class="h-56 flex justify-center"><canvas id="severityChart"></canvas></div>
                </div>
                <div class="cyber-card cyber-border-cyan rounded-xl p-5 flex flex-col justify-between">
                    <div>
                        <div class="flex justify-between items-center mb-3">
                            <h3 class="text-sm font-bold text-cyan-400 mono">📋 AUTOMATED SHIFT HANDOVER REPORT</h3>
                            <div class="flex space-x-2">
                                <button onclick="copyText('handover-box')" class="glow-btn text-xs mono px-3 py-1.5 rounded text-white font-semibold">📋 Copy</button>
                                <button onclick="clearShiftHistory()" class="bg-red-500/20 hover:bg-red-500/40 text-red-400 border border-red-500/40 text-xs mono px-3 py-1.5 rounded transition">🗑️ Clear</button>
                            </div>
                        </div>
                        <pre id="handover-box" class="bg-slate-950 p-4 rounded border border-slate-800 text-xs mono text-emerald-300 whitespace-pre-wrap max-h-48 overflow-y-auto"></pre>
                    </div>
                </div>
            </div>

            <div class="cyber-card rounded-xl p-5">
                <h3 class="text-sm font-bold text-cyan-400 mono mb-4">🕒 TRIAGED ALERTS LOG (CLICK 'LOAD' TO RE-OPEN WITHOUT API CALLS)</h3>
                <div class="overflow-x-auto">
                    <table class="w-full text-left text-sm mono">
                        <thead class="text-xs text-slate-400 border-b border-slate-800">
                            <tr>
                                <th class="pb-3">TIME (UTC)</th>
                                <th class="pb-3">RISK SCORE</th>
                                <th class="pb-3">SEVERITY</th>
                                <th class="pb-3">INTERNAL HOST</th>
                                <th class="pb-3">MITRE ATT&CK</th>
                                <th class="pb-3">ALERT PREVIEW</th>
                                <th class="pb-3 text-right">ACTION</th>
                            </tr>
                        </thead>
                        <tbody id="history-table-body" class="divide-y divide-slate-800/60"></tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- TAB 5: EVENT ID MATRIX -->
        <div id="view-events" class="hidden cyber-card rounded-xl p-6">
            <h3 class="text-sm font-bold text-cyan-400 mono mb-4">🪟 WINDOWS SECURITY & SYSMON EVENT ID REFERENCE</h3>
            <div class="divide-y divide-slate-800 mono text-sm">
                {% for eid, info in events.items() %}
                <div class="py-3 flex justify-between">
                    <div><span class="text-cyan-400 font-bold">ID {{ eid }}</span> — <span class="text-white font-semibold">{{ info[0] }}</span></div>
                    <div class="text-slate-400 text-xs max-w-xl text-right">{{ info[1] }}</div>
                </div>
                {% endfor %}
            </div>
        </div>

        <!-- TAB 6: QUICK DECODER -->
        <div id="view-decoder" class="hidden cyber-card rounded-xl p-6 space-y-4">
            <h3 class="text-sm font-bold text-cyan-400 mono">🔓 BASE64 / POWERSHELL / URL DECODER</h3>
            <textarea id="dec-input" rows="4" class="w-full bg-slate-950 border border-slate-800 rounded-lg p-4 text-sm mono text-emerald-300" placeholder="Paste obfuscated PowerShell -enc or URL-encoded payload..."></textarea>
            <button onclick="runDecoder()" class="glow-btn text-white font-semibold px-6 py-2 rounded-lg text-sm mono">DECODE PAYLOAD</button>
            <pre id="dec-output" class="bg-slate-950 p-4 rounded border border-slate-800 text-xs mono text-amber-300 whitespace-pre-wrap"></pre>
        </div>

    </main>

    <script>
        let shiftCache = [];
        let currentAlertData = null;
        let sevChartInstance = null;

        function updateClock() {
            const now = new Date();
            document.getElementById('utc-clock').innerText = now.toISOString().replace('T', ' ').substring(0, 19) + ' UTC';
        }
        setInterval(updateClock, 1000);
        updateClock();

        function switchTab(tab) {
            ['triage', 'sandbox', 'phish', 'history', 'events', 'decoder'].forEach(t => {
                document.getElementById('view-' + t).classList.add('hidden');
                document.getElementById('tab-' + t).classList.remove('tab-active');
                document.getElementById('tab-' + t).classList.add('text-slate-400');
            });
            document.getElementById('view-' + tab).classList.remove('hidden');
            document.getElementById('tab-' + tab).classList.add('tab-active');
        }

        function badge(verdict) {
            if (verdict.includes('CRITICAL')) return `<span class="px-2 py-0.5 rounded bg-red-500/20 text-red-400 border border-red-500/40 text-xs font-bold">${verdict}</span>`;
            if (verdict.includes('SUSPICIOUS')) return `<span class="px-2 py-0.5 rounded bg-amber-500/20 text-amber-400 border border-amber-500/40 text-xs font-bold">${verdict}</span>`;
            return `<span class="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-400 border border-emerald-500/40 text-xs">${verdict}</span>`;
        }

        function renderTriageData(data) {
            currentAlertData = data;
            document.getElementById('ai-box').classList.add('hidden');
            document.getElementById('triage-results').classList.remove('hidden');
            document.getElementById('m-risk').innerText = data.risk_score || 0;
            document.getElementById('m-int').innerText = data.internal_ips.length;
            document.getElementById('m-ext').innerText = data.external_ips.length;
            document.getElementById('m-mitre').innerText = (data.mitre || []).length;

            const mitreBox = document.getElementById('mitre-box');
            const mitreCards = document.getElementById('mitre-cards');
            if (data.mitre && data.mitre.length > 0) {
                mitreBox.classList.remove('hidden');
                mitreCards.innerHTML = data.mitre.map(m => `
                    <a href="${m.url}" target="_blank" class="bg-slate-950 hover:bg-slate-900 border border-purple-500/40 rounded-lg p-3 block transition">
                        <div class="flex justify-between items-center">
                            <span class="text-xs font-bold text-purple-400 mono">${m.id}</span>
                            <span class="text-[10px] bg-purple-500/20 text-purple-300 px-2 py-0.5 rounded mono">${m.tactic}</span>
                        </div>
                        <div class="text-xs text-white font-semibold mt-1">${m.name}</div>
                    </a>
                `).join('');
            } else {
                mitreBox.classList.add('hidden');
            }

            const decBox = document.getElementById('decoded-box');
            const decContent = document.getElementById('decoded-content');
            if (data.decoded.length > 0) {
                decBox.classList.remove('hidden');
                decContent.innerHTML = data.decoded.map(d => `<div class="text-xs text-slate-400 mono">${d.type}:</div><pre class="bg-slate-950 p-3 rounded border border-red-500/40 text-emerald-300 text-xs mono overflow-x-auto">${d.value}</pre>`).join('');
            } else {
                decBox.classList.add('hidden');
            }

            const ipBody = document.getElementById('ip-table-body');
            ipBody.innerHTML = data.ip_intel.length ? data.ip_intel.map(ip => `
                <tr>
                    <td class="py-3 text-amber-300">${ip.defanged_ip}</td>
                    <td class="py-3">${ip.location}</td>
                    <td class="py-3 text-slate-300">${ip.isp}</td>
                    <td class="py-3">${ip.abuse}</td>
                    <td class="py-3">${ip.vt}</td>
                    <td class="py-3">${badge(ip.verdict)}</td>
                </tr>
            `).join('') : `<tr><td colspan="6" class="py-3 text-slate-500">No external IPs detected.</td></tr>`;

            const hashCard = document.getElementById('hash-card');
            const hashBody = document.getElementById('hash-table-body');
            if (data.hash_intel.length > 0) {
                hashCard.classList.remove('hidden');
                hashBody.innerHTML = data.hash_intel.map(h => `
                    <tr>
                        <td class="py-3 text-cyan-300">${h.hash}</td>
                        <td class="py-3">${h.vt}</td>
                        <td class="py-3">${h.label}</td>
                        <td class="py-3">${badge(h.verdict)}</td>
                    </tr>
                `).join('');
            } else {
                hashCard.classList.add('hidden');
            }

            document.getElementById('soar-playbook').innerText = data.soar_playbook || '# No automated playbook generated.';
            document.getElementById('int-list').innerText = data.internal_ips.join('\\n') || 'None';
            document.getElementById('url-list').innerText = data.urls.join('\\n') || 'None';

            const evList = document.getElementById('event-list');
            evList.innerHTML = data.events.length ? data.events.map(e => `
                <div class="bg-slate-950 p-3 rounded border border-slate-800">
                    <div class="text-cyan-400 font-bold mono">Event ID ${e.id}: ${e.name}</div>
                    <div class="text-xs text-slate-300 mt-1">${e.desc}</div>
                </div>
            `).join('') : `<div class="text-slate-500 mono text-xs">No specific Event ID matched.</div>`;

            document.getElementById('esc-ticket').innerText = data.escalation_ticket;
            document.getElementById('cls-ticket').innerText = data.closure_ticket;
        }

        async function runAlertTriage() {
            const raw = document.getElementById('raw-alert').value;
            if (!raw.trim()) return;
            const btn = document.getElementById('btn-analyze');
            btn.innerText = '⏳ EXECUTING SOAR & THREAT INTEL...';

            const res = await fetch('/api/triage', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({raw_text: raw})
            });
            const data = await res.json();
            btn.innerText = '⚡ EXECUTE SOAR TRIAGE';
            renderTriageData(data);
            loadShiftHistory();
        }

        async function runAICoPilot() {
            if (!currentAlertData) return;
            const btn = document.getElementById('btn-ai');
            btn.innerText = '🧠 GENERATING AI BRIEFING...';
            const res = await fetch('/api/ai_copilot', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify(currentAlertData)
            });
            const data = await res.json();
            btn.innerText = '🧠 Ask AI SOC Co-Pilot';
            document.getElementById('ai-box').classList.remove('hidden');
            document.getElementById('ai-source').innerText = 'Engine: ' + data.source;
            document.getElementById('ai-content').innerText = data.analysis;
        }

        async function sendWebhookAlert() {
            if (!currentAlertData) return;
            const btn = document.getElementById('btn-webhook');
            btn.innerText = '⏳ SENDING...';
            const res = await fetch('/api/webhook', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify(currentAlertData)
            });
            const data = await res.json();
            btn.innerText = '🔔 Push to Discord SOAR';
            alert(data.message);
        }

        async function runMalwareSandbox() {
            const fileInput = document.getElementById('sandbox-file');
            if (!fileInput.files.length) return;
            const btn = document.getElementById('btn-sandbox');
            btn.innerText = '⏳ INSPECTING BINARY & QUERYING VT...';

            const formData = new FormData();
            formData.append('file', fileInput.files[0]);

            const res = await fetch('/api/sandbox', {method: 'POST', body: formData});
            const d = await res.json();
            btn.innerText = '🧬 ANALYZE FILE ARTIFACT';

            const box = document.getElementById('sandbox-results');
            box.classList.remove('hidden');
            box.innerHTML = `
                <div class="cyber-card rounded-xl p-6 space-y-4">
                    <div class="flex justify-between items-center border-b border-slate-800 pb-3">
                        <div>
                            <h3 class="text-lg font-bold text-white mono">${d.filename} <span class="text-xs text-slate-400">(${d.size_kb})</span></h3>
                            <p class="text-xs text-cyan-400 mono">Detected Magic Header: ${d.magic_type}</p>
                        </div>
                        <div>${badge(d.vt.verdict)}</div>
                    </div>
                    ${d.spoof_warning ? `<div class="bg-red-500/20 border border-red-500 p-3 rounded text-xs text-red-300 mono font-bold">⚠️ EXTENSION SPOOFING DETECTED: File header is an executable binary (MZ), but extension is disguised!</div>` : ''}
                    <div class="grid grid-cols-3 gap-4 text-xs mono">
                        <div class="bg-slate-950 p-3 rounded border border-slate-800">
                            <div class="text-slate-400">SHANNON ENTROPY:</div>
                            <div class="text-lg font-bold ${d.entropy >= 7.0 ? 'text-red-400' : 'text-emerald-400'} mt-1">${d.entropy} / 8.0</div>
                            <div class="text-[11px] text-slate-400 mt-1">${d.packing_status}</div>
                        </div>
                        <div class="bg-slate-950 p-3 rounded border border-slate-800">
                            <div class="text-slate-400">VIRUSTOTAL REPUTATION:</div>
                            <div class="text-lg font-bold text-amber-300 mt-1">${d.vt.vt}</div>
                            <div class="text-[11px] text-slate-400 mt-1">Family: ${d.vt.label}</div>
                        </div>
                        <div class="bg-slate-950 p-3 rounded border border-slate-800">
                            <div class="text-slate-400">CRYPTOGRAPHIC HASHES:</div>
                            <div class="text-[11px] text-cyan-300 mt-1 break-all"><b>MD5:</b> ${d.md5}</div>
                            <div class="text-[11px] text-cyan-300 mt-1 break-all"><b>SHA256:</b> ${d.sha256}</div>
                        </div>
                    </div>
                    <div class="grid grid-cols-2 gap-4">
                        <div>
                            <div class="text-xs font-bold text-purple-400 mono mb-2">SUSPICIOUS WIN32 APIs / CAPABILITIES:</div>
                            <pre class="bg-slate-950 p-3 rounded border border-slate-800 text-xs mono text-red-300">${d.suspicious_apis.join(', ') || 'None detected'}</pre>
                        </div>
                        <div>
                            <div class="text-xs font-bold text-cyan-400 mono mb-2">EXTRACTED EMBEDDED URLs & IPs:</div>
                            <pre class="bg-slate-950 p-3 rounded border border-slate-800 text-xs mono text-amber-300">${(d.urls.concat(d.ips)).join('\\n') || 'None detected'}</pre>
                        </div>
                    </div>
                </div>
            `;
        }

        async function loadShiftHistory() {
            const res = await fetch('/api/history');
            shiftCache = await res.json();
            document.getElementById('history-count').innerText = shiftCache.length;

            const critCount = shiftCache.filter(x => x.severity === 'CRITICAL').length;
            const suspCount = shiftCache.filter(x => x.severity === 'SUSPICIOUS').length;
            const cleanCount = shiftCache.length - critCount - suspCount;

            const ctx = document.getElementById('severityChart').getContext('2d');
            if (sevChartInstance) sevChartInstance.destroy();
            sevChartInstance = new Chart(ctx, {
                type: 'doughnut',
                data: {
                    labels: ['Critical', 'Suspicious', 'Clean / Low'],
                    datasets: [{
                        data: [critCount, suspCount, cleanCount],
                        backgroundColor: ['#ef4444', '#f59e0b', '#10b981'],
                        borderColor: '#0f172a',
                        borderWidth: 2
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: { legend: { labels: { color: '#cbd5e1', font: { family: 'JetBrains Mono' } } } }
                }
            });

            const tbody = document.getElementById('history-table-body');
            if (!shiftCache.length) {
                tbody.innerHTML = `<tr><td colspan="7" class="py-4 text-slate-500 text-center">No alerts triaged in this shift yet.</td></tr>`;
                document.getElementById('handover-box').innerText = "No alerts logged yet.";
                return;
            }

            tbody.innerHTML = shiftCache.map((item, idx) => `
                <tr class="hover:bg-slate-900/50">
                    <td class="py-3 text-xs text-slate-400">${item.timestamp}</td>
                    <td class="py-3 font-bold text-purple-400">${item.risk_score || 0}/100</td>
                    <td class="py-3">${badge(item.severity)}</td>
                    <td class="py-3 text-cyan-300">${item.internal_ips.join(', ') || 'N/A'}</td>
                    <td class="py-3 text-xs text-purple-300">${(item.mitre || []).map(m => m.id).join(', ') || 'None'}</td>
                    <td class="py-3 text-xs text-slate-300 truncate max-w-xs">${item.raw_preview}</td>
                    <td class="py-3 text-right">
                        <button onclick="reopenAlert(${idx})" class="bg-cyan-600/30 hover:bg-cyan-600 text-cyan-300 hover:text-white border border-cyan-500/40 px-3 py-1 rounded text-xs transition">
                            🔄 Load
                        </button>
                    </td>
                </tr>
            `).join('');

            let handover = `=== SOC TIER 1 SHIFT HANDOVER SUMMARY ===\\n`;
            handover += `• Total Alerts Triaged: ${shiftCache.length} (Critical: ${critCount} | Suspicious: ${suspCount} | Benign: ${cleanCount})\\n\\n`;
            handover += `=== KEY ALERTS LOGGED THIS SHIFT ===\\n`;
            shiftCache.forEach((item, i) => {
                handover += `${i+1}. [${item.timestamp}] [${item.severity} - Score: ${item.risk_score || 0}/100] Host: ${item.internal_ips.join(', ') || 'N/A'} | MITRE: ${(item.mitre || []).map(m => m.id).join(', ') || 'N/A'}\\n`;
            });
            document.getElementById('handover-box').innerText = handover;
        }

        function reopenAlert(index) {
            const item = shiftCache[index];
            document.getElementById('raw-alert').value = item.raw_text;
            renderTriageData(item);
            switchTab('triage');
        }

        async function clearShiftHistory() {
            if (!confirm('Clear all shift history logs?')) return;
            await fetch('/api/history/clear', {method: 'POST'});
            loadShiftHistory();
        }

        async function runPhishTriage() {
            const fileInput = document.getElementById('eml-file');
            if (!fileInput.files.length) return;
            const formData = new FormData();
            formData.append('file', fileInput.files[0]);

            const res = await fetch('/api/phish', {method: 'POST', body: formData});
            const data = await res.json();
            const box = document.getElementById('phish-results');
            box.classList.remove('hidden');
            box.innerHTML = `
                <div class="grid grid-cols-2 gap-4 text-xs mono">
                    <div class="bg-slate-950 p-3 rounded border border-slate-800"><span class="text-slate-400">From:</span> ${data.from}</div>
                    <div class="bg-slate-950 p-3 rounded border border-slate-800"><span class="text-slate-400">Reply-To:</span> <span class="${data.spoofed ? 'text-red-400 font-bold' : ''}">${data.reply_to}</span></div>
                    <div class="bg-slate-950 p-3 rounded border border-slate-800"><span class="text-slate-400">Subject:</span> ${data.subject}</div>
                    <div class="bg-slate-950 p-3 rounded border border-slate-800"><span class="text-slate-400">Auth:</span> ${data.auth}</div>
                </div>
                <div class="text-xs text-cyan-400 mono font-bold mt-4">DEFANGED URLS:</div>
                <pre class="bg-slate-950 p-3 rounded border border-slate-800 text-xs mono text-amber-300">${data.urls.join('\\n') || 'None'}</pre>
                <div class="text-xs text-cyan-400 mono font-bold mt-4">ATTACHMENTS & VIRUSTOTAL:</div>
                <pre class="bg-slate-950 p-3 rounded border border-slate-800 text-xs mono text-emerald-300">${data.attachments.map(a => `${a.filename} \vert{} SHA256:${a.sha256} | VT: ${a.vt} (${a.verdict})`).join('\\n') || 'No attachments'}</pre>
            `;
        }

        async function runDecoder() {
            const raw = document.getElementById('dec-input').value;
            const res = await fetch('/api/decode', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({raw_text: raw})
            });
            const data = await res.json();
            document.getElementById('dec-output').innerText = data.decoded.map(d => `[${d.type}]\\n${d.value}`).join('\\n\\n') || 'Nothing decoded.';
        }

        function copyText(id) {
            navigator.clipboard.writeText(document.getElementById(id).innerText);
            alert('Copied to clipboard!');
        }

        loadShiftHistory();
    </script>
</body>
</html>
"""

@app.route("/")
def index():
    return render_template_string(HTML_THEME, keys=soc_shift.get_api_keys(), events=soc_shift.EVENT_IDS)

@app.route("/api/triage", methods=["POST"])
def api_triage():
    raw_text = request.json.get("raw_text", "")
    return jsonify(soc_shift.analyze_alert_data(raw_text))

@app.route("/api/ai_copilot", methods=["POST"])
def api_ai_copilot():
    return jsonify(soc_shift.generate_ai_copilot_analysis(request.json))

@app.route("/api/webhook", methods=["POST"])
def api_webhook():
    return jsonify(soc_shift.send_soar_webhook(request.json))

@app.route("/api/sandbox", methods=["POST"])
def api_sandbox():
    f = request.files["file"]
    return jsonify(soc_shift.analyze_suspicious_file(f.filename, f.read()))

@app.route("/api/history", methods=["GET"])
def api_history():
    return jsonify(soc_shift.load_history())

@app.route("/api/history/clear", methods=["POST"])
def api_history_clear():
    soc_shift.clear_history()
    return jsonify({"status": "cleared"})

@app.route("/api/phish", methods=["POST"])
def api_phish():
    f = request.files["file"]
    return jsonify(soc_shift.analyze_eml_bytes(f.read()))

@app.route("/api/decode", methods=["POST"])
def api_decode():
    raw_text = request.json.get("raw_text", "")
    return jsonify({"decoded": soc_shift.try_decode_payloads(raw_text)})

if __name__ == "__main__":
    print("\n[+] Starting TriageX AI-Driven SOAR Console on: http://127.0.0.1:5000\n")
    app.run(host="127.0.0.1", port=5000, debug=False)