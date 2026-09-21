import json
import os
import re
from collections import Counter, defaultdict
from datetime import datetime

from core.analytics import (
    THREAT_PATTERNS,
    calculate_modified_z_scores,
    calculate_shannon_entropy,
)
from core.containment import ContainmentEngine
from core.threat_intel import ThreatIntelProvider

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(BASE_DIR, "logs", "access.log")
JSON_REPORT = os.path.join(BASE_DIR, "report.json")
HTML_REPORT = os.path.join(BASE_DIR, "dashboard.html")
BLOCKLIST_FILE = os.path.join(BASE_DIR, "blocked_ips.txt")


def generate_wazuh_dashboard(report_data):
    """Generates an enterprise Wazuh-inspired HTML SOC Dashboard."""
    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    ip_counter = Counter()

    for threat in report_data["signature_telemetry"]:
        sev = threat["severity"].upper()
        if sev in sev_counts:
            sev_counts[sev] += 1
        ip_counter[threat["ip"]] += 1

    sev_counts["HIGH"] += len(report_data["volumetric_anomalies"])
    for bf in report_data["volumetric_anomalies"]:
        ip_counter[bf["ip"]] += bf["failed_count"]

    top_ips = ip_counter.most_common(5)
    top_ip_labels = [ip for ip, _ in top_ips]
    top_ip_counts = [count for _, count in top_ips]

    table_rows = ""
    for threat in report_data["signature_telemetry"]:
        table_rows += f"""
        <tr>
            <td style="font-family: monospace; color: #94a3b8;">{threat['timestamp']}</td>
            <td><strong style="color: #38bdf8;">{threat['ip']}</strong></td>
            <td><span class="badge badge-mitre">{threat['mitre_id']}</span></td>
            <td><span style="color: #f8fafc; font-weight: 600;">{threat['threat_type']}</span></td>
            <td><span class="badge badge-{threat['severity'].lower()}">{threat['severity']}</span></td>
            <td><span class="badge badge-entropy">H(X): {threat['entropy']}</span></td>
            <td><code>{threat['request']}</code></td>
        </tr>
        """

    for bf in report_data["volumetric_anomalies"]:
        table_rows += f"""
        <tr>
            <td style="font-family: monospace; color: #94a3b8;">Volumetric Spike</td>
            <td><strong style="color: #38bdf8;">{bf['ip']}</strong></td>
            <td><span class="badge badge-mitre">{bf['mitre_id']}</span></td>
            <td><span style="color: #f8fafc; font-weight: 600;">HTTP Brute Force Spike (Z-Score: {bf['z_score']})</span></td>
            <td><span class="badge badge-high">HIGH</span></td>
            <td><span class="badge badge-entropy">N/A</span></td>
            <td><code>POST /login.php ({bf['failed_count']} 401 Attempts)</code></td>
        </tr>
        """

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PyLogShield | Wazuh Enterprise Security Platform</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Inter:wght@400;600;700&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg-dark: #0b0f19;
            --panel-bg: rgba(18, 26, 43, 0.85);
            --border-color: #1e293b;
            --wazuh-blue: #0284c7;
            --accent-cyan: #38bdf8;
            --accent-red: #f43f5e;
            --accent-orange: #fb923c;
            --accent-green: #22c55e;
            --text-main: #f8fafc;
            --text-sub: #94a3b8;
        }}

        * {{ box-sizing: border-box; margin: 0; padding: 0; }}

        body {{
            font-family: 'Inter', sans-serif;
            background-color: var(--bg-dark);
            background-image: radial-gradient(circle at 50% 0%, rgba(2, 132, 199, 0.12) 0%, transparent 60%);
            color: var(--text-main);
            padding: 25px;
            min-height: 100vh;
        }}

        header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding-bottom: 20px;
            border-bottom: 1px solid var(--border-color);
            margin-bottom: 25px;
        }}

        .brand {{
            display: flex;
            align-items: center;
            gap: 14px;
        }}

        .brand-logo {{
            width: 44px;
            height: 44px;
            background: linear-gradient(135deg, var(--wazuh-blue), #0369a1);
            border-radius: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 22px;
            box-shadow: 0 0 20px rgba(2, 132, 199, 0.4);
        }}

        .brand-text h1 {{
            font-size: 1.4rem;
            font-weight: 700;
            letter-spacing: -0.5px;
        }}

        .brand-text p {{
            font-size: 0.82rem;
            color: var(--text-sub);
        }}

        .live-status {{
            display: flex;
            align-items: center;
            gap: 10px;
            background: rgba(34, 197, 94, 0.1);
            border: 1px solid rgba(34, 197, 94, 0.3);
            color: var(--accent-green);
            padding: 6px 14px;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: 600;
        }}

        .pulse-dot {{
            width: 8px;
            height: 8px;
            background-color: var(--accent-green);
            border-radius: 50%;
            box-shadow: 0 0 10px var(--accent-green);
        }}

        .kpi-grid {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 18px;
            margin-bottom: 25px;
        }}

        .kpi-card {{
            background: var(--panel-bg);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            padding: 18px;
            backdrop-filter: blur(10px);
        }}

        .kpi-title {{
            font-size: 0.75rem;
            color: var(--text-sub);
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 6px;
        }}

        .kpi-value {{
            font-size: 1.8rem;
            font-weight: 700;
            font-family: 'JetBrains Mono', monospace;
        }}

        .charts-grid {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-bottom: 25px;
        }}

        .chart-card {{
            background: var(--panel-bg);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            padding: 20px;
        }}

        .chart-card h3 {{
            font-size: 0.95rem;
            margin-bottom: 15px;
            color: var(--accent-cyan);
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}

        .table-card {{
            background: var(--panel-bg);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            padding: 20px;
            overflow: hidden;
        }}

        .table-header-tools {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }}

        .search-box {{
            background: #090d16;
            border: 1px solid var(--border-color);
            border-radius: 6px;
            padding: 8px 12px;
            color: white;
            font-size: 0.85rem;
            width: 260px;
            outline: none;
        }}

        .search-box:focus {{ border-color: var(--accent-cyan); }}

        table {{ width: 100%; border-collapse: collapse; }}

        th {{
            text-align: left;
            padding: 10px 14px;
            font-size: 0.72rem;
            text-transform: uppercase;
            color: var(--text-sub);
            border-bottom: 1px solid var(--border-color);
            background: rgba(9, 13, 22, 0.6);
        }}

        td {{
            padding: 12px 14px;
            border-bottom: 1px solid var(--border-color);
            font-size: 0.85rem;
        }}

        tr:hover {{ background-color: rgba(30, 41, 59, 0.5); }}

        .badge {{
            padding: 3px 8px;
            border-radius: 4px;
            font-weight: 700;
            font-size: 0.68rem;
        }}

        .badge-critical {{ background: rgba(244, 63, 94, 0.2); color: var(--accent-red); border: 1px solid var(--accent-red); }}
        .badge-high {{ background: rgba(251, 146, 60, 0.2); color: var(--accent-orange); border: 1px solid var(--accent-orange); }}
        .badge-mitre {{ background: rgba(2, 132, 199, 0.2); color: var(--accent-cyan); border: 1px solid var(--wazuh-blue); }}
        .badge-entropy {{ background: rgba(148, 163, 184, 0.15); color: #cbd5e1; font-family: monospace; }}

        code {{
            font-family: 'JetBrains Mono', monospace;
            background: #090d16;
            color: var(--accent-red);
            padding: 3px 6px;
            border-radius: 4px;
            font-size: 0.78rem;
            border: 1px solid rgba(244, 63, 94, 0.2);
        }}
    </style>
</head>
<body>

    <header>
        <div class="brand">
            <div class="brand-logo">🛡️</div>
            <div class="brand-text">
                <h1>WAZUH TELEMETRY CONSOLE (PyLogShield Core)</h1>
                <p>Enterprise Host-Based Intrusion Prevention & Mathematical Threat Intelligence</p>
            </div>
        </div>
        <div class="live-status">
            <div class="pulse-dot"></div>
            HIPS ACTIVE | ACTIVE CONTAINMENT ENFORCED
        </div>
    </header>

    <div class="kpi-grid">
        <div class="kpi-card">
            <div class="kpi-title">Ingested Log Events</div>
            <div class="kpi-value" style="color: var(--accent-cyan);">{report_data['metadata']['total_logs_analyzed']}</div>
        </div>
        <div class="kpi-card">
            <div class="kpi-title">Signature Detections</div>
            <div class="kpi-value" style="color: var(--accent-red);">{report_data['metadata']['signature_threats_detected']}</div>
        </div>
        <div class="kpi-card">
            <div class="kpi-title">Z-Score Anomalies</div>
            <div class="kpi-value" style="color: var(--accent-orange);">{report_data['metadata']['volumetric_anomalies_detected']}</div>
        </div>
        <div class="kpi-card">
            <div class="kpi-title">Active Isolation Rules</div>
            <div class="kpi-value" style="color: var(--accent-red);">{report_data['metadata']['total_active_containments']}</div>
        </div>
    </div>

    <div class="charts-grid">
        <div class="chart-card">
            <h3>Threat Severity Breakdown</h3>
            <div style="height: 220px; position: relative;">
                <canvas id="chart1"></canvas>
            </div>
        </div>
        <div class="chart-card">
            <h3>Top Offensive Source IPs</h3>
            <div style="height: 220px; position: relative;">
                <canvas id="chart2"></canvas>
            </div>
        </div>
    </div>

    <div class="table-card">
        <div class="table-header-tools">
            <h3 style="font-size: 1rem; color: var(--accent-cyan);">SECURITY TELEMETRY LOGS</h3>
            <input type="text" id="searchInput" onkeyup="filterTable()" class="search-box" placeholder="⚡ Search IP, MITRE ID, Threat...">
        </div>
        <table id="threatTable">
            <thead>
                <tr>
                    <th>Timestamp</th>
                    <th>Source IP</th>
                    <th>MITRE ID</th>
                    <th>Threat Classification</th>
                    <th>Severity</th>
                    <th>Entropy H(X)</th>
                    <th>Raw Telemetry / Payload</th>
                </tr>
            </thead>
            <tbody>
                {table_rows}
            </tbody>
        </table>
    </div>

    <script>
        new Chart(document.getElementById('chart1'), {{
            type: 'doughnut',
            data: {{
                labels: ['Critical', 'High'],
                datasets: [{{
                    data: [{sev_counts['CRITICAL']}, {sev_counts['HIGH']}],
                    backgroundColor: ['#f43f5e', '#fb923c'],
                    borderColor: '#0b0f19',
                    borderWidth: 3
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{ legend: {{ position: 'bottom', labels: {{ color: '#94a3b8' }} }} }}
            }}
        }});

        new Chart(document.getElementById('chart2'), {{
            type: 'bar',
            data: {{
                labels: {json.dumps(top_ip_labels)},
                datasets: [{{
                    label: 'Attacks',
                    data: {json.dumps(top_ip_counts)},
                    backgroundColor: '#0284c7',
                    borderRadius: 4
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                scales: {{
                    x: {{ ticks: {{ color: '#94a3b8' }}, grid: {{ display: false }} }},
                    y: {{ ticks: {{ color: '#94a3b8' }}, grid: {{ color: '#1e293b' }} }}
                }},
                plugins: {{ legend: {{ display: false }} }}
            }}
        }});

        function filterTable() {{
            let input = document.getElementById("searchInput").value.toLowerCase();
            let rows = document.querySelectorAll("#threatTable tbody tr");
            rows.forEach(row => {{
                let text = row.innerText.toLowerCase();
                row.style.display = text.includes(input) ? "" : "none";
            }});
        }}
    </script>
</body>
</html>"""

    with open(HTML_REPORT, "w", encoding="utf-8") as f:
        f.write(html)


def run_framework():
    print("[⚙] Starting PyLogShield Enterprise HIPS Platform...")

    if not os.path.exists(LOG_FILE):
        print(f"[-] Error: Telemetry log file not found at {LOG_FILE}")
        return

    containment = ContainmentEngine(BLOCKLIST_FILE)
    threat_intel = ThreatIntelProvider()

    flagged_events = []
    failed_logins = defaultdict(int)
    total_logs = 0

    with open(LOG_FILE, "r", encoding="utf-8") as f:
        for line in f:
            total_logs += 1
            match = re.search(
                r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+-\s+-\s+\[(.*?)\]\s+\"(.*?)\"\s+(\d{3})",
                line.strip(),
            )
            if not match:
                continue

            ip, timestamp, request_str, status = match.groups()

            if status == "401":
                failed_logins[ip] += 1

            # 1. Entropy Calculation
            entropy_score = calculate_shannon_entropy(request_str)

            # 2. Pattern & Anomaly Matching
            for threat_name, info in THREAT_PATTERNS.items():
                if info["pattern"].search(request_str) or entropy_score > 4.5:
                    intel = threat_intel.check_ip_reputation(ip)

                    event = {
                        "timestamp": timestamp,
                        "ip": ip,
                        "severity": info["severity"],
                        "threat_type": threat_name,
                        "mitre_id": info["mitre_id"],
                        "entropy": entropy_score,
                        "reputation": intel,
                        "request": request_str,
                    }
                    flagged_events.append(event)

                    if info["severity"] == "CRITICAL":
                        containment.enforce_isolation(
                            ip, threat_name, info["mitre_id"]
                        )

    # 3. Statistical Rate Anomaly Detection (Modified Z-Score)
    counts = list(failed_logins.values())
    ips = list(failed_logins.keys())
    z_scores = calculate_modified_z_scores(counts)

    brute_force_events = []
    for ip, count, z in zip(ips, counts, z_scores):
        if z > 3.5 or count >= 3:
            brute_force_events.append(
                {
                    "ip": ip,
                    "failed_count": count,
                    "z_score": z,
                    "mitre_id": "T1110.001",
                }
            )
            containment.enforce_isolation(
                ip, f"Brute Force Spike (Z-Score: {z})", "T1110.001"
            )

    report = {
        "metadata": {
            "system": "PyLogShield Enterprise HIPS v3.0",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "total_logs_analyzed": total_logs,
            "signature_threats_detected": len(flagged_events),
            "volumetric_anomalies_detected": len(brute_force_events),
            "total_active_containments": len(containment.enforced_ips),
        },
        "signature_telemetry": flagged_events,
        "volumetric_anomalies": brute_force_events,
    }

    with open(JSON_REPORT, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=4)

    # Generate Wazuh-inspired HTML dashboard
    generate_wazuh_dashboard(report)

    print(
        f"[✔] Telemetry Processing Complete. Security report exported to {JSON_REPORT}"
    )
    print(f"[✔] Wazuh SOC Console generated at {HTML_REPORT}")


if __name__ == "__main__":
    run_framework()