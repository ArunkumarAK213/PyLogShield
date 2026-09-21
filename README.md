# 🛡️ PyLogShield — Enterprise HIPS & Threat Telemetry Framework

[![Live SOC Console](https://img.shields.io/badge/Live_SOC_Console-Wazuh_Inspired-0284c7?style=for-the-badge\&logo=wazuh)](https://arunkumarak213.github.io/PyLogShield/)
[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge\&logo=python\&logoColor=white)](https://www.python.org/)
[![MITRE ATT\&CK](https://img.shields.io/badge/MITRE_ATT%26CK-Mapped-red?style=for-the-badge)](https://attack.mitre.org/)

**PyLogShield** is a modular, high-throughput **Host-Based Intrusion Prevention System (HIPS)** built in Python. It ingests web server telemetry, processes payloads using mathematical entropy evaluation and statistical anomaly detection algorithms, queries threat intelligence APIs, and enforces OS-level active firewall containment.

---

## 🚀 Key Features

* **🧮 Payload Entropy Analysis:** Evaluates string randomness using **Shannon Information Entropy ($H(X) > 4.5$)** to identify base64 obfuscation, encrypted shellcode, and evasive injection attempts.
* **📊 Volumetric Outlier Detection:** Implements **Modified Z-Scores** via Median Absolute Deviation (MAD) to detect brute-force spikes without relying on rigid static thresholds.
* **🔥 Dynamic Host Isolation:** Automatically executes OS-level firewall rules (`iptables` / `netsh`) for high-severity threats and repeated volumetric breaches.
* **🌐 Threat Intelligence Scoring:** Cross-references malicious source IPs against global threat intelligence APIs (AbuseIPDB) for automated reputation scoring.
* **📊 Wazuh-Inspired SOC Dashboard:** Generates a dynamic HTML/Chart.js console for operational analysis and exports SIEM-ready structured JSON telemetry.

---

## 🏗️ System Architecture

```mermaid
flowchart TD
    A[Web Server Telemetry / access.log] --> B[PyLogShield Engine]
    B --> C{Core Analytics Engine}
    C -->|Regex Patterns| D[OWASP Threat Classifier]
    C -->|Shannon Entropy H(X) > 4.5| E[Payload Obfuscation Detector]
    C -->|Modified Z-Score > 3.5| F[Volumetric Anomaly Engine]
    D & E & F --> G[Threat Intelligence Provider]
    G --> H[SIEM Export / report.json]
    G --> I[Wazuh SOC Console / index.html]
    G -->|Critical Breaches| J[Active Containment Engine]
    J -->|iptables / netsh| K[OS Host Firewall Blocklist]
```

---

## 📄 Mathematical Specifications

### 1. Shannon Information Entropy Calculation

$$
\text{H}(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)
$$

**Baseline Threshold:** Payloads exhibiting an entropy score $H(X) > 4.5$ are automatically flagged for triage.

### 2. Modified Z-Score Outlier Detection

$$
M_i = \frac{0.6745 \cdot (x_i - \tilde{x})}{\text{MAD}}
$$

**Decision Rule:** Source IPs exhibiting $M_i > 3.5$ in failed authentication attempts (HTTP 401) trigger volumetric containment actions.

---

## 📂 Project Structure

```text
PyLogShield/
│── core/
│   │── analytics.py        # Entropy & Modified Z-Score engines
│   │── containment.py      # Host firewall isolation handler
│   └── threat_intel.py     # AbuseIPDB API interface
│── logs/
│   └── access.log          # Raw web server telemetry input
│── .gitignore
│── blocked_ips.txt         # Active firewall containment ledger
│── index.html              # Wazuh-inspired SOC console UI
│── main.py                 # Core framework orchestrator
│── README.md               # Framework documentation
│── report.json             # SIEM export report
└── SPECIFICATIONS.md       # Extended technical design notes
```

---

## 🛠️ Getting Started

### Prerequisites

Python 3.10+
Git

### Installation & Run

```bash
# Clone the repository
git clone https://github.com/ArunkumarAK213/PyLogShield.git

# Navigate to project root
cd PyLogShield

# Execute HIPS engine
python main.py
```

---

## 🔗 Live Console & Documentation

**Interactive SOC Console:** https://arunkumarak213.github.io/PyLogShield/

**Repository:** https://github.com/ArunkumarAK213/PyLogShield
