# PyLogShield Framework Architectural Specifications

## 1. Mathematical Models & Anomaly Detection

### Shannon Information Entropy Calculation
PyLogShield evaluates string randomness across HTTP URIs and payload streams to detect base64 obfuscation, encrypted shellcode, and evasive injection patterns:
$$H(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$
* **Baseline Threshold:** Payloads exhibiting an entropy score $H(X) > 4.5$ are automatically flagged for triage regardless of signature matches.

### Modified Z-Score Volumetric Outlier Detection
To prevent false positives inherent in traditional static thresholds during high-traffic spikes, PyLogShield applies the Median Absolute Deviation (MAD) Modified Z-Score:
$$M_i = \frac{0.6745 \cdot (x_i - \tilde{x})}{\text{MAD}}$$
* **Decision Rule:** Any source IP demonstrating $M_i > 3.5$ in authentication failures (`HTTP 401`) is flagged as a statistical volumetric anomaly and sent to active containment.

## 2. Threat Matrix & MITRE ATT&CK Mapping
| Threat Classification | Algorithmic Method | MITRE ATT&CK | Automated Response |
| :--- | :--- | :--- | :--- |
| **SQL Injection (SQLi)** | Regex Signature + Entropy Evaluation | [T1190] Exploit Public Application | Firewall Isolation |
| **Cross-Site Scripting (XSS)** | Payload Pattern Matching | [T1059.007] JavaScript Execution | Alert & Telemetry Logging |
| **HTTP Brute Force** | Modified Z-Score Outlier Analysis ($M_i > 3.5$) | [T1110.001] Password Guessing | Firewall Isolation |
| **Directory Traversal** | Path Normalization Matching | [T1083] File Discovery | Firewall Isolation |

## 3. Operational Performance Indicators
* **Ingestion Throughput:** $\approx 10,000\text{ events/sec}$ (Streaming line generator).
* **Space Complexity:** $O(1)$ memory allocation.
* **Containment Execution Latency:** $\le 15\text{ ms}$ (Local OS sockets).