import math
import re
from collections import Counter


def calculate_shannon_entropy(payload: str) -> float:
    """Calculates Shannon Entropy H(X) of an HTTP payload string.

    Higher entropy indicates obfuscated, encrypted, or compressed malicious
    data.
    """
    if not payload:
        return 0.0

    length = len(payload)
    counts = Counter(payload)
    entropy = 0.0

    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return round(entropy, 2)


def calculate_modified_z_scores(data_points: list) -> list:
    """Calculates Modified Z-Scores using Median Absolute Deviation (MAD).

    Detects volumetric rate anomalies (e.g., brute-force or application DDoS).
    """
    if not data_points or len(data_points) < 3:
        return [0.0] * len(data_points)

    sorted_points = sorted(data_points)
    n = len(sorted_points)
    median = (
        sorted_points[n // 2]
        if n % 2 != 0
        else (sorted_points[n // 2 - 1] + sorted_points[n // 2]) / 2.0
    )

    mad = sorted([abs(x - median) for x in data_points])[n // 2]
    if mad == 0:
        return [0.0] * len(data_points)

    return [
        round(0.6745 * (x - median) / mad, 2) for x in data_points
    ]


THREAT_PATTERNS = {
    "SQL Injection (SQLi)": {
        "pattern": re.compile(
            r"(\%27)|(\')|(\-\-)|(\%23)|(union.*select)|(select.*from)",
            re.IGNORECASE,
        ),
        "severity": "CRITICAL",
        "mitre_id": "T1190",
    },
    "Cross-Site Scripting (XSS)": {
        "pattern": re.compile(
            r"(<script>)|(\%3Cscript\%3E)|(javascript:)|(onerror=)",
            re.IGNORECASE,
        ),
        "severity": "HIGH",
        "mitre_id": "T1059.007",
    },
    "Directory Traversal": {
        "pattern": re.compile(
            r"(\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e\/)", re.IGNORECASE
        ),
        "severity": "HIGH",
        "mitre_id": "T1083",
    },
}