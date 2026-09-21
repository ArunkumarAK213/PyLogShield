import json
import os
import urllib.request


class ThreatIntelProvider:

    def __init__(self):
        self.abuse_api_key = os.getenv("ABUSEIPDB_API_KEY", "")

    def check_ip_reputation(self, ip: str) -> dict:
        """Queries AbuseIPDB API for global abuse confidence score."""
        if ip.startswith(("127.", "10.", "192.168.")):
            return {
                "score": 0,
                "verdict": "Internal Network",
                "country": "Private LAN",
            }

        if not self.abuse_api_key:
            return {
                "score": 0,
                "verdict": "Unchecked (No API Key)",
                "country": "Unknown",
            }

        try:
            url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}"
            req = urllib.request.Request(
                url,
                headers={
                    "Key": self.abuse_api_key,
                    "Accept": "application/json",
                },
            )
            with urllib.request.urlopen(req, timeout=3) as resp:
                data = json.loads(resp.read().decode())["data"]
                score = data.get("abuseConfidenceScore", 0)
                return {
                    "score": score,
                    "verdict": "MALICIOUS" if score > 50 else "CLEAN",
                    "country": data.get("countryCode", "Unknown"),
                }
        except Exception:
            return {
                "score": 0,
                "verdict": "Lookup Error",
                "country": "Unknown",
            }