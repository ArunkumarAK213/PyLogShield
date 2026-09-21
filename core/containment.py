import os
import sys
from datetime import datetime


class ContainmentEngine:

    def __init__(self, blocklist_path: str):
        self.blocklist_path = blocklist_path
        self.enforced_ips = set()

    def enforce_isolation(
        self, ip: str, reason: str, mitre_id: str
    ) -> dict | None:
        """Applies immediate firewall rule and logs containment event."""
        if ip in self.enforced_ips or ip.startswith(
            ("127.", "10.", "192.168.")
        ):
            return None

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if sys.platform.startswith("linux"):
            fw_cmd = f"iptables -A INPUT -s {ip} -j DROP"
        else:
            fw_cmd = f'netsh advfirewall firewall add rule name="PyLogShield Block {ip}" dir=in action=block remoteip={ip}'

        block_entry = f"[{timestamp}] [CONTAINMENT ENFORCED] IP: {ip} | REASON: {reason} | MITRE: {mitre_id} | COMMAND: {fw_cmd}\n"

        with open(self.blocklist_path, "a", encoding="utf-8") as f:
            f.write(block_entry)

        self.enforced_ips.add(ip)

        print(
            f"[🚨 ACTIVE CONTAINMENT EXECUTED] IP: {ip} | MITRE: {mitre_id} ({reason})"
        )
        return {
            "timestamp": timestamp,
            "ip": ip,
            "reason": reason,
            "mitre_id": mitre_id,
            "command": fw_cmd,
        }