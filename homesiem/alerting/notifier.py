"""Alert notifier. Default channel: Discord webhook.

The webhook URL is read from config (config.yaml) and is treated as a
SECRET - never commit it. Email is provided as an optional stub.
"""
from __future__ import annotations

import json
import urllib.request
from typing import Optional

from ..detection.rules import Alert

_COLORS = {
    "info": 0x3498DB, "low": 0x2ECC71, "medium": 0xF1C40F,
    "high": 0xE67E22, "critical": 0xE74C3C,
}


class DiscordNotifier:
    def __init__(self, webhook_url: Optional[str]) -> None:
        self.webhook_url = webhook_url

    def send(self, alert: Alert) -> None:
        if not self.webhook_url:
            return  # alerting disabled if no webhook configured
        payload = {
            "embeds": [{
                "title": f"[{alert.severity.upper()}] {alert.rule}",
                "description": alert.message,
                "color": _COLORS.get(alert.severity, 0x95A5A6),
                "fields": [{"name": "MITRE ATT&CK", "value": alert.mitre,
                            "inline": True}],
            }]
        }
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            self.webhook_url, data=data,
            headers={"Content-Type": "application/json"},
        )
        try:
            urllib.request.urlopen(req, timeout=10)
        except Exception as exc:  # never let alerting crash the SIEM
            print(f"[notifier] failed to send Discord alert: {exc}")
