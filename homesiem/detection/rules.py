"""Detection rules. Each rule inspects events and may raise an alert.

Rules are mapped to MITRE ATT&CK tactics/techniques where applicable,
which is good practice for a real SIEM and documents intent clearly.
"""
from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Optional

from ..schema import Event


@dataclass
class Alert:
    rule: str
    severity: str
    mitre: str
    message: str
    event_id: str
    timestamp: float


class BruteForceLoginRule:
    """Multiple failed logins from one source in a short window.

    MITRE: TA0006 Credential Access / T1110 Brute Force
    Triggers on Windows 4625 events or syslog auth failures.
    """
    mitre = "TA0006 / T1110"

    def __init__(self, threshold: int = 5, window_seconds: int = 120) -> None:
        self.threshold = threshold
        self.window = window_seconds
        self._fails: dict[str, deque[float]] = defaultdict(deque)

    def check(self, event: Event) -> Optional[Alert]:
        is_fail = (event.action == "login_failed" or
                   (event.category == "syslog" and
                    "failed password" in event.message.lower()))
        if not is_fail:
            return None
        key = event.src_ip or event.host or "unknown"
        now = event.timestamp
        bucket = self._fails[key]
        bucket.append(now)
        while bucket and now - bucket[0] > self.window:
            bucket.popleft()
        if len(bucket) >= self.threshold:
            bucket.clear()
            return Alert(
                rule="brute_force_login",
                severity="high",
                mitre=self.mitre,
                message=(f"Possible brute-force: {self.threshold}+ "
                         f"failed logins from {key} within {self.window}s"),
                event_id=event.event_id,
                timestamp=now,
            )
        return None


class NewDeviceRule:
    """A previously unseen device joined the network.

    MITRE: TA0007 Discovery (defender-side asset awareness)
    """
    mitre = "TA0007"

    def check(self, event: Event) -> Optional[Alert]:
        if event.action == "device_joined" and event.severity != "info":
            return Alert(
                rule="new_device_joined",
                severity="medium",
                mitre=self.mitre,
                message=event.message,
                event_id=event.event_id,
                timestamp=event.timestamp,
            )
        return None


class PrivilegedAccountChangeRule:
    """Account creation or privileged group membership change.

    MITRE: TA0003 Persistence / TA0004 Privilege Escalation
    """
    mitre = "TA0003 / TA0004"

    def check(self, event: Event) -> Optional[Alert]:
        if event.action in ("user_created", "group_member_added"):
            return Alert(
                rule="privileged_account_change",
                severity="high",
                mitre=self.mitre,
                message=f"Sensitive account change: {event.action} on {event.host}",
                event_id=event.event_id,
                timestamp=event.timestamp,
            )
        return None


def default_rules() -> list:
    return [BruteForceLoginRule(), NewDeviceRule(), PrivilegedAccountChangeRule()]
