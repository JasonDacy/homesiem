"""Detection engine: routes every event through all rules and persists alerts."""
from __future__ import annotations

from typing import Callable, Optional

from ..schema import Event
from ..storage import Storage
from .rules import Alert, default_rules


class DetectionEngine:
    def __init__(self, storage: Storage,
                 on_alert: Optional[Callable[[Alert], None]] = None) -> None:
        self.storage = storage
        self.rules = default_rules()
        self.on_alert = on_alert

    def process(self, event: Event) -> None:
        self.storage.store_event(event)
        for rule in self.rules:
            alert = rule.check(event)
            if alert:
                self.storage.store_alert(
                    rule=alert.rule, severity=alert.severity, mitre=alert.mitre,
                    message=alert.message, event_id=alert.event_id,
                    timestamp=alert.timestamp,
                )
                if self.on_alert:
                    self.on_alert(alert)
