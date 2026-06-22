"""Normalized event schema shared by all collectors.

Every collector converts its raw input into an Event so the detection
engine, storage layer, and dashboard all speak the same language.
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Any, Optional


@dataclass
class Event:
    # Core identity
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = field(default_factory=time.time)

    # Where it came from
    source: str = "unknown"          # e.g. "syslog", "windows_eventlog", "network"
    host: Optional[str] = None       # hostname or IP that generated the event
    src_ip: Optional[str] = None
    dest_ip: Optional[str] = None

    # What happened
    category: str = "generic"        # e.g. "authentication", "network", "process"
    action: Optional[str] = None     # e.g. "login_failed", "device_joined"
    severity: str = "info"           # info | low | medium | high | critical
    message: str = ""

    # Free-form extra fields specific to the source
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
