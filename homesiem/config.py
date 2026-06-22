"""Loads YAML configuration with sensible defaults."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import yaml


@dataclass
class Config:
    subnet: str = "192.168.1.0/24"
    syslog_host: str = "0.0.0.0"
    syslog_port: int = 5140
    scan_interval: float = 300.0
    db_path: str = "homesiem.db"
    dashboard_host: str = "127.0.0.1"
    dashboard_port: int = 8080
    discord_webhook_url: str = ""
    enable_windows_eventlog: bool = True
    enable_network_discovery: bool = True
    enable_syslog: bool = True

    @classmethod
    def load(cls, path: str = "config.yaml") -> "Config":
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data: dict[str, Any] = yaml.safe_load(fh) or {}
        except FileNotFoundError:
            print(f"[config] {path} not found; using defaults.")
            data = {}
        known = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in data.items() if k in known})
