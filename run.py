"""HomeSIEM entry point. Wires collectors -> detection engine -> storage,
sends alerts to Discord, and serves the dashboard.

Usage:  python run.py
"""
from __future__ import annotations

import signal
import sys

from homesiem.config import Config
from homesiem.storage import Storage
from homesiem.detection.engine import DetectionEngine
from homesiem.detection.rules import Alert
from homesiem.alerting.notifier import DiscordNotifier
from homesiem.collectors.syslog_collector import SyslogCollector
from homesiem.collectors.windows_eventlog_collector import WindowsEventLogCollector
from homesiem.collectors.network_discovery import NetworkDiscovery
from homesiem.dashboard.app import create_app


def main() -> None:
    cfg = Config.load()
    storage = Storage(cfg.db_path)
    notifier = DiscordNotifier(cfg.discord_webhook_url)

    def on_alert(alert: Alert) -> None:
        print(f"[ALERT] {alert.severity.upper()} {alert.rule}: {alert.message}")
        notifier.send(alert)

    engine = DetectionEngine(storage, on_alert=on_alert)
    collectors = []

    if cfg.enable_syslog:
        collectors.append(SyslogCollector(engine.process,
                                      cfg.syslog_host, cfg.syslog_port))
    if cfg.enable_windows_eventlog:
        collectors.append(WindowsEventLogCollector(engine.process))
    if cfg.enable_network_discovery:
        collectors.append(NetworkDiscovery(engine.process,
                                       subnet=cfg.subnet,
                                       scan_interval=cfg.scan_interval))

    for c in collectors:
        c.start()
    print(f"[homesiem] {len(collectors)} collector(s) running.")

    def shutdown(*_):
        print("\n[homesiem] shutting down...")
        for c in collectors:
            try:
                c.stop()
            except Exception:
                pass
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)

    app = create_app(storage)
    print(f"[homesiem] dashboard at http://{cfg.dashboard_host}:{cfg.dashboard_port}")
    app.run(host=cfg.dashboard_host, port=cfg.dashboard_port)


if __name__ == "__main__":
    main()
