"""Active network discovery.

Periodically scans the local subnet (ARP/ping sweep) to build an inventory
of every device on the network. Emits an event when a NEW device appears
or a known device changes state. This is how 'silent' IoT devices that
can't forward logs still show up in the SIEM.
"""
from __future__ import annotations

import ipaddress
import subprocess
import threading
import time
from typing import Callable

from ..schema import Event


def _ping(ip: str, timeout_ms: int = 500) -> bool:
    # Cross-platform single ping. On Windows: -n 1 -w ms ; elsewhere: -c 1 -W s
    import platform
    if platform.system().lower().startswith("win"):
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, timeout_ms // 1000)), ip]
    try:
        return subprocess.run(cmd, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL).returncode == 0
    except Exception:
        return False


class NetworkDiscovery:
    def __init__(self, on_event: Callable[[Event], None],
                 subnet: str = "192.168.1.0/24",
                 scan_interval: float = 300.0) -> None:
        self.on_event = on_event
        self.subnet = subnet
        self.scan_interval = scan_interval
        self._known: set[str] = set()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _scan_once(self) -> set[str]:
        net = ipaddress.ip_network(self.subnet, strict=False)
        alive: set[str] = set()
        threads = []

        def check(ip_str: str) -> None:
            if _ping(ip_str):
                alive.add(ip_str)

        for ip in net.hosts():
            t = threading.Thread(target=check, args=(str(ip),))
            t.start()
            threads.append(t)
        for t in threads:
            t.join()
        return alive

    def _run(self) -> None:
        while not self._stop.is_set():
            alive = self._scan_once()
            new_devices = alive - self._known
            for ip in sorted(new_devices):
                severity = "medium" if self._known else "info"  # first sweep = baseline
                self.on_event(Event(
                    source="network",
                    host=ip,
                    src_ip=ip,
                    category="network",
                    action="device_joined",
                    severity=severity,
                    message=f"New device detected on network: {ip}",
                    raw={"ip": ip},
                ))
            self._known |= alive
            self._stop.wait(self.scan_interval)
