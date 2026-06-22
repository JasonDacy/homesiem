"""UDP/TCP syslog listener.

Other devices on your LAN (router, Linux/Mac machines, network gear) are
configured to forward their logs here. We parse the basic RFC3164/5424
priority and turn each line into a normalized Event.
"""
from __future__ import annotations

import re
import socketserver
import threading
from typing import Callable

from ..schema import Event

# <PRI> at the start of a syslog message encodes facility*8 + severity
_PRI_RE = re.compile(r"^<(\d+)>")

# Map syslog numeric severity (0-7) to our severity labels
_SEVERITY_MAP = {
    0: "critical", 1: "critical", 2: "critical", 3: "high",
    4: "medium", 5: "low", 6: "info", 7: "info",
}


def _parse_priority(line: str) -> tuple[str, str]:
    m = _PRI_RE.match(line)
    if not m:
        return "info", line
    pri = int(m.group(1))
    sev = pri & 0x07
    return _SEVERITY_MAP.get(sev, "info"), line[m.end():]


class _Handler(socketserver.BaseRequestHandler):
    on_event: Callable[[Event], None]

    def handle(self) -> None:
        data = self.request[0] if isinstance(self.request, tuple) else self.request.recv(8192)
        text = data.decode("utf-8", errors="replace").strip()
        if not text:
            return
        severity, body = _parse_priority(text)
        event = Event(
            source="syslog",
            host=self.client_address[0],
            src_ip=self.client_address[0],
            category="syslog",
            severity=severity,
            message=body,
            raw={"raw_line": text},
        )
        self.on_event(event)


class SyslogCollector:
    def __init__(self, on_event: Callable[[Event], None],
                 host: str = "0.0.0.0", port: int = 5140) -> None:
        # Default to 5140 (unprivileged); use 514 if you run with privileges.
        self.host, self.port = host, port
        handler = type("BoundHandler", (_Handler,), {"on_event": staticmethod(on_event)})
        self._server = socketserver.UDPServer((host, port), handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()
