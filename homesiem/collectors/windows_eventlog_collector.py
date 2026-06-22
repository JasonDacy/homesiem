"""Windows Event Log collector (Security channel).

Reads security events from the local Windows machine using pywin32 and
normalizes the high-value ones. Key event IDs:
    4624 - successful logon
    4625 - failed logon (brute-force signal)  [MITRE T1110 / TA0006]
    4688 - new process created
    4720 - user account created
    4728 - member added to security-enabled group
Reference: Microsoft Learn event-4625 documentation.
"""
from __future__ import annotations

import threading
import time
from typing import Callable

from ..schema import Event

try:
    import win32evtlog  # type: ignore
    _HAVE_WIN32 = True
except ImportError:  # so the module imports fine on non-Windows dev machines
    _HAVE_WIN32 = False

_INTERESTING = {
    4624: ("authentication", "login_success", "info"),
    4625: ("authentication", "login_failed", "medium"),
    4688: ("process", "process_created", "info"),
    4720: ("account", "user_created", "high"),
    4728: ("account", "group_member_added", "high"),
}


class WindowsEventLogCollector:
    def __init__(self, on_event: Callable[[Event], None],
                 channel: str = "Security", poll_interval: float = 5.0) -> None:
        self.on_event = on_event
        self.channel = channel
        self.poll_interval = poll_interval
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> None:
        if not _HAVE_WIN32:
            print("[windows_eventlog] pywin32 not available - collector disabled "
                  "(this is expected when developing off-Windows).")
            return
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _run(self) -> None:
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        handle = win32evtlog.OpenEventLog(None, self.channel)
        seen_record = win32evtlog.GetNumberOfEventLogRecords(handle)
        while not self._stop.is_set():
            events = win32evtlog.ReadEventLog(handle, flags, 0)
            for ev in events or []:
                code = ev.EventID & 0xFFFF
                if code not in _INTERESTING:
                    continue
                category, action, severity = _INTERESTING[code]
                self.on_event(Event(
                    source="windows_eventlog",
                    host="localhost",
                    category=category,
                    action=action,
                    severity=severity,
                    message=f"Windows Event {code}: {action}",
                    raw={"event_id": code,
                         "strings": list(ev.StringInserts or [])},
                ))
            time.sleep(self.poll_interval)
