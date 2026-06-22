"""Basic tests for the detection rules (run with: pytest)."""
import time

from homesiem.schema import Event
from homesiem.detection.rules import (
    BruteForceLoginRule, NewDeviceRule, PrivilegedAccountChangeRule,
)


def test_brute_force_triggers_after_threshold():
    rule = BruteForceLoginRule(threshold=3, window_seconds=60)
    now = time.time()
    alerts = []
    for _ in range(3):
        ev = Event(action="login_failed", src_ip="10.0.0.5", timestamp=now)
        a = rule.check(ev)
        if a:
            alerts.append(a)
    assert len(alerts) == 1
    assert alerts[0].rule == "brute_force_login"


def test_brute_force_respects_window():
    rule = BruteForceLoginRule(threshold=3, window_seconds=10)
    base = time.time()
    # spread failures beyond the window -> should not trigger
    for i in range(3):
        ev = Event(action="login_failed", src_ip="10.0.0.9",
                   timestamp=base + i * 60)
        assert rule.check(ev) is None


def test_new_device_rule():
    rule = NewDeviceRule()
    ev = Event(action="device_joined", severity="medium",
               message="New device 192.168.1.50")
    assert rule.check(ev) is not None


def test_privileged_account_change():
    rule = PrivilegedAccountChangeRule()
    ev = Event(action="user_created", host="localhost")
    a = rule.check(ev)
    assert a and a.severity == "high"
