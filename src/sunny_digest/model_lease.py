"""A model grant expires on elapsed host time and on a suspend/resume gap."""
from __future__ import annotations

import math
import time


def boottime():
    # Linux CLOCK_BOOTTIME includes suspend; macOS fallback is for offline tests.
    return time.clock_gettime(time.CLOCK_BOOTTIME) if hasattr(time, "CLOCK_BOOTTIME") else time.monotonic()


def validate_lease(value):
    if not isinstance(value, dict) or set(value) != {"expires_mono", "expires_boot"}:
        raise ValueError("model lease fields are invalid")
    if any(type(deadline) not in (int, float) or not math.isfinite(deadline) or deadline <= 0
           for deadline in value.values()):
        raise ValueError("model lease deadline is invalid")
    return value


def remaining_lease(value, *, monotonic=None, boot_clock=None):
    mono = value["expires_mono"] - (monotonic or time.monotonic)()
    boot = value["expires_boot"] - (boot_clock or boottime)()
    # A fresh receiver gate is required after suspend, even inside the window.
    return 0.0 if abs(mono - boot) > 1 else max(0.0, min(mono, boot))


def require_lease(value):
    remaining = remaining_lease(value)
    if remaining <= 0:
        raise TimeoutError("model grant expired or host suspended")
    return remaining
