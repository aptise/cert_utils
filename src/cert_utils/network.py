"""Shared HTTP timeout configuration (seconds)."""

import math
import os
from typing import Optional
from typing import Tuple

Timeout = Tuple[float, float]
DEFAULT_TIMEOUT: Timeout = (5.0, 30.0)


def parse_timeout(value: str) -> Timeout:
    """Parse CONNECT,READ seconds; both values must be finite and positive."""
    try:
        connect, read = (float(part.strip()) for part in value.split(","))
    except ValueError:
        raise ValueError("timeout must be CONNECT,READ seconds") from None
    if not all(math.isfinite(v) and v > 0 for v in (connect, read)):
        raise ValueError("timeouts must be finite positive seconds")
    return (connect, read)


def get_timeout(override: Optional[Timeout] = None) -> Timeout:
    """Explicit settings override CERT_UTILS_TIMEOUT, then defaults."""
    if override is not None:
        return parse_timeout("%s,%s" % override)
    value = os.environ.get("CERT_UTILS_TIMEOUT")
    return parse_timeout(value) if value is not None else DEFAULT_TIMEOUT
