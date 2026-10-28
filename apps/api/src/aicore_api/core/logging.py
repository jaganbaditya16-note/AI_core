"""Logging configuration.

Plain, structured-enough logging for Phase 0. Secrets are never logged: callers
pass ``Settings.safe_summary()`` rather than the settings object.
"""

from __future__ import annotations

import logging
import sys

_LOG_FORMAT = "%(asctime)s %(levelname)-8s %(name)s %(message)s"
_CONFIGURED = False


def configure_logging(level: str = "info") -> None:
    """Configure root logging once per process."""
    global _CONFIGURED
    if _CONFIGURED:
        return

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter(_LOG_FORMAT))

    root = logging.getLogger()
    root.setLevel(level.upper())
    root.addHandler(handler)

    # Access logs are emitted by uvicorn with its own configuration; keep its
    # loggers from double-printing through the root handler.
    for noisy in ("uvicorn.access", "uvicorn.error"):
        logging.getLogger(noisy).propagate = False

    _CONFIGURED = True
