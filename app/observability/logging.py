"""Structured JSON security logging (Layer 5).

Every security-relevant event — blocked prompt injections, DLP/PII hits,
rate-limit triggers, blocked output — is logged as a single structured JSON
line, ready to ship straight into a SIEM (Microsoft Sentinel, Splunk, etc.)
via a log forwarder with no custom parsing required.

`configure_logging()` wires BOTH structlog and the stdlib `logging` module
(used by other modules via `logging.getLogger(...)`) through the same JSON
renderer, so every log line in the process — not just structlog call sites
— comes out in the same shape.
"""
from __future__ import annotations

import logging
import sys

import structlog

from app.core.config import get_settings

SECURITY_EVENT_LOGGER_NAME = "gateway.security"


def configure_logging() -> None:
    settings = get_settings()
    level = getattr(logging, settings.log_level.upper(), logging.INFO)

    shared_processors = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
    ]

    structlog.configure(
        processors=shared_processors + [structlog.stdlib.ProcessorFormatter.wrap_for_formatter],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    formatter = structlog.stdlib.ProcessorFormatter(
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            structlog.processors.JSONRenderer(),
        ],
        foreign_pre_chain=shared_processors,
    )

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)

    root_logger = logging.getLogger()
    root_logger.handlers = [handler]
    root_logger.setLevel(level)


def get_security_logger() -> structlog.stdlib.BoundLogger:
    return structlog.get_logger(SECURITY_EVENT_LOGGER_NAME)


def log_security_event(event: str, **fields) -> None:
    """Emit one structured security event, e.g.:

        log_security_event("prompt_injection_blocked", principal="alice",
                            score=0.9, patterns=["dan_mode"])
    """
    get_security_logger().warning(event, **fields)
