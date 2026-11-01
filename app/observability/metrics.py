"""Prometheus metrics (Layer 5): latency, request volume, threat counts,
and blocked-attack counts, scraped from `/metrics`.
"""
from __future__ import annotations

import time

from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

REQUEST_COUNT = Counter(
    "gateway_requests_total",
    "Total HTTP requests handled by the gateway",
    ["method", "path", "status"],
)

REQUEST_LATENCY_SECONDS = Histogram(
    "gateway_request_latency_seconds",
    "Request latency in seconds",
    ["method", "path"],
)

THREATS_BLOCKED_TOTAL = Counter(
    "gateway_threats_blocked_total",
    "Blocked security threats by type",
    ["threat_type"],
)

RATE_LIMIT_TRIGGERED_TOTAL = Counter(
    "gateway_rate_limit_triggered_total",
    "Number of requests rejected for exceeding the rate limit",
)


def render_latest() -> Response:
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)


class MetricsMiddleware(BaseHTTPMiddleware):
    """Records request volume and latency for every request. Cardinality is
    kept bounded by using the *route template* (e.g. `/v1/anthropic/messages`)
    rather than the raw path when FastAPI has matched one."""

    async def dispatch(self, request: Request, call_next):
        start = time.perf_counter()
        response = await call_next(request)
        duration = time.perf_counter() - start

        route = request.scope.get("route")
        path_label = getattr(route, "path", request.url.path)

        REQUEST_COUNT.labels(method=request.method, path=path_label, status=response.status_code).inc()
        REQUEST_LATENCY_SECONDS.labels(method=request.method, path=path_label).observe(duration)
        return response
