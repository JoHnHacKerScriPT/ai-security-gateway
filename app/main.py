"""AI Security Gateway — FastAPI async entrypoint.

Wires together every layer: async httpx upstream client, JWT/API-key auth,
Redis token-bucket rate limiting (Layer 1), input guardrails (Layer 2),
secure routing to Anthropic/OpenAI (Layer 3), output inspection (Layer 4),
and structured logging + Prometheus metrics (Layer 5).
"""
from __future__ import annotations

from contextlib import asynccontextmanager

import httpx
from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse

from app.core.config import get_settings
from app.core.redis_client import close_redis, get_redis
from app.core.secrets import SecretNotConfigured
from app.core.security import Principal, get_current_principal
from app.guardrails.exceptions import GuardrailViolation
from app.middleware.rate_limit import RateLimitMiddleware
from app.observability.logging import configure_logging, log_security_event
from app.observability.metrics import THREATS_BLOCKED_TOTAL, MetricsMiddleware, render_latest
from app.routers.proxy import router as proxy_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    configure_logging()
    app.state.http_client = httpx.AsyncClient(timeout=settings.upstream_timeout_seconds)
    app.state.redis = get_redis()
    yield
    await app.state.http_client.aclose()
    await close_redis()


def create_app() -> FastAPI:
    app = FastAPI(
        title="AI Security Gateway",
        description="Production-grade reverse proxy in front of AI provider APIs.",
        version="0.1.0",
        lifespan=lifespan,
    )

    # Middleware order matters: Starlette runs the LAST-added middleware
    # outermost. We add RateLimitMiddleware first and MetricsMiddleware
    # second so Metrics wraps everything (including 429 responses) and
    # Redis is only consulted after that outer bookkeeping.
    app.add_middleware(RateLimitMiddleware, redis=get_redis())
    app.add_middleware(MetricsMiddleware)

    app.include_router(proxy_router)

    @app.exception_handler(GuardrailViolation)
    async def guardrail_violation_handler(request: Request, exc: GuardrailViolation):
        THREATS_BLOCKED_TOTAL.labels(threat_type=exc.code).inc()
        log_security_event(exc.code, message=exc.message, path=request.url.path, **exc.details)
        return JSONResponse(
            status_code=400,
            content={"error": exc.code, "message": exc.message, "details": exc.details},
        )

    @app.exception_handler(SecretNotConfigured)
    async def secret_not_configured_handler(request: Request, exc: SecretNotConfigured):
        return JSONResponse(
            status_code=503,
            content={"error": "secret_not_configured", "message": str(exc)},
        )

    @app.get("/health", response_class=PlainTextResponse)
    async def health() -> str:
        return "ok"

    @app.get("/metrics")
    async def metrics():
        return render_latest()

    @app.get("/v1/whoami")
    async def whoami(principal: Principal = Depends(get_current_principal)):
        """Demo protected endpoint proving auth + rate limiting work end to
        end, independent of any specific upstream provider."""
        return {"subject": principal.subject, "auth_method": principal.auth_method}

    return app


app = create_app()
