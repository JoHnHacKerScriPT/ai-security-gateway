"""Secure routing to Anthropic & OpenAI (Layer 3), with Layer 2 input
guardrails applied before forwarding and Layer 4 output inspection applied
to whatever comes back, before it ever reaches the caller.
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Body, Depends, HTTPException, Request

from app.core.config import get_settings
from app.core.message_payload import sanitize_user_messages
from app.core.secrets import get_anthropic_api_key, get_openai_api_key
from app.core.security import Principal, get_current_principal
from app.core.upstream import forward_with_retry
from app.guardrails.output_inspection import inspect_output
from app.observability.logging import log_security_event
from app.observability.metrics import THREATS_BLOCKED_TOTAL

logger = logging.getLogger("gateway.proxy")

router = APIRouter(prefix="/v1", tags=["proxy"])


_ANTHROPIC_BODY_EXAMPLE = {
    "model": "claude-3-5-sonnet-20241022",
    "max_tokens": 100,
    "messages": [{"role": "user", "content": "Hello, Claude!"}],
}


@router.post("/anthropic/messages")
async def proxy_anthropic_messages(
    request: Request,
    body: dict = Body(..., openapi_examples={"basic": {"summary": "Basic message", "value": _ANTHROPIC_BODY_EXAMPLE}}),
    principal: Principal = Depends(get_current_principal),
):
    settings = get_settings()

    sanitized_body, reports = sanitize_user_messages(body)
    for report in reports:
        if report.pii_redacted:
            logger.info("pii_redacted principal=%s kinds=%s", principal.subject, report.pii_kinds)

    client = request.app.state.http_client
    response = await forward_with_retry(
        client,
        method="POST",
        url=f"{settings.anthropic_base_url}/v1/messages",
        headers={
            "x-api-key": get_anthropic_api_key(),
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        },
        json_body=sanitized_body,
        timeout=settings.upstream_timeout_seconds,
        max_retries=settings.upstream_max_retries,
    )

    return _inspect_and_return(response, principal)


_OPENAI_BODY_EXAMPLE = {
    "model": "gpt-4o-mini",
    "messages": [{"role": "user", "content": "Hello!"}],
}


@router.post("/openai/chat/completions")
async def proxy_openai_chat_completions(
    request: Request,
    body: dict = Body(..., openapi_examples={"basic": {"summary": "Basic message", "value": _OPENAI_BODY_EXAMPLE}}),
    principal: Principal = Depends(get_current_principal),
):
    settings = get_settings()

    sanitized_body, reports = sanitize_user_messages(body)
    for report in reports:
        if report.pii_redacted:
            logger.info("pii_redacted principal=%s kinds=%s", principal.subject, report.pii_kinds)

    client = request.app.state.http_client
    response = await forward_with_retry(
        client,
        method="POST",
        url=f"{settings.openai_base_url}/v1/chat/completions",
        headers={
            "Authorization": f"Bearer {get_openai_api_key()}",
            "content-type": "application/json",
        },
        json_body=sanitized_body,
        timeout=settings.upstream_timeout_seconds,
        max_retries=settings.upstream_max_retries,
    )

    return _inspect_and_return(response, principal)


def _inspect_and_return(response, principal: Principal):
    if response.status_code >= 500:
        raise HTTPException(status_code=502, detail="Upstream provider error.")

    try:
        payload = response.json()
    except ValueError:
        # Non-JSON upstream response (shouldn't normally happen) — pass the
        # status through without attempting output inspection on it.
        raise HTTPException(status_code=502, detail="Upstream returned a non-JSON response.")

    if response.status_code >= 400:
        # Don't run output guardrails on the provider's own error payloads;
        # just relay the failure as-is.
        raise HTTPException(status_code=response.status_code, detail=payload)

    finding = inspect_output(payload)
    if finding.blocked:
        for reason in finding.reasons:
            THREATS_BLOCKED_TOTAL.labels(threat_type=reason).inc()
        log_security_event(
            "output_blocked", principal=principal.subject, reasons=finding.reasons
        )
        raise HTTPException(
            status_code=502,
            detail={
                "error": "output_blocked_by_guardrail",
                "message": "The upstream response was blocked because it appears to contain a "
                "leaked secret or dangerous code.",
                "reasons": finding.reasons,
            },
        )

    return payload
