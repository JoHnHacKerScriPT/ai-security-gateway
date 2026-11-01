"""Secure reverse-proxying to upstream AI provider APIs.

`forward_with_retry` is the one place that talks to Anthropic/OpenAI: TLS is
handled by httpx against the real provider hostnames (TLS termination for
*inbound* traffic is done by whatever sits in front of this gateway, e.g. a
load balancer/ingress — this function is the *outbound* leg). Retries only
happen for transient failures (connect errors, timeouts, 5xx) — never for
4xx, since retrying a bad request just wastes quota against the provider.
"""
from __future__ import annotations

import asyncio
import logging

import httpx

logger = logging.getLogger("gateway.upstream")

_RETRYABLE_STATUS = {502, 503, 504}


async def forward_with_retry(
    client: httpx.AsyncClient,
    *,
    method: str,
    url: str,
    headers: dict[str, str],
    json_body: dict,
    timeout: float,
    max_retries: int,
) -> httpx.Response:
    attempt = 0
    while True:
        try:
            response = await client.request(method, url, headers=headers, json=json_body, timeout=timeout)
        except (httpx.ConnectError, httpx.ConnectTimeout, httpx.ReadTimeout, httpx.PoolTimeout) as exc:
            if attempt >= max_retries:
                logger.warning("upstream request failed after %s retries: %s", attempt, exc)
                raise
            await asyncio.sleep(_backoff_seconds(attempt))
            attempt += 1
            continue

        if response.status_code in _RETRYABLE_STATUS and attempt < max_retries:
            await asyncio.sleep(_backoff_seconds(attempt))
            attempt += 1
            continue

        return response


def _backoff_seconds(attempt: int) -> float:
    return min(0.25 * (2 ** attempt), 4.0)
