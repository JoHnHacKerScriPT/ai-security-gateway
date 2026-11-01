"""Dev-only stand-in for Redis — NOT for production.

Runs an in-memory, Redis-protocol-compatible server on 127.0.0.1:6379 using
`fakeredis` (already in requirements-dev.txt, so nothing new to install or
download). It speaks the real RESP wire protocol over a real TCP socket, so
the gateway's actual `redis.asyncio.Redis` client — and its Lua
token-bucket script — work against it exactly as they would against a real
Redis server.

Use this only for local development on a machine without Docker/Memurai.
For anything resembling production, use a real Redis instance instead.

Usage:
    python scripts/run_fake_redis.py
"""
from __future__ import annotations

from fakeredis import TcpFakeServer

HOST = "127.0.0.1"
PORT = 6379

if __name__ == "__main__":
    server = TcpFakeServer((HOST, PORT))
    print(f"[fake-redis] listening on {HOST}:{PORT} (dev only) — Ctrl+C to stop")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[fake-redis] stopped")
