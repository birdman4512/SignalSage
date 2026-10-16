"""Small dependency-free logging, health, and task supervision helpers."""

import asyncio
import json
import logging
import os
import sys
import time
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any


class JsonFormatter(logging.Formatter):
    """Emit one machine-readable JSON object per log record."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "event": record.getMessage(),
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


def configure_logging() -> None:
    """Configure stdout logging; set LOG_FORMAT=json for structured output."""
    handler = logging.StreamHandler(sys.stdout)
    if os.getenv("LOG_FORMAT", "text").lower() == "json":
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(logging.Formatter("%(asctime)s %(name)s %(levelname)s %(message)s"))
    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO").upper(), handlers=[handler], force=True
    )


async def supervise(
    name: str,
    run: Callable[[], Awaitable[None]],
    *,
    max_backoff: float = 60,
) -> None:
    """Restart a failed long-running component with bounded exponential backoff."""
    delay = 1.0
    logger = logging.getLogger(__name__)
    while True:
        try:
            await run()
            logger.warning("component_stopped name=%s", name)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("component_failed name=%s retry_seconds=%s", name, delay)
        await asyncio.sleep(delay)
        delay = min(max_backoff, delay * 2)


class HealthServer:
    """Minimal HTTP liveness/readiness and JSON metrics endpoint."""

    def __init__(self, status: Callable[[], dict] | None = None):
        self.status = status or (lambda: {})
        self.ready = False
        self.started = time.time()
        self._server: asyncio.Server | None = None

    async def start(self, host: str = "0.0.0.0", port: int = 8080) -> None:
        self._server = await asyncio.start_server(self._handle, host, port)

    async def close(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            request = await asyncio.wait_for(reader.readline(), timeout=2)
            path = request.decode("ascii", errors="ignore").split(" ")[1]
        except (IndexError, TimeoutError):
            path = ""
        code = 200
        if path == "/health/live":
            body = {"status": "alive", "uptime_seconds": round(time.time() - self.started, 1)}
        elif path == "/health/ready":
            code = 200 if self.ready else 503
            body = {"status": "ready" if self.ready else "starting"}
        elif path == "/metrics":
            body = self.status()
        else:
            code, body = 404, {"error": "not found"}
        encoded = json.dumps(body, default=str).encode()
        reason = "OK" if code == 200 else "Service Unavailable" if code == 503 else "Not Found"
        writer.write(
            f"HTTP/1.1 {code} {reason}\r\nContent-Type: application/json\r\n"
            f"Content-Length: {len(encoded)}\r\nConnection: close\r\n\r\n".encode()
            + encoded
        )
        await writer.drain()
        writer.close()
        await writer.wait_closed()
