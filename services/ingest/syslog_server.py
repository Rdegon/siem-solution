"""
/home/siem/siem-solution/services/ingest/syslog_server.py

Назначение:
  - Простой TCP syslog-сервер (строки RFC3164/5424-подобные).
  - Каждая строка пушится в Redis Stream `siem:raw`.
Используемые env-переменные: см. IngestSettings в config.py.
"""

from __future__ import annotations

import asyncio
import logging

from redis.asyncio import Redis

from .config import IngestSettings
from .redis_client import push_raw_event

logger = logging.getLogger(__name__)


class SyslogTcpServer:
    """Syslog TCP-сервер, интегрированный с asyncio."""

    def __init__(self, settings: IngestSettings, redis: Redis) -> None:
        self._settings = settings
        self._redis = redis
        self._server: asyncio.AbstractServer | None = None

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._handle_client,
            host=self._settings.ingest_syslog_host,
            port=self._settings.ingest_syslog_port,
        )
        addr = ", ".join(str(sock.getsockname()) for sock in (self._server.sockets or []))
        logger.info(
            "Syslog TCP server started",
            extra={"extra": {"listen": addr}},
        )

    async def stop(self) -> None:
        if self._server is None:
            return
        self._server.close()
        await self._server.wait_closed()
        logger.info("Syslog TCP server stopped")

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        peername = writer.get_extra_info("peername")
        host: str | None = None
        port: int | None = None
        if isinstance(peername, tuple) and len(peername) >= 2:
            host = str(peername[0])
            port = int(peername[1])

        logger.info(
            "Syslog client connected",
            extra={"extra": {"peer_host": host, "peer_port": port}},
        )

        try:
            while True:
                line = await reader.readline()
                if not line:
                    break

                msg = line.decode(errors="replace").rstrip("\r\n")
                if not msg:
                    continue

                event = {
                    "source": host or "",
                    "source_type": "syslog",
                    "message": msg,
                }

                try:
                    await push_raw_event(self._redis, event)
                except Exception as exc:  # noqa: BLE001
                    logger.error(
                        "Failed to push syslog message to Redis",
                        extra={
                            "extra": {
                                "error": str(exc),
                                "peer_host": host,
                                "peer_port": port,
                            }
                        },
                    )
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:  # noqa: BLE001
                pass

            logger.info(
                "Syslog client disconnected",
                extra={"extra": {"peer_host": host, "peer_port": port}},
            )


async def create_syslog_server(settings: IngestSettings, redis: Redis) -> SyslogTcpServer:
    server = SyslogTcpServer(settings, redis)
    await server.start()
    return server
