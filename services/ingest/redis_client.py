"""
/home/siem/siem-solution/services/ingest/redis_client.py

Назначение:
  - Создание и управление асинхронным Redis-клиентом.
  - Утилита для записи сырых событий в Stream `siem:raw`.
Используемые env-переменные: см. IngestSettings в config.py.
"""

from __future__ import annotations

import logging
from typing import Any, Dict

from redis.asyncio import Redis

from .config import IngestSettings

logger = logging.getLogger(__name__)

RAW_STREAM_KEY = "siem:raw"


def create_redis_client(settings: IngestSettings) -> Redis:
    """Создаёт Redis-клиент с пулом подключений."""
    return Redis(
        host=settings.redis_host,
        port=settings.redis_port,
        db=settings.redis_db,
        password=settings.redis_password,
        decode_responses=True,
    )


async def push_raw_event(redis: Redis, event: Dict[str, Any]) -> str:
    """Записывает сырое событие в Stream `siem:raw`.

    Возвращает ID записи в Stream.
    """
    fields: Dict[str, str] = {}
    for key, value in event.items():
        fields[str(key)] = "" if value is None else str(value)

    stream_id = await redis.xadd(
        RAW_STREAM_KEY,
        fields,
        maxlen=1_000_000,
        approximate=True,
    )
    logger.debug(
        "Pushed event to Redis stream",
        extra={"extra": {"stream": RAW_STREAM_KEY, "id": stream_id}},
    )
    return stream_id
