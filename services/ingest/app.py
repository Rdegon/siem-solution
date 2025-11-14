"""
/home/siem/siem-solution/services/ingest/app.py

Назначение:
  - HTTP/JSON ingest (FastAPI) + health-check.
  - Запуск TCP syslog-сервера.
  - Публикация всех событий в Redis Stream `siem:raw`.

Используемые env-переменные: см. IngestSettings в config.py.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

from fastapi import Body, FastAPI, HTTPException, Request
from redis.asyncio import Redis

from .config import IngestSettings
from .logging_conf import configure_logging
from .redis_client import create_redis_client, push_raw_event
from .syslog_server import create_syslog_server

logger = logging.getLogger(__name__)

_settings: IngestSettings | None = None
_redis: Redis | None = None
_syslog_server = None  # type: ignore[var-annotated]


def _get_settings() -> IngestSettings:
    global _settings
    if _settings is None:
        _settings = IngestSettings.load()
    return _settings


def _get_redis() -> Redis:
    global _redis
    if _redis is None:
        raise RuntimeError("Redis client not initialized")
    return _redis


app = FastAPI(title="SIEM Ingest Service", version="0.1.0")


@app.on_event("startup")
async def on_startup() -> None:
    configure_logging()
    settings = _get_settings()

    logger.info(
        "Starting SIEM Ingest Service",
        extra={"extra": {"env": settings.env, "instance": settings.instance_name}},
    )

    global _redis, _syslog_server
    _redis = create_redis_client(settings)
    _syslog_server = await create_syslog_server(settings, _redis)


@app.on_event("shutdown")
async def on_shutdown() -> None:
    global _redis, _syslog_server

    if _syslog_server is not None:
        await _syslog_server.stop()

    if _redis is not None:
        await _redis.close()
        _redis = None


@app.get("/health")
async def health() -> dict:
    """Проверка состояния сервиса и Redis."""
    settings = _get_settings()
    redis = _get_redis()

    try:
        pong = await redis.ping()
    except Exception as exc:  # noqa: BLE001
        logger.error(
            "Redis ping failed",
            extra={"extra": {"error": str(exc)}},
        )
        raise HTTPException(status_code=503, detail="redis_unhealthy") from exc

    return {
        "status": "ok",
        "env": settings.env,
        "instance": settings.instance_name,
        "redis": "ok" if pong else "failed",
    }


@app.post("/ingest/json")
async def ingest_json(
    payload: Any = Body(...),
    request: Request,
) -> dict:
    """Принимает JSON (объект или список объектов) и пишет в Redis Stream.

    Ожидается:
      - объект: { ... }
      - список объектов: [ { ... }, { ... } ]
    """
    redis = _get_redis()
    _settings = _get_settings()  # пока просто, чтобы не ругался линтер

    # Нормализуем в список
    if isinstance(payload, list):
        events: List[Any] = payload
    else:
        events = [payload]

    # Проверяем, что каждый элемент — словарь
    if not all(isinstance(e, dict) for e in events):
        raise HTTPException(status_code=400, detail="payload_must_be_object_or_list")

    source_ip = request.client.host if request.client else ""
    source_type = "http_json"

    count = 0
    for raw in events:
        event: Dict[str, Any] = dict(raw)
        event.setdefault("source", source_ip)
        event.setdefault("source_type", source_type)

        await push_raw_event(redis, event)
        count += 1

    logger.info(
        "Ingested events via HTTP",
        extra={
            "extra": {
                "count": count,
                "source_ip": source_ip,
                "path": "/ingest/json",
            }
        },
    )

    return {"status": "ok", "ingested": count}
