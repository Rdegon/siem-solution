"""
/home/siem/siem-solution/services/normalizer/worker.py

Назначение:
  - Читает события из Redis Stream `siem:raw` (через XREAD),
    применяет JMESPath-правила и пишет результат в:
      - Redis Stream `siem:normalized`
      - ClickHouse таблицу siem.events

Важно:
  - Сейчас используется XREAD с локальным last_id (без consumer groups),
    чтобы гарантированно запустить нормализацию.
  - Возможны дубликаты при рестарте сервиса -> позже добавим дедуп и
    consumer groups, когда пайплайн будет стабильно работать.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, List, Tuple

from clickhouse_driver import Client
from redis.asyncio import Redis

from .config import NormalizerSettings
from .logging_conf import configure_logging
from .normalizer_core import NormalizerRule, apply_rules, load_rules

logger = logging.getLogger(__name__)


class NormalizerWorker:
    def __init__(self, settings: NormalizerSettings) -> None:
        self._settings = settings
        self._redis: Redis | None = None
        self._ch_client: Client | None = None
        self._rules: List[NormalizerRule] = []
        # Последний прочитанный ID в потоке siem:raw
        self._last_id: str = "0-0"

    async def init(self) -> None:
        """Инициализация Redis и ClickHouse, загрузка правил нормализации."""
        self._redis = Redis(
            host=self._settings.redis_host,
            port=self._settings.redis_port,
            db=self._settings.redis_db,
            password=self._settings.redis_password,
            decode_responses=True,
        )
        self._ch_client = Client(
            host=self._settings.ch_host,
            port=self._settings.ch_port,
            user=self._settings.ch_user,
            password=self._settings.ch_password,
            database=self._settings.ch_db,
            send_receive_timeout=self._settings.ch_timeout_secs,
        )

        self._rules = load_rules(self._settings)

        logger.info(
            "NormalizerWorker initialized",
            extra={
                "extra": {
                    "raw_stream": self._settings.raw_stream_key,
                    "normalized_stream": self._settings.normalized_stream_key,
                    "batch_size": self._settings.batch_size,
                }
            },
        )

    async def run(self) -> None:
        """Главный цикл: XREAD -> нормализация -> Redis + ClickHouse."""
        assert self._redis is not None
        assert self._ch_client is not None

        redis = self._redis
        ch = self._ch_client

        while True:
            try:
                # Ждём новые сообщения из siem:raw
                resp = await redis.xread(
                    {self._settings.raw_stream_key: self._last_id},
                    count=self._settings.batch_size,
                    block=5_000,  # 5 секунд
                )
            except Exception as exc:  # noqa: BLE001
                logger.error(
                    "Redis XREAD failed",
                    extra={"extra": {"error": str(exc)}},
                )
                await asyncio.sleep(1)
                continue

            if not resp:
                # Таймаут ожидания — просто ждём дальше
                continue

            events_to_insert: List[Dict[str, Any]] = []
            read_count = 0

            for stream_key, messages in resp:
                for msg_id, fields in messages:
                    read_count += 1
                    self._last_id = msg_id

                    raw_event: Dict[str, Any] = dict(fields)

                    uem = apply_rules(self._rules, raw_event)
                    if uem is None:
                        logger.debug(
                            "No normalizer rule matched",
                            extra={"extra": {"msg_id": msg_id}},
                        )
                        continue

                    events_to_insert.append(uem)

                    # Пытаемся положить нормализованное событие в Redis Stream siem:normalized
                    try:
                        await redis.xadd(
                            self._settings.normalized_stream_key,
                            {k: "" if v is None else str(v) for k, v in uem.items()},
                            maxlen=1_000_000,
                            approximate=True,
                        )
                    except Exception as exc:  # noqa: BLE001
                        logger.error(
                            "Failed to push normalized event to Redis",
                            extra={
                                "extra": {
                                    "error": str(exc),
                                    "msg_id": msg_id,
                                }
                            },
                        )

            if events_to_insert:
                rows = [
                    (
                        e.get("event.provider") or "",
                        e.get("event.category") or "",
                        e.get("event.type") or "",
                        e.get("source.ip") or "",
                        e.get("event.original") or "",
                    )
                    for e in events_to_insert
                ]
                try:
                    ch.execute(
                        """
                        INSERT INTO siem.events (event_provider, event_category, event_type, src_ip, event_original)
                        VALUES
                        """,
                        rows,
                    )
                    logger.info(
                        "Inserted normalized events into ClickHouse",
                        extra={
                            "extra": {
                                "count": len(rows),
                            }
                        },
                    )
                except Exception as exc:  # noqa: BLE001
                    logger.error(
                        "Failed to insert normalized events into ClickHouse",
                        extra={
                            "extra": {
                                "error": str(exc),
                                "count": len(rows),
                            }
                        },
                    )

            if read_count > 0:
                logger.info(
                    "Normalizer batch processed",
                    extra={
                        "extra": {
                            "raw_events_read": read_count,
                            "normalized_events": len(events_to_insert),
                            "last_id": self._last_id,
                        }
                    },
                )


async def main() -> None:
    configure_logging()
    settings = NormalizerSettings.load()
    worker = NormalizerWorker(settings)
    await worker.init()
    await worker.run()


if __name__ == "__main__":
    import asyncio

    asyncio.run(main())
