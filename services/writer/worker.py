"""
/home/siem/siem-solution/services/writer/worker.py

Writer-сервис:
  - Читает события из Redis Stream `siem:filtered` (XREAD).
  - Для каждого события:
      * извлекает UEM-поля (event.provider, event.category, event.type, source.ip,
        event.original, tags);
      * формирует батч записей и вставляет в ClickHouse siem.events.
  - Хранит последний обработанный ID в Redis-ключе `siem:writer:last_id`.

Идемпотентность:
  - При старте читает last_id из Redis, продолжает с него.
  - После успешной вставки батча обновляет last_id в Redis.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, List, Optional, Tuple

from clickhouse_driver import Client
from redis.asyncio import Redis

from .config import WriterSettings
from .logging_conf import configure_logging

logger = logging.getLogger(__name__)


class WriterWorker:
    def __init__(self, settings: WriterSettings) -> None:
        self._settings = settings
        self._redis: Optional[Redis] = None
        self._ch_client: Optional[Client] = None
        self._last_id: str = "0-0"

    async def init(self) -> None:
        """Инициализация Redis, ClickHouse и загрузка last_id."""
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

        # Пробуем прочитать last_id из Redis
        try:
            value = await self._redis.get(self._settings.writer_last_id_key)
            if value:
                self._last_id = value
        except Exception as exc:  # noqa: BLE001
            logger.error(
                "Failed to load writer last_id from Redis",
                extra={"extra": {"error": str(exc)}},
            )

        logger.info(
            "WriterWorker initialized",
            extra={
                "extra": {
                    "filtered_stream": self._settings.filtered_stream_key,
                    "last_id": self._last_id,
                    "batch_size": self._settings.batch_size,
                }
            },
        )

    async def _save_last_id(self) -> None:
        assert self._redis is not None
        try:
            await self._redis.set(self._settings.writer_last_id_key, self._last_id)
        except Exception as exc:  # noqa: BLE001
            logger.error(
                "Failed to save writer last_id to Redis",
                extra={"extra": {"error": str(exc), "last_id": self._last_id}},
            )

    async def run(self) -> None:
        assert self._redis is not None
        assert self._ch_client is not None

        redis = self._redis
        ch = self._ch_client

        while True:
            try:
                resp = await redis.xread(
                    {self._settings.filtered_stream_key: self._last_id},
                    count=self._settings.batch_size,
                    block=5_000,
                )
            except Exception as exc:  # noqa: BLE001
                logger.error(
                    "Redis XREAD failed in writer",
                    extra={"extra": {"error": str(exc)}},
                )
                await asyncio.sleep(1)
                continue

            if not resp:
                continue

            read_count = 0
            inserted_count = 0
            max_id_in_batch: Optional[str] = None
            rows: List[Tuple[Any, ...]] = []

            for stream_key, messages in resp:
                for msg_id, fields in messages:
                    read_count += 1
                    max_id_in_batch = msg_id

                    event = dict(fields)

                    event_provider = event.get("event.provider") or ""
                    event_category = event.get("event.category") or ""
                    event_type = event.get("event.type") or ""
                    src_ip = event.get("source.ip") or ""
                    event_original = event.get("event.original") or ""
                    tags = event.get("tags") or ""
                    source_type = event_provider  # для совместимости

                    rows.append(
                        (
                            event_provider,
                            event_category,
                            event_type,
                            src_ip,
                            event_original,
                            source_type,
                            tags,
                        )
                    )

            if rows:
                try:
                    ch.execute(
                        """
                        INSERT INTO siem.events
                        (event_provider, event_category, event_type, src_ip, event_original, source_type, tags)
                        VALUES
                        """,
                        rows,
                    )
                    inserted_count = len(rows)

                    # Обновляем last_id только после успешной вставки
                    if max_id_in_batch is not None:
                        self._last_id = max_id_in_batch
                        await self._save_last_id()

                    logger.info(
                        "Writer batch inserted",
                        extra={
                            "extra": {
                                "events_read": read_count,
                                "rows_inserted": inserted_count,
                                "last_id": self._last_id,
                            }
                        },
                    )
                except Exception as exc:  # noqa: BLE001
                    logger.error(
                        "Failed to insert events into ClickHouse in writer",
                        extra={
                            "extra": {
                                "error": str(exc),
                                "rows": len(rows),
                            }
                        },
                    )

            else:
                # На всякий случай логируем факт пустого чтения
                logger.info(
                    "Writer batch read no rows",
                    extra={
                        "extra": {
                            "events_read": read_count,
                            "last_id": self._last_id,
                        }
                    },
                )


async def main() -> None:
    configure_logging()
    settings = WriterSettings.load()
    worker = WriterWorker(settings)
    await worker.init()
    await worker.run()


if __name__ == "__main__":
    import asyncio

    asyncio.run(main())
