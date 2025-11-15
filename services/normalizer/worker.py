"""
/home/siem/siem-solution/services/normalizer/worker.py

Микросервис нормализации:
  - Читает события из Redis Stream `siem:raw` (XREAD).
  - Применяет правила normalizer_core.apply_rules.
  - Пишет нормализованные события в Redis Stream `siem:normalized`.

Важно:
  - НИКУДА не пишет в ClickHouse — это задача отдельного writer-сервиса.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, List

from redis.asyncio import Redis

from .config import NormalizerSettings
from .logging_conf import configure_logging
from .normalizer_core import NormalizerRule, apply_rules, load_rules

logger = logging.getLogger(__name__)


class NormalizerWorker:
    def __init__(self, settings: NormalizerSettings) -> None:
        self._settings = settings
        self._redis: Redis | None = None
        self._rules: List[NormalizerRule] = []
        self._last_id: str = "0-0"

    async def init(self) -> None:
        """Инициализация Redis и загрузка правил нормализации."""
        self._redis = Redis(
            host=self._settings.redis_host,
            port=self._settings.redis_port,
            db=self._settings.redis_db,
            password=self._settings.redis_password,
            decode_responses=True,
        )

        self._rules = load_rules(self._settings)

        logger.info(
            "NormalizerWorker initialized",
            extra={
                "extra": {
                    "raw_stream": self._settings.raw_stream_key,
                    "normalized_stream": self._settings.normalized_stream_key,
                    "batch_size": self._settings.batch_size,
                    "rules_count": len(self._rules),
                }
            },
        )

    async def run(self) -> None:
        assert self._redis is not None
        redis = self._redis

        while True:
            try:
                resp = await redis.xread(
                    {self._settings.raw_stream_key: self._last_id},
                    count=self._settings.batch_size,
                    block=5_000,  # 5 секунд
                )
            except Exception as exc:  # noqa: BLE001
                logger.error(
                    "Redis XREAD failed in normalizer",
                    extra={"extra": {"error": str(exc)}},
                )
                await asyncio.sleep(1)
                continue

            if not resp:
                continue

            read_count = 0
            normalized_count = 0

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

                    normalized_count += 1

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

            if read_count > 0:
                logger.info(
                    "Normalizer batch processed",
                    extra={
                        "extra": {
                            "raw_events_read": read_count,
                            "normalized_events": normalized_count,
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
