"""
/home/siem/siem-solution/services/filter/worker.py

Микросервис фильтра:
  - Читает события из Redis Stream `siem:normalized` (XREAD).
  - Для каждого события:
      * применяет правила siem.filter_rules (в порядке priority, id);
      * если action == 'drop' -> событие отбрасывается;
      * если action == 'tag'  -> в событие добавляется поле 'tags' (строка);
      * если action == 'pass' -> просто пропускается дальше.
  - Прошедшие события пишет в Redis Stream `siem:filtered`.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, List, Optional, Tuple

from redis.asyncio import Redis

from .config import FilterSettings
from .filter_core import FilterRule, eval_expr, load_filter_rules
from .logging_conf import configure_logging

logger = logging.getLogger(__name__)


class FilterWorker:
    def __init__(self, settings: FilterSettings) -> None:
        self._settings = settings
        self._redis: Optional[Redis] = None
        self._rules: List[FilterRule] = []
        self._last_id: str = "0-0"

    async def init(self) -> None:
        """Инициализация Redis и загрузка правил."""
        self._redis = Redis(
            host=self._settings.redis_host,
            port=self._settings.redis_port,
            db=self._settings.redis_db,
            password=self._settings.redis_password,
            decode_responses=True,
        )
        self._rules = load_filter_rules(self._settings)
        logger.info(
            "FilterWorker initialized",
            extra={
                "extra": {
                    "normalized_stream": self._settings.normalized_stream_key,
                    "filtered_stream": self._settings.filtered_stream_key,
                    "batch_size": self._settings.batch_size,
                    "rules_count": len(self._rules),
                }
            },
        )

    async def _reload_rules_periodically(self) -> None:
        """Периодическая перезагрузка правил (каждые 30 секунд)."""
        while True:
            try:
                self._rules = load_filter_rules(self._settings)
            except Exception as exc:  # noqa: BLE001
                logger.error(
                    "Failed to reload filter rules",
                    extra={"extra": {"error": str(exc)}},
                )
            await asyncio.sleep(30)

    async def run(self) -> None:
        assert self._redis is not None
        redis = self._redis

        asyncio.create_task(self._reload_rules_periodically())

        while True:
            try:
                resp = await redis.xread(
                    {self._settings.normalized_stream_key: self._last_id},
                    count=self._settings.batch_size,
                    block=5_000,
                )
            except Exception as exc:  # noqa: BLE001
                logger.error(
                    "Redis XREAD failed in filter",
                    extra={"extra": {"error": str(exc)}},
                )
                await asyncio.sleep(1)
                continue

            if not resp:
                continue

            read_count = 0
            passed_count = 0
            dropped_count = 0
            tagged_count = 0

            for stream_key, messages in resp:
                for msg_id, fields in messages:
                    read_count += 1
                    self._last_id = msg_id

                    event = dict(fields)
                    decision, final_event = self.apply_rules(event)

                    if decision == "drop":
                        dropped_count += 1
                        continue

                    if decision == "tag":
                        tagged_count += 1

                    passed_count += 1

                    try:
                        await redis.xadd(
                            self._settings.filtered_stream_key,
                            {k: "" if v is None else str(v) for k, v in final_event.items()},
                            maxlen=1_000_000,
                            approximate=True,
                        )
                    except Exception as exc:  # noqa: BLE001
                        logger.error(
                            "Failed to push filtered event to Redis",
                            extra={
                                "extra": {
                                    "error": str(exc),
                                    "msg_id": msg_id,
                                }
                            },
                        )

            if read_count > 0:
                logger.info(
                    "Filter batch processed",
                    extra={
                        "extra": {
                            "events_read": read_count,
                            "events_passed": passed_count,
                            "events_dropped": dropped_count,
                            "events_tagged": tagged_count,
                            "last_id": self._last_id,
                        }
                    },
                )

    def apply_rules(self, event: Dict[str, Any]) -> tuple[str, Dict[str, Any]]:
        """Применяет правила к одному событию.

        Возвращает:
          (decision, event)
            decision: 'pass' | 'drop' | 'tag'
            event: возможно модифицированное событие (с тегами)
        """
        result = dict(event)
        tags: List[str] = []

        for rule in self._rules:
            if not rule.expr_ast:
                continue

            try:
                matched = eval_expr(rule.expr_ast, event)
            except Exception as exc:  # noqa: BLE001
                logger.error(
                    "Error evaluating filter rule",
                    extra={
                        "extra": {
                            "rule_id": rule.id,
                            "expr": rule.expr_text,
                            "error": str(exc),
                        }
                    },
                )
                continue

            if not matched:
                continue

            if rule.action == "drop":
                return "drop", result

            if rule.action == "tag":
                tags.extend(rule.tags)
                break

            if rule.action == "pass":
                break

        if tags:
            existing = result.get("tags")
            if existing:
                result["tags"] = f"{existing},{','.join(tags)}"
            else:
                result["tags"] = ",".join(tags)
            return "tag", result

        return "pass", result


async def main() -> None:
    configure_logging()
    settings = FilterSettings.load()
    worker = FilterWorker(settings)
    await worker.init()
    await worker.run()


if __name__ == "__main__":
    import asyncio

    asyncio.run(main())
