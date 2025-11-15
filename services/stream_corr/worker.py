"""
/home/siem/siem-solution/services/stream_corr/worker.py

Потоковый коррелятор:
  - XREADGROUP из Redis Stream siem:filtered
  - Для каждого события:
      * применяет включённые правила (pattern='threshold');
      * ведёт состояние по (rule_id, entity_key) в Redis ZSET;
      * при достижении threshold за window_s -> пишет алерт в siem.alerts_raw.

Для простоты:
  - используем время обработки (time.time()), а не ts из события.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from clickhouse_driver import Client
from redis.asyncio import Redis

from .config import StreamCorrSettings
from .logging_conf import configure_logging
from .rules import StreamCorrRule, load_stream_rules, matches_rule

logger = logging.getLogger(__name__)


class StreamCorrWorker:
    def __init__(self, settings: StreamCorrSettings) -> None:
        self._settings = settings
        self._redis: Optional[Redis] = None
        self._ch_client: Optional[Client] = None
        self._rules: List[StreamCorrRule] = []

    async def init(self) -> None:
        """Инициализация Redis, ClickHouse и загрузка правил."""
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

        assert self._redis is not None

        # Создаём consumer group, если его ещё нет
        try:
            await self._redis.xgroup_create(
                name=self._settings.filtered_stream_key,
                groupname=self._settings.group_name,
                id="0-0",
                mkstream=True,
            )
            logger.info(
                "Created Redis consumer group for stream_corr",
                extra={
                    "extra": {
                        "stream": self._settings.filtered_stream_key,
                        "group": self._settings.group_name,
                    }
                },
            )
        except Exception as exc:  # noqa: BLE001
            if "BUSYGROUP" in str(exc):
                logger.info(
                    "Redis consumer group already exists",
                    extra={
                        "extra": {
                            "stream": self._settings.filtered_stream_key,
                            "group": self._settings.group_name,
                        }
                    },
                )
            else:
                logger.error(
                    "Failed to create Redis consumer group",
                    extra={"extra": {"error": str(exc)}},
                )

        self._rules = load_stream_rules(self._settings)

        logger.info(
            "StreamCorrWorker initialized",
            extra={
                "extra": {
                    "stream": self._settings.filtered_stream_key,
                    "group": self._settings.group_name,
                    "consumer": self._settings.consumer_name,
                    "rules_count": len(self._rules),
                    "batch_size": self._settings.batch_size,
                }
            },
        )

    async def _reload_rules_periodically(self) -> None:
        """Периодическая перезагрузка правил (каждые 60 сек)."""
        while True:
            try:
                self._rules = load_stream_rules(self._settings)
            except Exception as exc:  # noqa: BLE001
                logger.error(
                    "Failed to reload stream correlation rules",
                    extra={"extra": {"error": str(exc)}},
                )
            await asyncio.sleep(60)

    async def run(self) -> None:
        assert self._redis is not None
        assert self._ch_client is not None
        redis = self._redis
        ch = self._ch_client

        asyncio.create_task(self._reload_rules_periodically())

        while True:
            try:
                resp = await redis.xreadgroup(
                    groupname=self._settings.group_name,
                    consumername=self._settings.consumer_name,
                    streams={self._settings.filtered_stream_key: ">"},
                    count=self._settings.batch_size,
                    block=5000,
                )
            except Exception as exc:  # noqa: BLE001
                logger.error(
                    "Redis XREADGROUP failed in stream_corr",
                    extra={"extra": {"error": str(exc)}},
                )
                await asyncio.sleep(1)
                continue

            if not resp:
                continue

            now = time.time()
            alerts_to_insert: List[Tuple[Any, ...]] = []
            processed_ids: List[str] = []
            events_processed = 0
            alerts_created = 0

            for _, messages in resp:
                for msg_id, fields in messages:
                    events_processed += 1
                    processed_ids.append(msg_id)

                    event: Dict[str, Any] = dict(fields)

                    for rule in self._rules:
                        if rule.pattern != "threshold":
                            continue

                        if not matches_rule(rule, event):
                            continue

                        entity_key = str(event.get(rule.entity_field) or "")
                        if not entity_key:
                            continue

                        should_alert, hits = await self._check_threshold_and_should_alert(
                            rule, entity_key, msg_id, now
                        )
                        if should_alert:
                            alerts_to_insert.append(
                                self._build_alert_row(rule, entity_key, now, hits)
                            )
                            alerts_created += 1

            if alerts_to_insert:
                try:
                    ch.execute(
                        """
                        INSERT INTO siem.alerts_raw
                        (ts, alert_id, rule_id, rule_name, severity,
                         ts_first, ts_last, window_s, entity_key,
                         hits, context_json, source, status)
                        VALUES
                        """,
                        alerts_to_insert,
                    )
                    logger.info(
                        "Inserted alerts batch into ClickHouse",
                        extra={
                            "extra": {
                                "alerts_inserted": len(alerts_to_insert),
                            }
                        },
                    )
                except Exception as exc:  # noqa: BLE001
                    logger.error(
                        "Failed to insert alerts into ClickHouse in stream_corr",
                        extra={
                            "extra": {
                                "error": str(exc),
                                "rows": len(alerts_to_insert),
                            }
                        },
                    )

            if processed_ids:
                try:
                    await redis.xack(
                        self._settings.filtered_stream_key,
                        self._settings.group_name,
                        *processed_ids,
                    )
                except Exception as exc:  # noqa: BLE001
                    logger.error(
                        "Failed to XACK messages in stream_corr",
                        extra={
                            "extra": {
                                "error": str(exc),
                                "ids": processed_ids,
                            }
                        },
                    )

            if events_processed > 0:
                logger.info(
                    "StreamCorr batch processed",
                    extra={
                        "extra": {
                            "events_processed": events_processed,
                            "alerts_created": alerts_created,
                        }
                    },
                )

    def _redis_key_zset(self, rule_id: int, entity_key: str) -> str:
        return f"siem:stream_corr:rule:{rule_id}:ent:{entity_key}"

    def _redis_key_last_alert(self, rule_id: int, entity_key: str) -> str:
        return f"siem:stream_corr:last_alert:{rule_id}:{entity_key}"

    async def _check_threshold_and_should_alert(
        self,
        rule: StreamCorrRule,
        entity_key: str,
        msg_id: str,
        now: float,
    ) -> Tuple[bool, int]:
        """
        Обновляет ZSET с событиями и проверяет достижение threshold.

        Возвращает (нужно_алертить, текущее_количество_событий_в_окне).
        """
        assert self._redis is not None
        redis = self._redis

        zkey = self._redis_key_zset(rule.id, entity_key)
        last_alert_key = self._redis_key_last_alert(rule.id, entity_key)

        window_start = now - rule.window_s

        await redis.zadd(zkey, {msg_id: now})
        await redis.zremrangebyscore(zkey, "-inf", window_start)
        current_count = int(await redis.zcard(zkey))
        last_alert_raw = await redis.get(last_alert_key)
        last_alert_ts = float(last_alert_raw) if last_alert_raw is not None else 0.0

        if current_count < rule.threshold:
            return False, current_count

        if last_alert_ts and (now - last_alert_ts) < rule.window_s:
            return False, current_count

        await redis.set(last_alert_key, str(now))
        return True, current_count

    def _build_alert_row(
        self,
        rule: StreamCorrRule,
        entity_key: str,
        now: float,
        hits: int,
    ) -> Tuple[Any, ...]:
        """
        Формирует строку для вставки в siem.alerts_raw.
        ts_first/ts_last считаем как [now - window_s, now].
        """
        ts_dt = datetime.fromtimestamp(now, tz=timezone.utc)
        ts_first_dt = datetime.fromtimestamp(now - rule.window_s, tz=timezone.utc)
        ts_last_dt = ts_dt

        alert_id = str(uuid.uuid4())
        context = {
            "rule_id": rule.id,
            "entity_key": entity_key,
            "description": rule.description,
        }

        return (
            ts_dt,                         # ts
            alert_id,                      # alert_id
            rule.id,                       # rule_id
            rule.name,                     # rule_name
            rule.severity,                 # severity
            ts_first_dt,                   # ts_first
            ts_last_dt,                    # ts_last
            rule.window_s,                 # window_s
            entity_key,                    # entity_key
            hits,                          # hits
            json.dumps(context, ensure_ascii=False),  # context_json
            "stream",                      # source
            "open",                        # status
        )


async def main() -> None:
    configure_logging()
    settings = StreamCorrSettings.load()
    worker = StreamCorrWorker(settings)
    await worker.init()
    await worker.run()


if __name__ == "__main__":
    import asyncio

    asyncio.run(main())
