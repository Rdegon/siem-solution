"""
/home/siem/siem-solution/services/stream_corr/worker.py

Потоковый коррелятор:
  - XREADGROUP из Redis Stream siem:filtered
  - Для каждого события:
      * применяет включённые правила (pattern='threshold');
      * ведёт состояние по (rule_id, entity_key) в Redis ZSET;
      * при достижении threshold за window_s -> пишет алерт в siem.alerts_raw.

Для простоты:
  - используем время из времени обработки (time.time()), а не timestamp из события.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
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

        # Создаём consumer group, если его ещё нет
        assert self._redis is not None
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
            # Если already exists, Redis вернёт BUSYGROUP -> это не ошибка
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

            for stream_key, messages in resp:
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

                        if self._check_threshold_and_should_alert(rule, entity_key, msg_id, now):
                            alert_row = self._build_alert_row(rule, entity_key, now)
                            alerts_to_insert.append(alert_row)
                            alerts_created += 1

            # Вставка алертов в ClickHouse
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

            # ACK всех обработанных сообщений
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

    def _check_threshold_and_should_alert(
        self,
        rule: StreamCorrRule,
        entity_key: str,
        msg_id: str,
        now: float,
    ) -> bool:
        """
        Обновляет ZSET с событиями и проверяет достижение threshold.

        Возвращает True, если нужно сгенерировать новый алерт.
        """
        assert self._redis is not None
        redis = self._redis

        zkey = self._redis_key_zset(rule.id, entity_key)
        last_alert_key = self._redis_key_last_alert(rule.id, entity_key)

        window_start = now - rule.window_s

        # Добавляем текущее событие в ZSET
        # Используем unix timestamp в секундах как score, msg_id как member
        score = now
        pipe = redis.pipeline()
        pipe.zadd(zkey, {msg_id: score})
        pipe.zremrangebyscore(zkey, "-inf", window_start)
        pipe.zcard(zkey)
        pipe.get(last_alert_key)
        results = asyncio.get_event_loop().run_until_complete(pipe.execute())  # type: ignore[call-arg]

        current_count = int(results[2])
        last_alert_raw = results[3]
        last_alert_ts = float(last_alert_raw) if last_alert_raw is not None else 0.0

        if current_count < rule.threshold:
            return False

        # Если с последнего алерта прошло меньше окна, не алертим снова
        if last_alert_ts and (now - last_alert_ts) < rule.window_s:
            return False

        # Обновляем время последнего алерта
        asyncio.get_event_loop().run_until_complete(redis.set(last_alert_key, str(now)))  # type: ignore[arg-type]

        return True

    def _build_alert_row(self, rule: StreamCorrRule, entity_key: str, now: float) -> Tuple[Any, ...]:
        """
        Формирует строку для вставки в siem.alerts_raw.
        Для простоты ts_first/ts_last считаем "текущее окно" = [now - window_s, now].
        """
        ts = int(now)
        # DateTime в ClickHouse ожидает UNIX timestamp (int) -> драйвер сам сконвертит
        ts_first = ts - int(rule.window_s)
        ts_last = ts

        alert_id = str(uuid.uuid4())
        context = {
            "rule_id": rule.id,
            "entity_key": entity_key,
            "description": rule.description,
        }

        # hits мы пока не знаем точно (требовало бы читать ZSET) -> используем threshold
        hits = rule.threshold

        return (
            ts,                 # ts
            alert_id,           # alert_id
            rule.id,            # rule_id
            rule.name,          # rule_name
            rule.severity,      # severity
            ts_first,           # ts_first
            ts_last,            # ts_last
            rule.window_s,      # window_s
            entity_key,         # entity_key
            hits,               # hits
            json.dumps(context, ensure_ascii=False),  # context_json
            "stream",           # source
            "open",             # status
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
