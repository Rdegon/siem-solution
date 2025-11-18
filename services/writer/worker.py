from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple

from clickhouse_driver import Client
from redis.asyncio import Redis
from redis.exceptions import ResponseError

logger = logging.getLogger("siem.writer")


@dataclass
class WriterSettings:
    # Redis
    redis_host: str = os.getenv("SIEM_REDIS_HOST", "127.0.0.1")
    redis_port: int = int(os.getenv("SIEM_REDIS_PORT", "6379"))
    redis_db: int = int(os.getenv("SIEM_REDIS_DB", "0"))
    redis_password: str | None = os.getenv("SIEM_REDIS_PASSWORD") or None

    # Stream / consumer group
    filtered_stream_key: str = os.getenv("SIEM_FILTERED_STREAM_KEY", "siem:filtered")
    group_name: str = os.getenv("SIEM_WRITER_GROUP", "writer")
    consumer_name: str = os.getenv("SIEM_WRITER_CONSUMER", "writer-1")
    batch_size: int = int(os.getenv("SIEM_WRITER_BATCH_SIZE", "100"))
    block_ms: int = int(os.getenv("SIEM_WRITER_BLOCK_MS", "1000"))

    # ClickHouse
    ch_host: str = os.getenv("SIEM_CH_HOST", "127.0.0.1")
    ch_port: int = int(os.getenv("SIEM_CH_PORT", "8123"))
    ch_user: str = os.getenv("SIEM_CH_USER", "siem_app")
    ch_password: str = os.getenv("SIEM_CH_PASSWORD", "")
    ch_db: str = os.getenv("SIEM_CH_DB", "siem")
    ch_timeout_secs: int = int(os.getenv("SIEM_CH_TIMEOUT_SECS", "10"))
    events_table: str = os.getenv("SIEM_EVENTS_TABLE", "siem.events")


def ipv4_to_int(ip: str | None) -> int:
    if not ip:
        return 0
    try:
        return int(ipaddress.IPv4Address(ip))
    except Exception:
        return 0


class WriterWorker:
    def __init__(self, settings: WriterSettings) -> None:
        self._settings = settings
        self._redis: Redis | None = None
        self._ch: Client | None = None

    async def init(self) -> None:
        """Инициализация Redis и ClickHouse, создание consumer group при необходимости."""
        self._redis = Redis(
            host=self._settings.redis_host,
            port=self._settings.redis_port,
            db=self._settings.redis_db,
            password=self._settings.redis_password,
            decode_responses=True,
        )

        self._ch = Client(
            host=self._settings.ch_host,
            port=self._settings.ch_port,
            user=self._settings.ch_user,
            password=self._settings.ch_password,
            database=self._settings.ch_db,
            send_receive_timeout=self._settings.ch_timeout_secs,
        )

        # Создаём consumer group, если её ещё нет
        try:
            await self._redis.xgroup_create(
                name=self._settings.filtered_stream_key,
                groupname=self._settings.group_name,
                id="0-0",
                mkstream=True,
            )
            logger.info(
                "Created Redis consumer group",
                extra={
                    "extra": {
                        "stream": self._settings.filtered_stream_key,
                        "group": self._settings.group_name,
                    }
                },
            )
        except ResponseError as exc:
            # BUSYGROUP означает "group уже существует" — это не ошибка
            if "BUSYGROUP" not in str(exc):
                raise

        logger.info(
            "WriterWorker initialized",
            extra={
                "extra": {
                    "stream": self._settings.filtered_stream_key,
                    "group": self._settings.group_name,
                    "consumer": self._settings.consumer_name,
                    "batch_size": self._settings.batch_size,
                }
            },
        )

    def _build_row(self, msg_id: str, fields: Dict[str, str]) -> Tuple[Any, ...]:
        """
        Строит строку под таблицу siem.events.

        Ожидаемые поля в записи stream'а:
          - event.provider
          - source.ip / destination.ip
          - event.original (исходное сообщение)
          - event.category (опц.)
          - event.type (опц.)
          - device.vendor / device.product / host.name / log.level и т.п.
        """
        now = datetime.now(timezone.utc)

        event_id = fields.get("event_id") or msg_id
        provider = fields.get("event.provider", "")

        category = fields.get("event.category") or provider or "generic"
        subcategory = fields.get("event.type") or ""

        src_ip_int = ipv4_to_int(fields.get("source.ip"))
        dst_ip_int = ipv4_to_int(fields.get("destination.ip"))

        src_port = int(fields.get("source.port", "0") or 0)
        dst_port = int(fields.get("destination.port", "0") or 0)

        device_vendor = fields.get("device.vendor") or provider
        device_product = fields.get("device.product") or provider

        log_source = (
            fields.get("log_source")
            or fields.get("host.name")
            or fields.get("source.ip")
            or ""
        )

        severity = (
            fields.get("event.severity")
            or fields.get("severity")
            or fields.get("log.level")
            or "info"
        )

        message = fields.get("event.original") or fields.get("message") or ""

        return (
            now,
            event_id,
            category,
            subcategory,
            src_ip_int,
            dst_ip_int,
            src_port,
            dst_port,
            device_vendor,
            device_product,
            log_source,
            severity,
            message,
        )

    async def run(self) -> None:
        """Основной цикл: читаем из Redis, пишем в ClickHouse."""
        assert self._redis is not None
        assert self._ch is not None

        redis = self._redis
        ch = self._ch
        s = self._settings

        insert_sql = (
            f"INSERT INTO {s.events_table} "
            "(ts, event_id, category, subcategory, "
            " src_ip, dst_ip, src_port, dst_port, "
            " device_vendor, device_product, log_source, severity, message) "
            "VALUES"
        )

        while True:
            resp = await redis.xreadgroup(
                groupname=s.group_name,
                consumername=s.consumer_name,
                streams={s.filtered_stream_key: ">"},
                count=s.batch_size,
                block=s.block_ms,
            )

            if not resp:
                continue

            rows: List[Tuple[Any, ...]] = []
            ids: List[str] = []

            for _stream_name, messages in resp:
                for msg_id, fields in messages:
                    try:
                        row = self._build_row(msg_id, fields)
                    except Exception as exc:  # noqa: BLE001
                        logger.error(
                            "Failed to build row from record",
                            extra={
                                "extra": {
                                    "error": str(exc),
                                    "id": msg_id,
                                    "fields": fields,
                                }
                            },
                        )
                        # Подтверждаем проблемную запись, чтобы не зависнуть
                        await redis.xack(s.filtered_stream_key, s.group_name, msg_id)
                        continue

                    rows.append(row)
                    ids.append(msg_id)

            if not rows:
                continue

            try:
                ch.execute(insert_sql, rows)
            except Exception as exc:  # noqa: BLE001
                logger.error(
                    "Failed to insert rows into ClickHouse",
                    extra={
                        "extra": {
                            "error": str(exc),
                            "rows": len(rows),
                        }
                    },
                )
                # Не подтверждаем — попробуем позже
                continue

            if ids:
                await redis.xack(s.filtered_stream_key, s.group_name, *ids)

            logger.info(
                "Batch written to ClickHouse",
                extra={"extra": {"rows": len(rows)}},
            )


async def _main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    settings = WriterSettings()
    worker = WriterWorker(settings)
    await worker.init()
    await worker.run()


if __name__ == "__main__":
    asyncio.run(_main())
