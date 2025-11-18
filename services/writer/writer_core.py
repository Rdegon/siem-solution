from __future__ import annotations

import json
import logging
import os
import time
from typing import Any, Dict, List

import redis
from clickhouse_driver import Client as ChClient

from services.common.ch_config import load_ch_config  # путь подстрой под свой проект

LOG = logging.getLogger("siem.writer")


class WriterWorker:
    """
    Читает события из Redis Stream siem:filtered и пачками пишет их в ClickHouse siem.events.
    Использует clickhouse_driver по native-порту (обычно 9000), не HTTP.
    """

    def __init__(self) -> None:
        ch_cfg = load_ch_config().native

        self.ch = ChClient(
            host=ch_cfg.host,
            port=ch_cfg.port,
            user=ch_cfg.user,
            password=ch_cfg.password,
            database=ch_cfg.db,
            settings={"insert_deduplicate": 1},
        )

        redis_host = os.getenv("SIEM_REDIS_HOST", "127.0.0.1")
        redis_port = int(os.getenv("SIEM_REDIS_PORT", "6379"))
        redis_db = int(os.getenv("SIEM_REDIS_DB", "0"))
        redis_password = os.getenv("SIEM_REDIS_PASSWORD") or None

        self.redis = redis.Redis(
            host=redis_host,
            port=redis_port,
            db=redis_db,
            password=redis_password,
            decode_responses=True,
        )

        self.stream = os.getenv("SIEM_REDIS_STREAM_FILTERED", "siem:filtered")
        self.group = os.getenv("SIEM_WRITER_GROUP", "writer")
        self.consumer = os.getenv("SIEM_WRITER_CONSUMER", "writer-1")

        LOG.info("WriterWorker initialized")

    def ensure_group(self) -> None:
        try:
            self.redis.xgroup_create(self.stream, self.group, id="0-0", mkstream=True)
        except redis.ResponseError as exc:
            if "BUSYGROUP" in str(exc):
                return
            raise

    def run_forever(self) -> None:
        self.ensure_group()
        batch: List[Dict[str, Any]] = []

        while True:
            try:
                res = self.redis.xreadgroup(
                    groupname=self.group,
                    consumername=self.consumer,
                    streams={self.stream: ">"},
                    count=100,
                    block=5000,
                )
                if not res:
                    continue

                for _stream, messages in res:
                    for msg_id, fields in messages:
                        try:
                            payload = json.loads(fields["data"])
                            batch.append(payload)
                            self.redis.xack(self.stream, self.group, msg_id)
                        except Exception as exc:  # noqa: BLE001
                            LOG.exception("Failed to process message %s: %s", msg_id, exc)

                if batch:
                    self._flush_batch(batch)
                    batch.clear()

            except Exception as exc:  # noqa: BLE001
                LOG.exception("Writer loop error: %s", exc)
                time.sleep(5)

    def _flush_batch(self, batch: List[Dict[str, Any]]) -> None:
        if not batch:
            return

        rows = []
        for ev in batch:
            rows.append(
                (
                    ev["ts"],
                    ev["event_id"],
                    ev["category"],
                    ev["subcategory"],
                    ev["src_ip"],
                    ev["dst_ip"],
                    ev["src_port"],
                    ev["dst_port"],
                    ev["device_vendor"],
                    ev["device_product"],
                    ev["log_source"],
                    ev["severity"],
                    ev["message"],
                )
            )

        query = """
            INSERT INTO siem.events
            (
                ts, event_id, category, subcategory,
                src_ip, dst_ip, src_port, dst_port,
                device_vendor, device_product, log_source,
                severity, message
            )
            VALUES
        """

        self.ch.execute(query, rows)
        LOG.info("Inserted %d rows into siem.events", len(rows))
