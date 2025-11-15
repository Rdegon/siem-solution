"""
/home/siem/siem-solution/services/batch_corr/worker.py

Batch-коррелятор:
  - раз в N секунд (SIEM_BATCH_CORR_INTERVAL_SEC) читает включённые правила
    из siem.correlation_rules_batch и выполняет их sql_template
    (одиночный INSERT ... SELECT ...) после подстановки {WINDOW_S}.
"""

from __future__ import annotations

import asyncio
import logging
from typing import List, Tuple

from clickhouse_driver import Client

from .config import BatchCorrSettings
from .logging_conf import configure_logging

logger = logging.getLogger(__name__)


class BatchCorrWorker:
    def __init__(self, settings: BatchCorrSettings) -> None:
        self._settings = settings
        self._client: Client | None = None

    def init_client(self) -> None:
        self._client = Client(
            host=self._settings.ch_host,
            port=self._settings.ch_port,
            user=self._settings.ch_user,
            password=self._settings.ch_password,
            database=self._settings.ch_db,
            send_receive_timeout=self._settings.ch_timeout_secs,
        )

        logger.info(
            "BatchCorrWorker initialized",
            extra={
                "extra": {
                    "ch_host": self._settings.ch_host,
                    "ch_port": self._settings.ch_port,
                    "db": self._settings.ch_db,
                    "interval_sec": self._settings.interval_sec,
                }
            },
        )

    def _load_rules(self) -> List[Tuple[int, str, int, str]]:
        assert self._client is not None
        rows = self._client.execute(
            """
            SELECT
                id,
                name,
                window_s,
                sql_template
            FROM siem.correlation_rules_batch
            WHERE enabled = 1
            ORDER BY id
            """
        )
        return [(int(r[0]), str(r[1]), int(r[2]), str(r[3])) for r in rows]

    def _run_rules_once(self) -> None:
        assert self._client is not None
        client = self._client

        rules = self._load_rules()
        if not rules:
            logger.info("No enabled batch correlation rules found", extra={"extra": {}})
            return

        for rule_id, name, window_s, sql_template in rules:
            final_sql = sql_template.replace("{WINDOW_S}", str(window_s))
            try:
                client.execute(final_sql)
                logger.info(
                    "Batch rule executed",
                    extra={
                        "extra": {
                            "rule_id": rule_id,
                            "name": name,
                            "window_s": window_s,
                        }
                    },
                )
            except Exception as exc:  # noqa: BLE001
                logger.error(
                    "Batch rule execution failed",
                    extra={
                        "extra": {
                            "rule_id": rule_id,
                            "name": name,
                            "window_s": window_s,
                            "error": str(exc),
                        }
                    },
                )

    async def run(self) -> None:
        assert self._client is not None

        while True:
            self._run_rules_once()
            await asyncio.sleep(self._settings.interval_sec)


async def main() -> None:
    configure_logging()
    settings = BatchCorrSettings.load()
    worker = BatchCorrWorker(settings)
    worker.init_client()
    await worker.run()


if __name__ == "__main__":
    import asyncio

    asyncio.run(main())
