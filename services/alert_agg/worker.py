"""
/home/siem/siem-solution/services/alert_agg/worker.py

Агрегатор алертов:
  - каждые N секунд (SIEM_ALERT_AGG_INTERVAL_SEC) пересчитывает siem.alerts_agg
    как агрегат siem.alerts_raw по (rule_id, entity_key).
"""

from __future__ import annotations

import asyncio
import logging

from clickhouse_driver import Client

from .config import AlertAggSettings
from .logging_conf import configure_logging

logger = logging.getLogger(__name__)


AGG_INSERT_SQL = """
INSERT INTO siem.alerts_agg
(
    ts,
    agg_id,
    rule_id,
    rule_name,
    severity_agg,
    ts_first,
    ts_last,
    count_alerts,
    unique_entities,
    entity_key,
    group_key_json,
    samples_json,
    status
)
SELECT
    now() AS ts,
    generateUUIDv4() AS agg_id,
    rule_id,
    any(rule_name) AS rule_name,
    max(severity) AS severity_agg,
    min(ts_first) AS ts_first,
    max(ts_last) AS ts_last,
    count(*) AS count_alerts,
    countDistinct(entity_key) AS unique_entities,
    entity_key,
    concat('{\"entity_key\":\"', entity_key, '\"}') AS group_key_json,
    toJSONString(arraySlice(groupArray(context_json), 1, 3)) AS samples_json,
    if(max(status) = 'open', 'open', 'closed') AS status
FROM siem.alerts_raw
GROUP BY rule_id, entity_key
"""


class AlertAggWorker:
    def __init__(self, settings: AlertAggSettings) -> None:
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
            "AlertAggWorker initialized",
            extra={
                "extra": {
                    "ch_host": self._settings.ch_host,
                    "ch_port": self._settings.ch_port,
                    "db": self._settings.ch_db,
                    "interval_sec": self._settings.interval_sec,
                }
            },
        )

    def _run_aggregation(self) -> int:
        assert self._client is not None
        client = self._client

        # 1. Полностью очищаем alerts_agg
        client.execute("TRUNCATE TABLE siem.alerts_agg")

        # 2. Пересчитываем агрегаты
        client.execute(AGG_INSERT_SQL)

        # 3. Считаем количество групп для логов
        rows = client.execute("SELECT count() FROM siem.alerts_agg")
        groups_count = int(rows[0][0]) if rows else 0
        return groups_count

    async def run(self) -> None:
        assert self._client is not None

        while True:
            try:
                groups_count = self._run_aggregation()
                logger.info(
                    "Alert aggregation completed",
                    extra={
                        "extra": {
                            "groups_count": groups_count,
                        }
                    },
                )
            except Exception as exc:  # noqa: BLE001
                logger.error(
                    "Alert aggregation failed",
                    extra={
                        "extra": {
                            "error": str(exc),
                        }
                    },
                )

            await asyncio.sleep(self._settings.interval_sec)


async def main() -> None:
    configure_logging()
    settings = AlertAggSettings.load()
    worker = AlertAggWorker(settings)
    worker.init_client()
    await worker.run()


if __name__ == "__main__":
    import asyncio

    asyncio.run(main())
