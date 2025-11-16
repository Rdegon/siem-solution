"""
app.deps
--------
Общие зависимости: ClickHouse-клиент и простые функции для запросов.

Использует:
- CONFIG.ch.host
- CONFIG.ch.port
- CONFIG.ch.db
- CONFIG.ch.user
- CONFIG.ch.password
"""

from __future__ import annotations

from functools import lru_cache
from typing import Any, Dict, List

import clickhouse_connect

from .config import CONFIG


@lru_cache(maxsize=1)
def get_ch_client():
    client = clickhouse_connect.get_client(
        host=CONFIG.ch.host,
        port=CONFIG.ch.port,
        username=CONFIG.ch.user,
        password=CONFIG.ch.password,
        database=CONFIG.ch.db,
    )
    return client


def fetch_alerts_agg(limit: int = 100) -> List[Dict[str, Any]]:
    client = get_ch_client()
    rows = client.query(
        """
        SELECT
          ts_first,
          ts_last,
          rule_id,
          rule_name,
          severity_agg,
          group_key_json,
          count_alerts,
          unique_entities,
          status
        FROM siem.alerts_agg
        ORDER BY ts_last DESC
        LIMIT %(limit)s
        """,
        parameters={"limit": limit},
    ).named_results()
    return [dict(r) for r in rows]


def fetch_alerts_raw(limit: int = 200) -> List[Dict[str, Any]]:
    client = get_ch_client()
    rows = client.query(
        """
        SELECT
          ts_first,
          ts_last,
          rule_id,
          rule_name,
          severity,
          entity_key,
          hits,
          source,
          status,
          context_json
        FROM siem.alerts_raw
        ORDER BY ts_last DESC
        LIMIT %(limit)s
        ""`,
        parameters={"limit": limit},
    ).named_results()
    return [dict(r) for r in rows]


def fetch_events(limit: int = 200) -> List[Dict[str, Any]]:
    client = get_ch_client()
    rows = client.query(
        """
        SELECT
          ts,
          event_id,
          category,
          subcategory,
          src_ip,
          dst_ip,
          src_port,
          dst_port,
          device_vendor,
          device_product,
          log_source,
          severity,
          message
        FROM siem.events
        ORDER BY ts DESC
        LIMIT %(limit)s
        """,
        parameters={"limit": limit},
    ).named_results()
    return [dict(r) for r in rows]


def fetch_events_timeseries(minutes: int = 60) -> List[Dict[str, Any]]:
    """
    Упрощённая таймсерия events per minute для графика.
    """
    client = get_ch_client()
    rows = client.query(
        """
        SELECT
          toStartOfMinute(ts) AS ts_minute,
          count() AS cnt
        FROM siem.events
        WHERE ts >= now() - INTERVAL %(minutes)s MINUTE
        GROUP BY ts_minute
        ORDER BY ts_minute ASC
        """,
        parameters={"minutes": minutes},
    ).named_results()
    return [dict(r) for r in rows]
