from __future__ import annotations

from functools import lru_cache
from typing import Any, Dict, List

import clickhouse_connect

from .config import CONFIG


# ───────────────── ClickHouse client ─────────────────


@lru_cache(maxsize=1)
def get_ch_client() -> clickhouse_connect.driver.Client:
    """
    Singleton-клиент ClickHouse, настроенный по CONFIG.ch.
    Работает через HTTP-интерфейс (порт SIEM_CH_PORT, обычно 8123).
    """
    ch = CONFIG.ch
    client = clickhouse_connect.get_client(
        host=ch.host,
        port=ch.port,
        username=ch.user,
        password=ch.password,
        database=ch.db,
    )
    return client


def ch_ping() -> bool:
    """
    Простейшая проверка доступности ClickHouse (SELECT 1).
    Используется в /health.
    """
    try:
        client = get_ch_client()
        client.command("SELECT 1")
        return True
    except Exception:
        return False


# ───────────────── Alerts helpers ─────────────────


def fetch_alerts_agg(limit: int = 200) -> List[Dict[str, Any]]:
    """
    Возвращает агрегированные алерты из siem.alerts_agg для /alerts_agg.
    """
    client = get_ch_client()
    query = """
        SELECT
            ts_first,
            ts_last,
            rule_id,
            severity_agg,
            count_alerts,
            unique_entities,
            group_key_json,
            status
        FROM siem.alerts_agg
        ORDER BY ts_last DESC
        LIMIT {limit}
    """
    result = client.query(query, parameters={"limit": limit})
    rows: List[Dict[str, Any]] = []
    for r in result.named_results():
        rows.append(
            {
                "ts_first": r.ts_first,
                "ts_last": r.ts_last,
                "rule_id": r.rule_id,
                "severity_agg": r.severity_agg,
                "count_alerts": r.count_alerts,
                "unique_entities": r.unique_entities,
                "group_key_json": r.group_key_json,
                "status": r.status,
            }
        )
    return rows


def fetch_alerts_raw(limit: int = 200) -> List[Dict[str, Any]]:
    """
    Возвращает сырые алерты из siem.alerts_raw для /alerts_raw.
    """
    client = get_ch_client()
    query = """
        SELECT
            ts_first,
            ts_last,
            rule_id,
            rule_name,
            severity,
            entity_key,
            hits,
            context_json,
            status
        FROM siem.alerts_raw
        ORDER BY ts_last DESC
        LIMIT {limit}
    """
    result = client.query(query, parameters={"limit": limit})
    rows: List[Dict[str, Any]] = []
    for r in result.named_results():
        rows.append(
            {
                "ts_first": r.ts_first,
                "ts_last": r.ts_last,
                "rule_id": r.rule_id,
                "rule_name": r.rule_name,
                "severity": r.severity,
                "entity_key": r.entity_key,
                "hits": r.hits,
                "context_json": r.context_json,
                "status": r.status,
            }
        )
    return rows


# ───────────────── Events helpers ─────────────────


def fetch_events(limit: int = 200) -> List[Dict[str, Any]]:
    """
    Возвращает последние события из siem.events для страницы /events.
    Ожидается схема:
      ts, event_id, category, subcategory,
      src_ip (IPv4), dst_ip (IPv4),
      src_port, dst_port,
      device_vendor, device_product, log_source,
      severity, message.
    """
    client = get_ch_client()
    query = """
        SELECT
            ts,
            event_id,
            category,
            subcategory,
            IPv4NumToString(src_ip) AS src_ip,
            IPv4NumToString(dst_ip) AS dst_ip,
            src_port,
            dst_port,
            device_vendor,
            device_product,
            log_source,
            severity,
            message
        FROM siem.events
        ORDER BY ts DESC
        LIMIT {limit}
    """
    result = client.query(query, parameters={"limit": limit})
    rows: List[Dict[str, Any]] = []
    for r in result.named_results():
        rows.append(
            {
                "ts": r.ts,
                "event_id": r.event_id,
                "category": r.category,
                "subcategory": r.subcategory,
                "src_ip": r.src_ip,
                "dst_ip": r.dst_ip,
                "src_port": r.src_port,
                "dst_port": r.dst_port,
                "device_vendor": r.device_vendor,
                "device_product": r.device_product,
                "log_source": r.log_source,
                "severity": r.severity,
                "message": r.message,
            }
        )
    return rows


def fetch_events_timeseries(minutes: int = 60) -> List[Dict[str, Any]]:
    """
    Таймсерия events per minute за последние N минут по таблице siem.events.
    Формат:
      {"ts_minute": "YYYY-MM-DD HH:MM:SS", "cnt": int}
    """
    client = get_ch_client()
    query = """
        SELECT
            toStartOfMinute(ts) AS ts_minute,
            count() AS cnt
        FROM siem.events
        WHERE ts >= now() - INTERVAL {minutes} MINUTE
        GROUP BY ts_minute
        ORDER BY ts_minute
    """
    result = client.query(query, parameters={"minutes": minutes})
    rows: List[Dict[str, Any]] = []
    for ts_minute, cnt in result.result_rows:
        rows.append(
            {
                "ts_minute": ts_minute.strftime("%Y-%m-%d %H:%M:%S"),
                "cnt": int(cnt),
            }
        )
    return rows
