from __future__ import annotations

from functools import lru_cache
from typing import Any, Dict, List

import clickhouse_connect

from .config import CONFIG


@lru_cache(maxsize=1)
def get_ch_client() -> clickhouse_connect.driver.Client:
    ch = CONFIG.ch
    return clickhouse_connect.get_client(
        host=ch.host,
        port=ch.port,
        username=ch.user,
        password=ch.password,
        database=ch.db,
    )


def ch_ping() -> bool:
    try:
        get_ch_client().command("SELECT 1")
        return True
    except Exception:
        return False


def _fmt(value: Any) -> Any:
    if value is None:
        return ""
    if hasattr(value, "strftime"):
        return value.strftime("%Y-%m-%d %H:%M:%S")
    return value


def _scalar(query: str) -> Any:
    result = get_ch_client().query(query)
    if not result.result_rows:
        return 0
    return result.result_rows[0][0]


def fetch_alerts_agg(limit: int = 200) -> List[Dict[str, Any]]:
    query = f"""
        SELECT
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
        FROM siem.alerts_agg
        ORDER BY ts_last DESC
        LIMIT {int(limit)}
    """
    rows: List[Dict[str, Any]] = []
    for row in get_ch_client().query(query).named_results():
        rows.append(
            {
                "ts": _fmt(row["ts"]),
                "agg_id": str(row["agg_id"]),
                "rule_id": row["rule_id"],
                "rule_name": row["rule_name"],
                "severity_agg": str(row["severity_agg"]).lower(),
                "ts_first": _fmt(row["ts_first"]),
                "ts_last": _fmt(row["ts_last"]),
                "count_alerts": int(row["count_alerts"]),
                "unique_entities": int(row["unique_entities"]),
                "entity_key": row["entity_key"],
                "group_key_json": row["group_key_json"],
                "samples_json": row["samples_json"],
                "status": row["status"],
            }
        )
    return rows


def fetch_alerts_raw(limit: int = 200) -> List[Dict[str, Any]]:
    query = f"""
        SELECT
            ts,
            alert_id,
            rule_id,
            rule_name,
            severity,
            ts_first,
            ts_last,
            window_s,
            entity_key,
            hits,
            context_json,
            source,
            status
        FROM siem.alerts_raw
        ORDER BY ts_last DESC
        LIMIT {int(limit)}
    """
    rows: List[Dict[str, Any]] = []
    for row in get_ch_client().query(query).named_results():
        rows.append(
            {
                "ts": _fmt(row["ts"]),
                "alert_id": str(row["alert_id"]),
                "rule_id": row["rule_id"],
                "rule_name": row["rule_name"],
                "severity": str(row["severity"]).lower(),
                "ts_first": _fmt(row["ts_first"]),
                "ts_last": _fmt(row["ts_last"]),
                "window_s": int(row["window_s"]),
                "entity_key": row["entity_key"],
                "hits": int(row["hits"]),
                "context_json": row["context_json"],
                "source": row["source"],
                "status": row["status"],
            }
        )
    return rows


def fetch_events(limit: int = 400) -> List[Dict[str, Any]]:
    query = f"""
        SELECT
            ts,
            event_id,
            category,
            subcategory,
            if(src_ip = 0, '', IPv4NumToString(src_ip)) AS src_ip,
            if(dst_ip = 0, '', IPv4NumToString(dst_ip)) AS dst_ip,
            src_port,
            dst_port,
            device_vendor,
            device_product,
            log_source,
            severity,
            message,
            tags
        FROM siem.events
        ORDER BY ts DESC
        LIMIT {int(limit)}
    """
    rows: List[Dict[str, Any]] = []
    for row in get_ch_client().query(query).named_results():
        rows.append(
            {
                "ts": _fmt(row["ts"]),
                "event_id": row["event_id"],
                "category": row["category"],
                "subcategory": row["subcategory"],
                "src_ip": row["src_ip"],
                "dst_ip": row["dst_ip"],
                "src_port": int(row["src_port"] or 0),
                "dst_port": int(row["dst_port"] or 0),
                "device_vendor": row["device_vendor"],
                "device_product": row["device_product"],
                "log_source": row["log_source"],
                "severity": str(row["severity"]).lower(),
                "message": row["message"],
                "tags": row["tags"] or "",
            }
        )
    return rows


def fetch_events_timeseries(hours: int = 24, bucket_minutes: int = 30) -> List[Dict[str, Any]]:
    query = f"""
        SELECT
            toStartOfInterval(ts, INTERVAL {int(bucket_minutes)} minute) AS bucket,
            count() AS cnt
        FROM siem.events
        WHERE ts >= now() - INTERVAL {int(hours)} HOUR
        GROUP BY bucket
        ORDER BY bucket ASC
    """
    rows: List[Dict[str, Any]] = []
    result = get_ch_client().query(query)
    for bucket, cnt in result.result_rows:
        rows.append({"bucket": _fmt(bucket), "cnt": int(cnt)})
    return rows


def fetch_severity_breakdown(hours: int = 24) -> List[Dict[str, Any]]:
    query = f"""
        SELECT lower(severity) AS severity, count() AS cnt
        FROM siem.events
        WHERE ts >= now() - INTERVAL {int(hours)} HOUR
        GROUP BY severity
        ORDER BY cnt DESC
    """
    rows: List[Dict[str, Any]] = []
    for severity, cnt in get_ch_client().query(query).result_rows:
        rows.append({"severity": severity or "unknown", "cnt": int(cnt)})
    return rows


def fetch_top_sources(limit: int = 8, hours: int = 24) -> List[Dict[str, Any]]:
    query = f"""
        SELECT
            log_source,
            count() AS events,
            max(ts) AS last_seen,
            countIf(lower(severity) = 'critical') AS critical_count,
            countIf(lower(severity) = 'high') AS high_count
        FROM siem.events
        WHERE ts >= now() - INTERVAL {int(hours)} HOUR
        GROUP BY log_source
        ORDER BY events DESC
        LIMIT {int(limit)}
    """
    rows: List[Dict[str, Any]] = []
    for row in get_ch_client().query(query).named_results():
        rows.append(
            {
                "log_source": row["log_source"] or "unknown",
                "events": int(row["events"]),
                "last_seen": _fmt(row["last_seen"]),
                "critical_count": int(row["critical_count"]),
                "high_count": int(row["high_count"]),
            }
        )
    return rows


def fetch_dashboard_metrics() -> Dict[str, Any]:
    return {
        "events_24h": int(_scalar("SELECT count() FROM siem.events WHERE ts >= now() - INTERVAL 24 HOUR")),
        "events_1h": int(_scalar("SELECT count() FROM siem.events WHERE ts >= now() - INTERVAL 1 HOUR")),
        "agg_alerts_24h": int(_scalar("SELECT count() FROM siem.alerts_agg WHERE ts >= now() - INTERVAL 24 HOUR")),
        "raw_alerts_24h": int(_scalar("SELECT count() FROM siem.alerts_raw WHERE ts >= now() - INTERVAL 24 HOUR")),
        "critical_events_24h": int(_scalar("SELECT count() FROM siem.events WHERE ts >= now() - INTERVAL 24 HOUR AND lower(severity) = 'critical'")),
        "active_sources_24h": int(_scalar("SELECT countDistinct(log_source) FROM siem.events WHERE ts >= now() - INTERVAL 24 HOUR")),
    }


def fetch_alert_metrics() -> Dict[str, Any]:
    return {
        "agg_total": int(_scalar("SELECT count() FROM siem.alerts_agg")),
        "agg_open": int(_scalar("SELECT count() FROM siem.alerts_agg WHERE lower(status) != 'closed'")),
        "raw_total": int(_scalar("SELECT count() FROM siem.alerts_raw")),
        "critical_raw": int(_scalar("SELECT count() FROM siem.alerts_raw WHERE lower(severity) = 'critical'")),
    }


def fetch_recent_alerts(limit: int = 10) -> List[Dict[str, Any]]:
    return fetch_alerts_raw(limit=limit)


def fetch_assets(limit: int = 50, hours: int = 24) -> List[Dict[str, Any]]:
    query = f"""
        SELECT
            log_source,
            count() AS events,
            max(ts) AS last_seen,
            countIf(lower(severity) IN ('critical', 'high')) AS notable_events,
            groupUniqArray(3)(category) AS categories
        FROM siem.events
        WHERE ts >= now() - INTERVAL {int(hours)} HOUR
        GROUP BY log_source
        ORDER BY events DESC
        LIMIT {int(limit)}
    """
    rows: List[Dict[str, Any]] = []
    for row in get_ch_client().query(query).named_results():
        rows.append(
            {
                "asset": row["log_source"] or "unknown",
                "events": int(row["events"]),
                "last_seen": _fmt(row["last_seen"]),
                "notable_events": int(row["notable_events"]),
                "categories": [str(item) for item in row["categories"]],
            }
        )
    return rows


def fetch_resource_overview() -> Dict[str, Any]:
    return {
        "clickhouse_ok": ch_ping(),
        "events_total": int(_scalar("SELECT count() FROM siem.events")),
        "alerts_raw_total": int(_scalar("SELECT count() FROM siem.alerts_raw")),
        "alerts_agg_total": int(_scalar("SELECT count() FROM siem.alerts_agg")),
        "normalizer_rules": int(_scalar("SELECT count() FROM siem.normalizer_rules WHERE enabled = 1")),
        "filter_rules": int(_scalar("SELECT count() FROM siem.filter_rules WHERE enabled = 1")),
        "stream_rules": int(_scalar("SELECT count() FROM siem.correlation_rules_stream WHERE enabled = 1")),
        "last_event_ts": _fmt(_scalar("SELECT max(ts) FROM siem.events")),
    }
