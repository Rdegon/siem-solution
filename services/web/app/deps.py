
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime
from functools import lru_cache
import re
from typing import Any, Dict, List
from urllib.parse import quote

import clickhouse_connect
import yaml

from .config import CONFIG


EVENT_ROW_LIMIT_DEFAULT = 250
EVENT_ROW_LIMIT_MAX = 1000
EVENT_WINDOWS = {
    '15m': "now() - INTERVAL 15 MINUTE",
    '1h': "now() - INTERVAL 1 HOUR",
    '6h': "now() - INTERVAL 6 HOUR",
    '24h': "now() - INTERVAL 24 HOUR",
    '7d': "now() - INTERVAL 7 DAY",
    'all': None,
}
EVENT_STORAGE_TABLES = {
    'hot': 'siem.events',
    'cold': 'siem.events_cold',
}
EVENT_BASE_SELECT_SQL = """
    SELECT
        ts,
        event_id,
        category,
        subcategory,
        event_action,
        event_outcome,
        if(src_ip = 0, '', IPv4NumToString(src_ip)) AS src_ip,
        if(dst_ip = 0, '', IPv4NumToString(dst_ip)) AS dst_ip,
        src_port,
        dst_port,
        device_vendor,
        device_product,
        log_source,
        host_name,
        user_name,
        target_user,
        process_name,
        process_executable,
        process_command,
        lower(severity) AS severity,
        message,
        normalized_json,
        tags
""".strip()
EVENT_VIEW_COLUMNS = [
    'ts',
    'event_id',
    'category',
    'subcategory',
    'event_action',
    'event_outcome',
    'src_ip',
    'dst_ip',
    'src_port',
    'dst_port',
    'device_vendor',
    'device_product',
    'log_source',
    'host_name',
    'user_name',
    'target_user',
    'process_name',
    'process_executable',
    'process_command',
    'severity',
    'message',
    'normalized_json',
    'tags',
]
ALLOWED_EVENT_FIELDS = set(EVENT_VIEW_COLUMNS)
FORBIDDEN_SQL_RE = re.compile(
    r"\b(insert|update|delete|drop|alter|create|truncate|optimize|attach|detach|rename|grant|revoke|kill|system|use|set)\b",
    re.IGNORECASE,
)
COMMENT_SQL_RE = re.compile(r"(--|/\*|\*/)")
FULL_SQL_RE = re.compile(r"^\s*(select|with)\b", re.IGNORECASE)
LIMIT_RE = re.compile(r"\blimit\s+(\d+)\b", re.IGNORECASE)
EVENT_VIEW_FROM_RE = re.compile(r"\b(from|join)\s+events_view\b", re.IGNORECASE)
EVENT_TABLE_FROM_RE = re.compile(r"\b(from|join)\s+siem\.events\b", re.IGNORECASE)
SIGMA_CONDITION_TOKEN_RE = re.compile(r"\(|\)|\b(?:and|or|not)\b|[A-Za-z0-9_*]+", re.IGNORECASE)
DETECTION_RULE_TABLE = "siem.detection_rule_catalog"
ACTIVE_LIST_TABLE = "siem.active_list_items"
ALERT_HISTORY_TABLE = "siem.alert_history"
EVENTS_COLD_TABLE = "siem.events_cold"
INCIDENT_STATUS_TRANSITIONS = {
    "new": {"triaged", "assigned", "closed", "false_positive"},
    "open": {"triaged", "assigned", "in_progress", "closed", "false_positive"},
    "triaged": {"assigned", "in_progress", "closed", "false_positive"},
    "assigned": {"in_progress", "closed", "false_positive"},
    "in_progress": {"closed", "false_positive", "assigned"},
    "closed": {"reopened"},
    "false_positive": {"reopened"},
    "reopened": {"assigned", "in_progress", "closed", "false_positive"},
}


def _event_select_sql(table_name: str) -> str:
    return f"{EVENT_BASE_SELECT_SQL}\n    FROM {table_name}"


def _event_view_sql(storage: str = 'hot') -> str:
    if storage == 'all':
        ensure_cold_storage_support()
        return f"{_event_select_sql('siem.events')} UNION ALL {_event_select_sql(EVENTS_COLD_TABLE)}"
    table_name = EVENT_STORAGE_TABLES.get(storage, 'siem.events')
    if storage == 'cold':
        ensure_cold_storage_support()
    return _event_select_sql(table_name)


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
    if isinstance(value, (list, tuple)):
        return [_fmt(item) for item in value]
    if isinstance(value, dict):
        return {key: _fmt(item) for key, item in value.items()}
    return value


def _scalar(query: str) -> Any:
    result = get_ch_client().query(query)
    if not result.result_rows:
        return 0
    return result.result_rows[0][0]


def _event_time_filter(window: str) -> str:
    expr = EVENT_WINDOWS.get(window, EVENT_WINDOWS['24h'])
    if expr is None:
        return "1"
    return f"ts >= {expr}"


def _sql_quote(value: str) -> str:
    return "'" + value.replace("\\", "\\\\").replace("'", "''") + "'"


def _search_expr_for_token(token: str) -> str:
    quoted = _sql_quote(token)
    haystack = (
        "concat(toString(ts), ' ', toString(event_id), ' ', category, ' ', subcategory, ' ', "
        "event_action, ' ', event_outcome, ' ', "
        "src_ip, ' ', dst_ip, ' ', toString(src_port), ' ', toString(dst_port), ' ', "
        "device_vendor, ' ', device_product, ' ', log_source, ' ', host_name, ' ', user_name, ' ', "
        "target_user, ' ', process_name, ' ', process_executable, ' ', process_command, ' ', "
        "severity, ' ', message, ' ', normalized_json, ' ', tags)"
    )
    return f"positionCaseInsensitiveUTF8({haystack}, {quoted}) > 0"


def _field_expr(field: str, expected: str) -> str:
    if field not in ALLOWED_EVENT_FIELDS:
        return _search_expr_for_token(f"{field}:{expected}")
    quoted = _sql_quote(expected)
    return f"positionCaseInsensitiveUTF8(toString({field}), {quoted}) > 0"


def _build_token_query(raw_query: str) -> str:
    expressions: List[str] = []
    for token in raw_query.split():
        if not token:
            continue
        if ':' in token and not token.startswith('http'):
            field, expected = token.split(':', 1)
            expressions.append(_field_expr(field.strip(), expected.strip()))
            continue
        expressions.append(_search_expr_for_token(token))
    return ' AND '.join(expressions) if expressions else '1'


def _looks_like_expression(raw_query: str) -> bool:
    lower = raw_query.lower()
    markers = ['=', '!=', '>=', '<=', '<', '>', ' like ', ' ilike ', ' and ', ' or ', ' in ', ' not ', ' match(', '(', ')', "'", ' between ']
    return any(marker in lower for marker in markers)


def _validate_read_only_sql(raw_query: str) -> str:
    query = raw_query.strip().rstrip(';')
    if not query:
        raise ValueError('Query is empty')
    if COMMENT_SQL_RE.search(query):
        raise ValueError('Comments are not allowed in the query editor')
    if ';' in query:
        raise ValueError('Only a single statement is allowed')
    if FORBIDDEN_SQL_RE.search(query):
        raise ValueError('Only read-only SELECT/WITH queries are allowed')
    return query


def _ensure_limit(sql: str, limit: int) -> str:
    match = LIMIT_RE.search(sql)
    if not match:
        return f"{sql}\nLIMIT {limit}"
    current = int(match.group(1))
    if current <= limit:
        return sql
    return LIMIT_RE.sub(f"LIMIT {limit}", sql, count=1)


def _resolve_select_query(raw_query: str, limit: int, storage: str) -> str:
    query = _validate_read_only_sql(raw_query)
    view_sql = _event_view_sql(storage)
    if 'events_view' in query.lower():
        resolved = EVENT_VIEW_FROM_RE.sub(rf"\1 ({view_sql}) AS events_view", query)
    else:
        resolved = EVENT_TABLE_FROM_RE.sub(rf"\1 ({view_sql}) AS events_view", query)
    if ' from ' not in resolved.lower():
        raise ValueError('SELECT query must include a FROM clause')
    if resolved == query and 'events_view' not in query.lower() and 'siem.events' not in query.lower():
        raise ValueError("Read-only SELECT must query from events_view or siem.events")
    return _ensure_limit(resolved, limit)


def _build_events_sql(query_text: str, window: str, limit: int, storage: str = 'hot') -> str:
    limit = max(1, min(limit, EVENT_ROW_LIMIT_MAX))
    storage = storage if storage in {'hot', 'cold', 'all'} else 'hot'
    query_text = (query_text or '').strip()
    if not query_text:
        expression = '1'
    elif FULL_SQL_RE.match(query_text):
        return _resolve_select_query(query_text, limit, storage)
    elif _looks_like_expression(query_text):
        expression = _validate_read_only_sql(query_text)
    else:
        expression = _build_token_query(query_text)

    return (
        f"SELECT\n"
        f"    ts,\n"
        f"    event_id,\n"
        f"    category,\n"
        f"    subcategory,\n"
        f"    event_action,\n"
        f"    event_outcome,\n"
        f"    src_ip,\n"
        f"    dst_ip,\n"
        f"    src_port,\n"
        f"    dst_port,\n"
        f"    device_vendor,\n"
        f"    device_product,\n"
        f"    log_source,\n"
        f"    host_name,\n"
        f"    user_name,\n"
        f"    target_user,\n"
        f"    process_name,\n"
        f"    process_executable,\n"
        f"    process_command,\n"
        f"    severity,\n"
        f"    message,\n"
        f"    normalized_json,\n"
        f"    tags\n"
        f"FROM ({_event_view_sql(storage)}) AS events_view\n"
        f"WHERE {_event_time_filter(window)}\n"
        f"  AND ({expression})\n"
        f"ORDER BY ts DESC\n"
        f"LIMIT {limit}"
    )


def _rows_from_query(sql: str) -> Dict[str, Any]:
    result = get_ch_client().query(sql)
    columns = [str(name) for name in result.column_names]
    rows: List[Dict[str, Any]] = []
    for raw_row in result.result_rows:
        rows.append({columns[index]: _fmt(value) for index, value in enumerate(raw_row)})
    return {'columns': columns, 'rows': rows}


def _parse_ts(value: Any) -> datetime | None:
    text = str(value or '').strip()
    if not text:
        return None
    try:
        return datetime.fromisoformat(text.replace(' ', 'T'))
    except ValueError:
        return None


def _bucket_rows(rows: List[Dict[str, Any]], bucket_minutes: int = 15) -> List[Dict[str, Any]]:
    buckets: Dict[str, int] = defaultdict(int)
    for row in rows:
        dt = _parse_ts(row.get('ts'))
        if not dt:
            continue
        minute = (dt.minute // bucket_minutes) * bucket_minutes
        bucket = dt.replace(minute=minute, second=0, microsecond=0).strftime('%Y-%m-%d %H:%M:%S')
        buckets[bucket] += 1
    return [{'bucket': key, 'count': buckets[key]} for key in sorted(buckets)]


def _severity_stats(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    order = ['critical', 'high', 'medium', 'low', 'info', 'unknown']
    counts = Counter(str(row.get('severity') or 'unknown').lower() for row in rows)
    return [{'label': name, 'count': counts.get(name, 0)} for name in order if counts.get(name, 0)]


def _source_stats(rows: List[Dict[str, Any]], limit: int = 8) -> List[Dict[str, Any]]:
    counts = Counter(str(row.get('log_source') or 'unknown') for row in rows)
    return [{'label': key, 'count': value} for key, value in counts.most_common(limit)]


def execute_event_query(query_text: str, window: str = '24h', limit: int = EVENT_ROW_LIMIT_DEFAULT, storage: str = 'hot') -> Dict[str, Any]:
    sql = _build_events_sql(query_text=query_text, window=window, limit=limit, storage=storage)
    result = _rows_from_query(sql)
    rows = result['rows']
    return {
        'sql': sql,
        'storage': storage,
        'columns': result['columns'],
        'rows': rows,
        'row_count': len(rows),
        'histogram': _bucket_rows(rows, bucket_minutes=15),
        'severity_stats': _severity_stats(rows),
        'source_stats': _source_stats(rows),
    }


def fetch_alerts_agg(limit: int = 200) -> List[Dict[str, Any]]:
    ensure_incident_workflow_support()
    query = f"""
        SELECT
            ts,
            agg_id,
            rule_id,
            rule_name,
            lower(severity_agg) AS severity_agg,
            ts_first,
            ts_last,
            count_alerts,
            unique_entities,
            entity_key,
            group_key_json,
            samples_json,
            status,
            assignee,
            updated_ts
        FROM siem.alerts_agg
        ORDER BY ts_last DESC
        LIMIT {int(limit)}
    """
    rows: List[Dict[str, Any]] = []
    for row in get_ch_client().query(query).named_results():
        rows.append(
            {
                'ts': _fmt(row['ts']),
                'agg_id': str(row['agg_id']),
                'rule_id': row['rule_id'],
                'rule_name': row['rule_name'],
                'severity_agg': str(row['severity_agg']).lower(),
                'ts_first': _fmt(row['ts_first']),
                'ts_last': _fmt(row['ts_last']),
                'count_alerts': int(row['count_alerts']),
                'unique_entities': int(row['unique_entities']),
                'entity_key': row['entity_key'],
                'group_key_json': row['group_key_json'],
                'samples_json': row['samples_json'],
                'status': str(row['status']).lower(),
                'assignee': row.get('assignee', ''),
                'updated_ts': _fmt(row.get('updated_ts')),
            }
        )
    return rows


def fetch_alerts_raw(limit: int = 200) -> List[Dict[str, Any]]:
    ensure_incident_workflow_support()
    query = f"""
        SELECT
            ts,
            alert_id,
            rule_id,
            rule_name,
            lower(severity) AS severity,
            ts_first,
            ts_last,
            window_s,
            entity_key,
            hits,
            context_json,
            source,
            status,
            assignee,
            updated_ts
        FROM siem.alerts_raw
        ORDER BY ts_last DESC
        LIMIT {int(limit)}
    """
    rows: List[Dict[str, Any]] = []
    for row in get_ch_client().query(query).named_results():
        rows.append(
            {
                'ts': _fmt(row['ts']),
                'alert_id': str(row['alert_id']),
                'rule_id': row['rule_id'],
                'rule_name': row['rule_name'],
                'severity': str(row['severity']).lower(),
                'ts_first': _fmt(row['ts_first']),
                'ts_last': _fmt(row['ts_last']),
                'window_s': int(row['window_s']),
                'entity_key': row['entity_key'],
                'hits': int(row['hits']),
                'context_json': row['context_json'],
                'source': row['source'],
                'status': str(row['status']).lower(),
                'assignee': row.get('assignee', ''),
                'updated_ts': _fmt(row.get('updated_ts')),
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
        rows.append({'bucket': _fmt(bucket), 'cnt': int(cnt)})
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
        rows.append({'severity': severity or 'unknown', 'cnt': int(cnt)})
    return rows


def fetch_alert_severity_breakdown(hours: int = 24) -> List[Dict[str, Any]]:
    query = f"""
        SELECT lower(severity) AS severity, count() AS cnt
        FROM siem.alerts_raw
        WHERE ts >= now() - INTERVAL {int(hours)} HOUR
        GROUP BY severity
        ORDER BY cnt DESC
    """
    rows: List[Dict[str, Any]] = []
    for severity, cnt in get_ch_client().query(query).result_rows:
        rows.append({'severity': severity or 'unknown', 'cnt': int(cnt)})
    return rows


def fetch_alert_status_breakdown(hours: int = 24) -> List[Dict[str, Any]]:
    query = f"""
        SELECT lower(status) AS status, count() AS cnt
        FROM siem.alerts_raw
        WHERE ts >= now() - INTERVAL {int(hours)} HOUR
        GROUP BY status
        ORDER BY cnt DESC
    """
    rows: List[Dict[str, Any]] = []
    for status, cnt in get_ch_client().query(query).result_rows:
        rows.append({'status': status or 'unknown', 'cnt': int(cnt)})
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
                'log_source': row['log_source'] or 'unknown',
                'events': int(row['events']),
                'last_seen': _fmt(row['last_seen']),
                'critical_count': int(row['critical_count']),
                'high_count': int(row['high_count']),
            }
        )
    return rows


def fetch_top_categories(limit: int = 8, hours: int = 24) -> List[Dict[str, Any]]:
    query = f"""
        SELECT category, count() AS events
        FROM siem.events
        WHERE ts >= now() - INTERVAL {int(hours)} HOUR
        GROUP BY category
        ORDER BY events DESC
        LIMIT {int(limit)}
    """
    rows: List[Dict[str, Any]] = []
    for category, events in get_ch_client().query(query).result_rows:
        rows.append({'category': str(category or 'unknown'), 'events': int(events)})
    return rows


def fetch_dashboard_metrics() -> Dict[str, Any]:
    return {
        'events_24h': int(_scalar("SELECT count() FROM siem.events WHERE ts >= now() - INTERVAL 24 HOUR")),
        'events_1h': int(_scalar("SELECT count() FROM siem.events WHERE ts >= now() - INTERVAL 1 HOUR")),
        'open_incidents_24h': int(_scalar("SELECT count() FROM siem.alerts_agg WHERE ts >= now() - INTERVAL 24 HOUR AND lower(status) != 'closed'")),
        'new_alerts_24h': int(_scalar("SELECT count() FROM siem.alerts_raw WHERE ts >= now() - INTERVAL 24 HOUR AND lower(status) = 'new'")),
        'critical_events_24h': int(_scalar("SELECT count() FROM siem.events WHERE ts >= now() - INTERVAL 24 HOUR AND lower(severity) = 'critical'")),
        'active_sources_24h': int(_scalar("SELECT countDistinct(log_source) FROM siem.events WHERE ts >= now() - INTERVAL 24 HOUR")),
        'audit_events_24h': int(_scalar("SELECT count() FROM siem.events WHERE ts >= now() - INTERVAL 24 HOUR AND message LIKE '%auditd:%'")),
    }


def fetch_alert_metrics() -> Dict[str, Any]:
    ensure_incident_workflow_support()
    return {
        'agg_total': int(_scalar("SELECT count() FROM siem.alerts_agg")),
        'agg_open': int(_scalar("SELECT count() FROM siem.alerts_agg WHERE lower(status) != 'closed'")),
        'raw_total': int(_scalar("SELECT count() FROM siem.alerts_raw")),
        'critical_raw': int(_scalar("SELECT count() FROM siem.alerts_raw WHERE lower(severity) = 'critical'")),
        'new_raw': int(_scalar("SELECT count() FROM siem.alerts_raw WHERE lower(status) = 'new'")),
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
            groupUniqArray(4)(category) AS categories,
            countIf(message LIKE '%auditd:%') AS audit_events
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
                'asset': row['log_source'] or 'unknown',
                'events': int(row['events']),
                'last_seen': _fmt(row['last_seen']),
                'notable_events': int(row['notable_events']),
                'audit_events': int(row['audit_events']),
                'categories': [str(item) for item in row['categories']],
            }
        )
    return rows


def fetch_resource_overview() -> Dict[str, Any]:
    ensure_detection_support_tables()
    ensure_incident_workflow_support()
    ensure_active_list_support()
    ensure_cold_storage_support()
    return {
        'clickhouse_ok': ch_ping(),
        'events_total': int(_scalar("SELECT count() FROM siem.events")) + int(_scalar(f"SELECT count() FROM {EVENTS_COLD_TABLE}")),
        'events_hot_total': int(_scalar("SELECT count() FROM siem.events")),
        'events_cold_total': int(_scalar(f"SELECT count() FROM {EVENTS_COLD_TABLE}")),
        'alerts_raw_total': int(_scalar("SELECT count() FROM siem.alerts_raw")),
        'alerts_agg_total': int(_scalar("SELECT count() FROM siem.alerts_agg")),
        'normalizer_rules': int(_scalar("SELECT count() FROM siem.normalizer_rules WHERE enabled = 1")),
        'filter_rules': int(_scalar("SELECT count() FROM siem.filter_rules WHERE enabled = 1")),
        'stream_rules': int(_scalar("SELECT count() FROM siem.correlation_rules_stream WHERE enabled = 1")),
        'detection_rules': int(_scalar(f"SELECT count() FROM {DETECTION_RULE_TABLE}")),
        'active_list_items': int(_scalar(f"SELECT count() FROM {ACTIVE_LIST_TABLE}")),
        'incident_history_rows': int(_scalar(f"SELECT count() FROM {ALERT_HISTORY_TABLE}")),
        'last_event_ts': _fmt(_scalar("SELECT max(ts) FROM siem.events")),
        'hot_retention_hours': int(CONFIG.hot_retention_hours),
        'cold_retention_days': int(CONFIG.cold_retention_days),
    }


def ensure_cold_storage_support() -> None:
    get_ch_client().command(
        f"""
        CREATE TABLE IF NOT EXISTS {EVENTS_COLD_TABLE}
        (
            ts DateTime,
            event_id String,
            category String,
            subcategory String,
            event_action String DEFAULT '',
            event_outcome String DEFAULT '',
            src_ip UInt32,
            dst_ip UInt32,
            src_port UInt16,
            dst_port UInt16,
            device_vendor String,
            device_product String,
            log_source String,
            host_name String DEFAULT '',
            user_name String DEFAULT '',
            target_user String DEFAULT '',
            process_name String DEFAULT '',
            process_executable String DEFAULT '',
            process_command String DEFAULT '',
            severity String,
            message String,
            normalized_json String DEFAULT '',
            tags String
        )
        ENGINE = MergeTree
        ORDER BY (ts, log_source, event_id)
        """
    )


def ensure_incident_workflow_support() -> None:
    for table in ("siem.alerts_raw", "siem.alerts_agg"):
        get_ch_client().command(f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS assignee String DEFAULT ''")
        get_ch_client().command(f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS updated_ts DateTime DEFAULT now()")
    get_ch_client().command(
        f"""
        CREATE TABLE IF NOT EXISTS {ALERT_HISTORY_TABLE}
        (
            changed_ts DateTime DEFAULT now(),
            view LowCardinality(String),
            record_id String,
            rule_id UInt32,
            previous_status LowCardinality(String),
            next_status LowCardinality(String),
            previous_assignee String,
            next_assignee String,
            changed_by String,
            note String
        )
        ENGINE = MergeTree
        ORDER BY (view, record_id, changed_ts)
        """
    )


def ensure_active_list_support() -> None:
    get_ch_client().command(
        f"""
        CREATE TABLE IF NOT EXISTS {ACTIVE_LIST_TABLE}
        (
            list_name LowCardinality(String),
            list_kind LowCardinality(String) DEFAULT 'watch',
            value String,
            value_type LowCardinality(String),
            label String,
            tags String,
            enabled UInt8,
            updated_ts DateTime DEFAULT now()
        )
        ENGINE = MergeTree
        ORDER BY (list_name, value)
        """
    )
    get_ch_client().command(f"ALTER TABLE {ACTIVE_LIST_TABLE} ADD COLUMN IF NOT EXISTS list_kind LowCardinality(String) DEFAULT 'watch'")


def fetch_active_list_items(limit: int = 200) -> List[Dict[str, Any]]:
    ensure_active_list_support()
    query = f"""
        SELECT
            list_name,
            list_kind,
            value_type,
            value,
            label,
            tags,
            enabled,
            updated_ts
        FROM {ACTIVE_LIST_TABLE}
        ORDER BY updated_ts DESC, list_name, value
        LIMIT {int(limit)}
    """
    return [
        {
            "list_name": row["list_name"],
            "list_kind": row.get("list_kind", "watch"),
            "item_type": row["value_type"],
            "item_value": row["value"],
            "item_label": row["label"],
            "tags": [part for part in str(row["tags"] or "").split(",") if part],
            "enabled": bool(row["enabled"]),
            "updated_ts": _fmt(row["updated_ts"]),
        }
        for row in get_ch_client().query(query).named_results()
    ]


def save_active_list_item(
    *,
    list_name: str,
    list_kind: str,
    item_type: str,
    item_value: str,
    item_label: str = "",
    tags: str = "",
) -> Dict[str, Any]:
    ensure_active_list_support()
    safe_list_name = (list_name or "").strip()
    safe_list_kind = (list_kind or "watch").strip().lower()
    safe_item_type = (item_type or "").strip().lower()
    safe_item_value = (item_value or "").strip()
    safe_item_label = (item_label or "").strip()
    safe_tags = ",".join(part.strip() for part in str(tags or "").split(",") if part.strip())
    if safe_list_kind not in {"watch", "allow", "deny"}:
        raise ValueError("Active list kind must be watch, allow or deny")
    if not safe_list_name or not safe_item_type or not safe_item_value:
        raise ValueError("Active list name, item type and item value are required")
    get_ch_client().command(
        f"""
        ALTER TABLE {ACTIVE_LIST_TABLE}
        DELETE WHERE
            list_name = {_sql_quote(safe_list_name)}
            AND list_kind = {_sql_quote(safe_list_kind)}
            AND value_type = {_sql_quote(safe_item_type)}
            AND value = {_sql_quote(safe_item_value)}
        """
    )
    get_ch_client().insert(
        ACTIVE_LIST_TABLE,
        [[safe_list_name, safe_list_kind, safe_item_value, safe_item_type, safe_item_label, safe_tags, 1]],
        column_names=["list_name", "list_kind", "value", "value_type", "label", "tags", "enabled"],
    )
    return {
        "list_name": safe_list_name,
        "list_kind": safe_list_kind,
        "item_type": safe_item_type,
        "item_value": safe_item_value,
        "item_label": safe_item_label,
        "tags": safe_tags,
    }


def archive_events_to_cold(older_than_hours: int) -> Dict[str, Any]:
    ensure_cold_storage_support()
    safe_hours = max(1, int(older_than_hours))
    threshold = f"now() - INTERVAL {safe_hours} HOUR"
    moved_rows = int(
        _scalar(
            f"""
            SELECT count()
            FROM siem.events
            WHERE ts < {threshold}
            """
        )
    )
    if moved_rows <= 0:
        return {
            "moved_rows": 0,
            "older_than_hours": safe_hours,
            "status": "no-op",
        }
    get_ch_client().command(
        f"""
        INSERT INTO {EVENTS_COLD_TABLE}
        SELECT
            ts,
            event_id,
            category,
            subcategory,
            event_action,
            event_outcome,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            device_vendor,
            device_product,
            log_source,
            host_name,
            user_name,
            target_user,
            process_name,
            process_executable,
            process_command,
            severity,
            message,
            normalized_json,
            tags
        FROM siem.events
        WHERE ts < {threshold}
        """
    )
    get_ch_client().command(
        f"""
        ALTER TABLE siem.events
        DELETE WHERE ts < {threshold}
        """
    )
    return {
        "moved_rows": moved_rows,
        "older_than_hours": safe_hours,
        "status": "archived",
    }


def fetch_alert_history(view: str, record_id: str, limit: int = 50) -> List[Dict[str, Any]]:
    ensure_incident_workflow_support()
    query = f"""
        SELECT
            changed_ts,
            view,
            record_id,
            rule_id,
            previous_status,
            next_status,
            previous_assignee,
            next_assignee,
            changed_by,
            note
        FROM {ALERT_HISTORY_TABLE}
        WHERE view = {_sql_quote(view)}
          AND record_id = {_sql_quote(record_id)}
        ORDER BY changed_ts DESC
        LIMIT {int(limit)}
    """
    return [
        {
            "changed_ts": _fmt(row["changed_ts"]),
            "view": row["view"],
            "record_id": row["record_id"],
            "rule_id": int(row["rule_id"]),
            "previous_status": row["previous_status"],
            "next_status": row["next_status"],
            "previous_assignee": row["previous_assignee"],
            "next_assignee": row["next_assignee"],
            "changed_by": row["changed_by"],
            "note": row["note"],
        }
        for row in get_ch_client().query(query).named_results()
    ]


def update_alert_assignment(
    view: str,
    record_id: str,
    *,
    status: str,
    assignee: str,
    changed_by: str,
    note: str = "",
) -> Dict[str, Any]:
    ensure_incident_workflow_support()
    target = "siem.alerts_raw" if view == "raw" else "siem.alerts_agg"
    id_column = "alert_id" if view == "raw" else "agg_id"
    next_status = (status or "new").strip().lower()
    next_assignee = (assignee or "").strip()
    safe_status = _sql_quote(next_status)
    safe_assignee = _sql_quote(next_assignee)
    safe_id = _sql_quote(record_id)
    current_query = f"""
        SELECT rule_id, lower(status) AS status, assignee
        FROM {target}
        WHERE toString({id_column}) = {safe_id}
        LIMIT 1
    """
    result = get_ch_client().query(current_query).result_rows
    if not result:
        raise ValueError("Alert or incident not found")
    rule_id, current_status, current_assignee = result[0]
    current_status = str(current_status or "new").lower()
    current_assignee = str(current_assignee or "")
    if next_status != current_status:
        allowed = INCIDENT_STATUS_TRANSITIONS.get(current_status, set())
        if next_status not in allowed:
            raise ValueError(f"Invalid transition: {current_status} -> {next_status}")
    get_ch_client().command(
        f"""
        ALTER TABLE {target}
        UPDATE
            status = {safe_status},
            assignee = {safe_assignee},
            updated_ts = now()
        WHERE toString({id_column}) = {safe_id}
        """
    )
    get_ch_client().insert(
        ALERT_HISTORY_TABLE,
        [[
            view,
            str(record_id),
            int(rule_id),
            current_status,
            next_status,
            current_assignee,
            next_assignee,
            (changed_by or "web").strip() or "web",
            (note or "").strip(),
        ]],
        column_names=[
            "view",
            "record_id",
            "rule_id",
            "previous_status",
            "next_status",
            "previous_assignee",
            "next_assignee",
            "changed_by",
            "note",
        ],
    )
    return {"view": view, "record_id": record_id, "status": next_status, "assignee": next_assignee}


DEFAULT_SIGMA_RULES = [
    {
        "id": 1001,
        "title": "Linux SSH Brute Force Burst",
        "level": "high",
        "window_s": 300,
        "threshold": 5,
        "entity_field": "source.ip",
        "yaml": """
title: Linux SSH Brute Force Burst
id: sigma-linux-ssh-bruteforce-burst
status: experimental
logsource:
  product: linux
  service: sshd
detection:
  selection:
    event.provider: linux.sshd
    event.type: ssh_login_failure
  condition: selection
level: high
tags:
  - attack.credential_access
  - attack.t1110
""".strip(),
    },
    {
        "id": 1002,
        "title": "Linux Audit USER_LOGIN Failures",
        "level": "medium",
        "window_s": 300,
        "threshold": 3,
        "entity_field": "source.ip",
        "yaml": """
title: Linux Audit USER_LOGIN Failures
id: sigma-linux-audit-user-login-failure
status: experimental
logsource:
  product: linux
  service: auditd
detection:
  selection:
    event.provider: linux.auditd
    event.type: audit_user_login_failure
  condition: selection
level: medium
tags:
  - attack.credential_access
  - attack.t1078
""".strip(),
    },
    {
        "id": 1003,
        "title": "Linux Sudo To Root",
        "level": "medium",
        "window_s": 300,
        "threshold": 1,
        "entity_field": "user.name",
        "yaml": """
title: Linux Sudo To Root
id: sigma-linux-sudo-to-root
status: experimental
logsource:
  product: linux
  service: sudo
detection:
  selection:
    event.provider: linux.sudo
    event.type: sudo_command
    user.target.name: root
  condition: selection
level: medium
tags:
  - attack.privilege_escalation
  - attack.t1548
""".strip(),
    },
    {
        "id": 1004,
        "title": "Linux Exec As Root Burst",
        "level": "high",
        "window_s": 600,
        "threshold": 3,
        "entity_field": "log_source",
        "yaml": """
title: Linux Exec As Root Burst
id: sigma-linux-exec-as-root-burst
status: experimental
logsource:
  product: linux
  service: auditd
detection:
  selection:
    event.provider: linux.auditd
    event.type: audit_exec_as_root
  condition: selection
level: high
tags:
  - attack.privilege_escalation
  - attack.execution
""".strip(),
    },
    {
        "id": 1005,
        "title": "Linux Root SSH Login Success",
        "level": "high",
        "window_s": 300,
        "threshold": 1,
        "entity_field": "source.ip",
        "yaml": """
title: Linux Root SSH Login Success
id: sigma-linux-root-ssh-login-success
status: experimental
logsource:
  product: linux
  service: sshd
detection:
  selection:
    event.provider: linux.sshd
    event.type: ssh_login_success
    user.name: root
  condition: selection
level: high
tags:
  - attack.initial_access
  - attack.t1078
""".strip(),
    },
    {
        "id": 1006,
        "title": "Linux Suspicious Download Utility",
        "level": "medium",
        "window_s": 300,
        "threshold": 1,
        "entity_field": "log_source",
        "yaml": """
title: Linux Suspicious Download Utility
id: sigma-linux-suspicious-download-utility
status: experimental
logsource:
  product: linux
  service: auditd
detection:
  selection_curl:
    event.provider: linux.auditd
    event.type: audit_execve
    process.command_line|contains: curl
  selection_wget:
    event.provider: linux.auditd
    event.type: audit_execve
    process.command_line|contains: wget
  condition: 1 of selection_*
level: medium
tags:
  - attack.command_and_control
  - attack.t1105
""".strip(),
    },
    {
        "id": 1007,
        "title": "Linux Netcat Execution",
        "level": "high",
        "window_s": 300,
        "threshold": 1,
        "entity_field": "log_source",
        "yaml": """
title: Linux Netcat Execution
id: sigma-linux-netcat-execution
status: experimental
logsource:
  product: linux
  service: auditd
detection:
  selection_nc:
    event.provider: linux.auditd
    event.type: audit_execve
    process.command_line|contains: nc
  selection_ncat:
    event.provider: linux.auditd
    event.type: audit_execve
    process.command_line|contains: ncat
  condition: 1 of selection_*
level: high
tags:
  - attack.command_and_control
  - attack.t1095
""".strip(),
    },
    {
        "id": 1008,
        "title": "Linux Sudo Root Session Opened",
        "level": "medium",
        "window_s": 300,
        "threshold": 1,
        "entity_field": "user.target.name",
        "yaml": """
title: Linux Sudo Root Session Opened
id: sigma-linux-sudo-root-session-opened
status: experimental
logsource:
  product: linux
  service: sudo
detection:
  selection:
    event.provider: linux.sudo
    event.type: sudo_session_opened
    user.target.name: root
  condition: selection
level: medium
tags:
  - attack.privilege_escalation
  - attack.t1548
""".strip(),
    },
    {
        "id": 1009,
        "title": "Linux Authorized Keys Modified",
        "level": "high",
        "window_s": 300,
        "threshold": 1,
        "entity_field": "log_source",
        "yaml": """
title: Linux Authorized Keys Modified
id: sigma-linux-authorized-keys-modified
status: experimental
logsource:
  product: linux
  service: auditd
detection:
  selection:
    event.provider: linux.auditd
    event.type: linux_authorized_keys_modified
  condition: selection
level: high
tags:
  - attack.persistence
  - attack.t1098
""".strip(),
    },
    {
        "id": 1010,
        "title": "Linux Cron Modified",
        "level": "high",
        "window_s": 300,
        "threshold": 1,
        "entity_field": "log_source",
        "yaml": """
title: Linux Cron Modified
id: sigma-linux-cron-modified
status: experimental
logsource:
  product: linux
  service: auditd
detection:
  selection:
    event.provider: linux.auditd
    event.type: linux_cron_modified
  condition: selection
level: high
tags:
  - attack.persistence
  - attack.t1053.003
""".strip(),
    },
    {
        "id": 1011,
        "title": "Linux Passwd Or Shadow Access",
        "level": "high",
        "window_s": 300,
        "threshold": 1,
        "entity_field": "log_source",
        "yaml": """
title: Linux Passwd Or Shadow Access
id: sigma-linux-passwd-shadow-access
status: experimental
logsource:
  product: linux
  service: auditd
detection:
  selection:
    event.provider: linux.auditd
    event.type: linux_passwd_shadow_access
  condition: selection
level: high
tags:
  - attack.credential_access
  - attack.t1003
""".strip(),
    },
    {
        "id": 1012,
        "title": "Linux User Added To Admin Group",
        "level": "high",
        "window_s": 300,
        "threshold": 1,
        "entity_field": "user.target.name",
        "yaml": """
title: Linux User Added To Admin Group
id: sigma-linux-user-added-to-admin-group
status: experimental
logsource:
  product: linux
  service: auditd
detection:
  selection:
    event.provider: linux.auditd
    event.type: linux_user_added_to_admin_group
  condition: selection
level: high
tags:
  - attack.privilege_escalation
  - attack.t1098
""".strip(),
    },
    {
        "id": 1013,
        "title": "Linux Execution From Tmp",
        "level": "high",
        "window_s": 300,
        "threshold": 1,
        "entity_field": "log_source",
        "yaml": """
title: Linux Execution From Tmp
id: sigma-linux-exec-from-tmp
status: experimental
logsource:
  product: linux
  service: auditd
detection:
  selection:
    event.provider: linux.auditd
    event.type: linux_exec_from_tmp
  condition: selection
level: high
tags:
  - attack.execution
  - attack.t1059
""".strip(),
    },
    {
        "id": 1014,
        "title": "Linux Reverse Shell Possible",
        "level": "critical",
        "window_s": 300,
        "threshold": 1,
        "entity_field": "log_source",
        "yaml": """
title: Linux Reverse Shell Possible
id: sigma-linux-reverse-shell-possible
status: experimental
logsource:
  product: linux
  service: auditd
detection:
  selection:
    event.provider: linux.auditd
    event.type: linux_reverse_shell_possible
  condition: selection
level: critical
tags:
  - attack.command_and_control
  - attack.t1059
""".strip(),
    },
    {
        "id": 1015,
        "title": "Linux Firewall Disabled",
        "level": "high",
        "window_s": 300,
        "threshold": 1,
        "entity_field": "log_source",
        "yaml": """
title: Linux Firewall Disabled
id: sigma-linux-firewall-disabled
status: experimental
logsource:
  product: linux
  service: auditd
detection:
  selection:
    event.provider: linux.auditd
    event.type: linux_firewall_disabled
  condition: selection
level: high
tags:
  - attack.defense_evasion
  - attack.t1562
""".strip(),
    },
    {
        "id": 1016,
        "title": "Linux Audit Rules Cleared",
        "level": "high",
        "window_s": 300,
        "threshold": 1,
        "entity_field": "log_source",
        "yaml": """
title: Linux Audit Rules Cleared
id: sigma-linux-audit-rules-cleared
status: experimental
logsource:
  product: linux
  service: auditd
detection:
  selection:
    event.provider: linux.auditd
    event.type: linux_audit_rules_cleared
  condition: selection
level: high
tags:
  - attack.defense_evasion
  - attack.t1562
""".strip(),
    },
    {
        "id": 1017,
        "title": "Linux Audit Config Changed",
        "level": "high",
        "window_s": 300,
        "threshold": 1,
        "entity_field": "log_source",
        "yaml": """
title: Linux Audit Config Changed
id: sigma-linux-audit-config-changed
status: experimental
logsource:
  product: linux
  service: auditd
detection:
  selection:
    event.provider: linux.auditd
    event.type: linux_audit_config_changed
  condition: selection
level: high
tags:
  - attack.defense_evasion
  - attack.t1562
""".strip(),
    },
    {
        "id": 1018,
        "title": "Linux User Created",
        "level": "medium",
        "window_s": 300,
        "threshold": 1,
        "entity_field": "user.target.name",
        "yaml": """
title: Linux User Created
id: sigma-linux-user-created
status: experimental
logsource:
  product: linux
  service: auditd
detection:
  selection:
    event.provider: linux.auditd
    event.type: linux_user_created
  condition: selection
level: medium
tags:
  - attack.persistence
  - attack.t1136
""".strip(),
    },
    {
        "id": 1019,
        "title": "Linux User Deleted",
        "level": "medium",
        "window_s": 300,
        "threshold": 1,
        "entity_field": "user.target.name",
        "yaml": """
title: Linux User Deleted
id: sigma-linux-user-deleted
status: experimental
logsource:
  product: linux
  service: auditd
detection:
  selection:
    event.provider: linux.auditd
    event.type: linux_user_deleted
  condition: selection
level: medium
tags:
  - attack.defense_evasion
  - attack.t1531
""".strip(),
    },
    {
        "id": 1020,
        "title": "Linux Password Changed",
        "level": "medium",
        "window_s": 300,
        "threshold": 1,
        "entity_field": "user.target.name",
        "yaml": """
title: Linux Password Changed
id: sigma-linux-password-changed
status: experimental
logsource:
  product: linux
  service: auditd
detection:
  selection:
    event.provider: linux.auditd
    event.type: linux_password_changed
  condition: selection
level: medium
tags:
  - attack.credential_access
  - attack.t1098
""".strip(),
    },
    {
        "id": 1021,
        "title": "Linux LD Preload Modified",
        "level": "critical",
        "window_s": 300,
        "threshold": 1,
        "entity_field": "log_source",
        "yaml": """
title: Linux LD Preload Modified
id: sigma-linux-ld-preload-modified
status: experimental
logsource:
  product: linux
  service: auditd
detection:
  selection:
    event.provider: linux.auditd
    event.type: linux_ld_preload_modified
  condition: selection
level: critical
tags:
  - attack.persistence
  - attack.t1574
""".strip(),
    },
    {
        "id": 1022,
        "title": "Denylist Entity Observed",
        "level": "high",
        "window_s": 300,
        "threshold": 1,
        "entity_field": "log_source",
        "yaml": """
title: Denylist Entity Observed
id: sigma-denylist-entity-observed
status: experimental
logsource:
  product: linux
  service: enriched
detection:
  selection:
    keywords:
      - 'denylist:'
  condition: selection
level: high
tags:
    - enrichment.denylist
    - attack.resource_development
""".strip(),
    },
    {
        "id": 1023,
        "title": "Linux Sudoers Modified",
        "level": "high",
        "window_s": 300,
        "threshold": 1,
        "entity_field": "log_source",
        "yaml": """
title: Linux Sudoers Modified
id: sigma-linux-sudoers-modified
status: experimental
logsource:
  product: linux
  service: auditd
detection:
  selection:
    event.provider: linux.auditd
    event.type: linux_sudoers_modified
  condition: selection
level: high
tags:
  - attack.privilege_escalation
  - attack.t1548
""".strip(),
    },
    {
        "id": 1024,
        "title": "Linux Systemd Unit Modified",
        "level": "high",
        "window_s": 300,
        "threshold": 1,
        "entity_field": "log_source",
        "yaml": """
title: Linux Systemd Unit Modified
id: sigma-linux-systemd-unit-modified
status: experimental
logsource:
  product: linux
  service: auditd
detection:
  selection:
    event.provider: linux.auditd
    event.type: linux_systemd_unit_modified
  condition: selection
level: high
tags:
  - attack.persistence
  - attack.t1543
""".strip(),
    },
]


def ensure_detection_support_tables() -> None:
    get_ch_client().command(
        f"""
        CREATE TABLE IF NOT EXISTS {DETECTION_RULE_TABLE}
        (
            id UInt32,
            title String,
            sigma_id String,
            status LowCardinality(String),
            level LowCardinality(String),
            source_format LowCardinality(String),
            logsource_product String,
            logsource_service String,
            logsource_category String,
            sigma_yaml String,
            expr String,
            entity_field String,
            window_s UInt32,
            threshold UInt32,
            verification_query String,
            tags String,
            description String,
            enabled UInt8,
            author String,
            created_ts DateTime DEFAULT now(),
            updated_ts DateTime DEFAULT now()
        )
        ENGINE = MergeTree
        ORDER BY (id)
        """
    )
    _seed_default_sigma_rules()


def _map_sigma_field(field_name: str, *, target: str = "stream") -> tuple[str, str]:
    parts = field_name.split("|")
    field = parts[0].strip()
    modifier = parts[1].strip().lower() if len(parts) > 1 else "eq"
    field_key = field.lower()
    if target == "events":
        field_map = {
            "message": ("message", "contains"),
            "event.original": ("message", "contains"),
            "event.provider": ("device_product", "eq"),
            "event.category": ("category", "eq"),
            "event.type": ("subcategory", "eq"),
            "event.action": ("event_action", "eq"),
            "event.outcome": ("event_outcome", "eq"),
            "logsource": ("log_source", "eq"),
            "log_source": ("log_source", "eq"),
            "severity": ("severity", "eq"),
            "sourceip": ("src_ip", "eq"),
            "source.ip": ("src_ip", "eq"),
            "clientaddress": ("src_ip", "eq"),
            "ipaddress": ("src_ip", "eq"),
            "host": ("log_source", "eq"),
            "host.name": ("host_name", "eq"),
            "user": ("user_name", "contains"),
            "username": ("user_name", "contains"),
            "accountname": ("user_name", "contains"),
            "user.name": ("user_name", "contains"),
            "targetuser": ("target_user", "contains"),
            "targetusername": ("target_user", "contains"),
            "user.target.name": ("target_user", "contains"),
            "commandline": ("process_command", "contains"),
            "process.command_line": ("process_command", "contains"),
            "image": ("process_executable", "contains"),
            "process.executable": ("process_executable", "contains"),
            "process.name": ("process_name", "contains"),
        }
        normalized, default_modifier = field_map.get(field_key, ("message", "contains"))
        effective_modifier = modifier if modifier != "eq" else default_modifier
    else:
        field_map = {
            "message": "event.original",
            "event.original": "event.original",
            "event.provider": "event.provider",
            "event.category": "event.category",
            "event.type": "event.type",
            "event.action": "event.action",
            "event.outcome": "event.outcome",
            "commandline": "process.command_line",
            "process.command_line": "process.command_line",
            "image": "process.executable",
            "process.executable": "process.executable",
            "user": "user.name",
            "username": "user.name",
            "accountname": "user.name",
            "user.name": "user.name",
            "targetuser": "user.target.name",
            "targetusername": "user.target.name",
            "user.target.name": "user.target.name",
            "sourceip": "source.ip",
            "source.ip": "source.ip",
            "clientaddress": "source.ip",
            "ipaddress": "source.ip",
            "host": "host.name",
            "host.name": "host.name",
        }
        normalized = field_map.get(field_key, field)
        effective_modifier = modifier
    op_map = {
        "eq": "==",
        "contains": "icontains",
        "startswith": "startswith",
        "endswith": "endswith",
    }
    return normalized, op_map.get(effective_modifier, "==")


def _stream_expr(field: str, op: str, value: Any) -> str:
    escaped = str(value).replace("\\", "\\\\").replace("'", "\\'")
    return f"{field} {op} '{escaped}'"


def _verification_expr(field: str, op: str, value: Any) -> str:
    escaped = str(value).replace("\\", "\\\\").replace("'", "''")
    haystack = f"toString({field})"
    if op == "==":
        return f"{haystack} = '{escaped}'"
    if op == "!=":
        return f"{haystack} != '{escaped}'"
    if op == "icontains":
        return f"positionCaseInsensitiveUTF8({haystack}, '{escaped}') > 0"
    if op == "startswith":
        return f"positionCaseInsensitiveUTF8({haystack}, '{escaped}') = 1"
    if op == "endswith":
        return f"endsWith(lowerUTF8({haystack}), lowerUTF8('{escaped}'))"
    return f"positionCaseInsensitiveUTF8({haystack}, '{escaped}') > 0"


def _selection_to_expr(selection: Dict[str, Any], *, target: str) -> str:
    chunks: List[str] = []
    for raw_field, raw_value in selection.items():
        if raw_field == "keywords":
            values = raw_value if isinstance(raw_value, list) else [raw_value]
            builder = _stream_expr if target == "stream" else _verification_expr
            keyword_field = "event.original" if target == "stream" else "message"
            keyword_exprs = [builder(keyword_field, "icontains", item) for item in values]
            chunks.append("(" + " or ".join(keyword_exprs) + ")")
            continue
        field, op = _map_sigma_field(raw_field, target=target)
        values = raw_value if isinstance(raw_value, list) else [raw_value]
        builder = _stream_expr if target == "stream" else _verification_expr
        exprs = [builder(field, op, item) for item in values]
        chunks.append("(" + " or ".join(exprs) + ")" if len(exprs) > 1 else exprs[0])
    fallback = "event.provider != 'unknown'" if target == "stream" else "device_product != ''"
    return " and ".join(chunks) if chunks else fallback


def _compile_sigma_condition(condition: str, selections: Dict[str, str]) -> str:
    compact = " ".join(condition.strip().split())
    special = re.fullmatch(r"(1|all) of ([A-Za-z0-9_*]+)", compact, flags=re.IGNORECASE)
    if special:
        mode, pattern = special.groups()
        prefix = pattern[:-1] if pattern.endswith("*") else pattern
        matched = [expr for key, expr in selections.items() if key.startswith(prefix)]
        if not matched:
            raise ValueError("Sigma condition does not match any selection blocks")
        joiner = " or " if mode.lower() == "1" else " and "
        return "(" + joiner.join(matched) + ")"

    tokens = SIGMA_CONDITION_TOKEN_RE.findall(compact)
    pos = 0

    def parse_primary() -> str:
        nonlocal pos
        token = tokens[pos]
        lowered = token.lower()
        if token == "(":
            pos += 1
            inner = parse_or()
            if pos >= len(tokens) or tokens[pos] != ")":
                raise ValueError("Unclosed Sigma condition group")
            pos += 1
            return f"({inner})"
        if lowered == "not":
            raise ValueError("Sigma 'not' conditions are not supported in the current converter")
        if token not in selections:
            raise ValueError(f"Unsupported Sigma condition token: {token}")
        pos += 1
        return f"({selections[token]})"

    def parse_and() -> str:
        nonlocal pos
        left = parse_primary()
        while pos < len(tokens) and tokens[pos].lower() == "and":
            pos += 1
            left = f"({left} and {parse_primary()})"
        return left

    def parse_or() -> str:
        nonlocal pos
        left = parse_and()
        while pos < len(tokens) and tokens[pos].lower() == "or":
            pos += 1
            left = f"({left} or {parse_and()})"
        return left

    compiled = parse_or()
    if pos != len(tokens):
        raise ValueError("Unexpected tokens in Sigma condition")
    return compiled


def convert_sigma_to_stream_rule(
    sigma_yaml: str,
    *,
    threshold: int,
    window_s: int,
    entity_field: str,
    rule_id: int | None = None,
) -> Dict[str, Any]:
    document = yaml.safe_load(sigma_yaml) or {}
    if not isinstance(document, dict):
        raise ValueError("Sigma payload must be a YAML object")
    detection = document.get("detection")
    if not isinstance(detection, dict):
        raise ValueError("Sigma rule must contain detection")
    condition = str(detection.get("condition", "")).strip()
    if not condition:
        raise ValueError("Sigma detection.condition is required")

    selection_exprs: Dict[str, str] = {}
    verification_exprs: Dict[str, str] = {}
    for key, value in detection.items():
        if key == "condition":
            continue
        if not isinstance(value, dict):
            raise ValueError(f"Sigma selection '{key}' must be an object")
        selection_exprs[key] = _selection_to_expr(value, target="stream")
        verification_exprs[key] = _selection_to_expr(value, target="events")

    expr = _compile_sigma_condition(condition, selection_exprs)
    verification_query = _compile_sigma_condition(condition, verification_exprs)
    expr = f"({expr}) and not tags icontains 'allowlist:'"
    verification_query = f"({verification_query}) AND positionCaseInsensitiveUTF8(toString(tags), 'allowlist:') = 0"
    level = str(document.get("level", "medium") or "medium").lower()
    logsource = document.get("logsource") or {}
    if not isinstance(logsource, dict):
        logsource = {}
    title = str(document.get("title", "Untitled Sigma rule") or "Untitled Sigma rule").strip()
    description = str(document.get("description", "") or "").strip()
    sigma_id = str(document.get("id", "") or "").strip()
    tags = document.get("tags") or []
    if not isinstance(tags, list):
        tags = [str(tags)]
    return {
        "id": int(rule_id) if rule_id is not None else 0,
        "title": title,
        "sigma_id": sigma_id,
        "status": str(document.get("status", "custom") or "custom"),
        "level": level,
        "source_format": "sigma",
        "logsource_product": str(logsource.get("product", "") or ""),
        "logsource_service": str(logsource.get("service", "") or ""),
        "logsource_category": str(logsource.get("category", "") or ""),
        "sigma_yaml": sigma_yaml.strip(),
        "expr": expr,
        "entity_field": entity_field,
        "window_s": int(window_s),
        "threshold": int(threshold),
        "verification_query": verification_query,
        "tags": ",".join(str(tag) for tag in tags),
        "description": description,
        "enabled": 1,
        "author": "web",
    }


def _next_detection_rule_id() -> int:
    current_catalog = int(_scalar(f"SELECT max(id) FROM {DETECTION_RULE_TABLE}"))
    current_stream = int(_scalar("SELECT max(id) FROM siem.correlation_rules_stream"))
    return max(current_catalog, current_stream, 1999) + 1


def _seed_default_sigma_rules() -> None:
    desired_rules = [
        convert_sigma_to_stream_rule(
            item["yaml"],
            threshold=item["threshold"],
            window_s=item["window_s"],
            entity_field=item["entity_field"],
            rule_id=item["id"],
        )
        for item in DEFAULT_SIGMA_RULES
    ]
    if not desired_rules:
        return
    for rule in desired_rules:
        get_ch_client().command(f"ALTER TABLE {DETECTION_RULE_TABLE} DELETE WHERE id = {int(rule['id'])}")
    _insert_detection_rule_rows(desired_rules, sync_stream=False)
    for rule in desired_rules:
        _insert_stream_rule(rule)


def _insert_detection_rule_rows(rules: List[Dict[str, Any]], *, sync_stream: bool) -> None:
    rows = [
        [
            int(rule["id"]),
            rule["title"],
            rule["sigma_id"],
            rule["status"],
            rule["level"],
            rule["source_format"],
            rule["logsource_product"],
            rule["logsource_service"],
            rule["logsource_category"],
            rule["sigma_yaml"],
            rule["expr"],
            rule["entity_field"],
            int(rule["window_s"]),
            int(rule["threshold"]),
            rule["verification_query"],
            rule["tags"],
            rule["description"],
            int(rule["enabled"]),
            rule["author"],
        ]
        for rule in rules
    ]
    get_ch_client().insert(
        DETECTION_RULE_TABLE,
        rows,
        column_names=[
            "id",
            "title",
            "sigma_id",
            "status",
            "level",
            "source_format",
            "logsource_product",
            "logsource_service",
            "logsource_category",
            "sigma_yaml",
            "expr",
            "entity_field",
            "window_s",
            "threshold",
            "verification_query",
            "tags",
            "description",
            "enabled",
            "author",
        ],
    )
    if sync_stream:
        for rule in rules:
            _insert_stream_rule(rule)


def _insert_stream_rule(rule: Dict[str, Any]) -> None:
    get_ch_client().command(f"ALTER TABLE siem.correlation_rules_stream DELETE WHERE id = {int(rule['id'])}")
    get_ch_client().insert(
        "siem.correlation_rules_stream",
        [[
            int(rule["id"]),
            rule["title"],
            rule["description"] or f"Sigma-derived rule for {rule['title']}",
            1,
            rule["level"],
            "threshold",
            int(rule["window_s"]),
            int(rule["threshold"]),
            rule["expr"],
            rule["entity_field"],
        ]],
        column_names=[
            "id",
            "name",
            "description",
            "enabled",
            "severity",
            "pattern",
            "window_s",
            "threshold",
            "expr",
            "entity_field",
        ],
    )


def save_sigma_rule(
    sigma_yaml: str,
    *,
    threshold: int,
    window_s: int,
    entity_field: str,
    author: str = "web",
) -> Dict[str, Any]:
    ensure_detection_support_tables()
    rule = convert_sigma_to_stream_rule(
        sigma_yaml,
        threshold=threshold,
        window_s=window_s,
        entity_field=entity_field,
        rule_id=_next_detection_rule_id(),
    )
    rule["author"] = author
    _insert_detection_rule_rows([rule], sync_stream=True)
    return rule


def _count_rule_matches(query_text: str, window: str = "24h") -> int:
    expression = _validate_read_only_sql(str(query_text or "").strip())
    result = get_ch_client().query(
        f"""
        SELECT count() AS cnt
        FROM ({EVENT_VIEW_SQL}) AS events_view
        WHERE {_event_time_filter(window)}
          AND ({expression})
        """
    )
    return int(result.result_rows[0][0]) if result.result_rows else 0


def fetch_detection_rules(limit: int = 100) -> List[Dict[str, Any]]:
    ensure_detection_support_tables()
    query = f"""
        SELECT
            id,
            title,
            sigma_id,
            status,
            level,
            source_format,
            logsource_product,
            logsource_service,
            logsource_category,
            expr,
            entity_field,
            window_s,
            threshold,
            verification_query,
            tags,
            description,
            enabled,
            author,
            created_ts,
            updated_ts
        FROM {DETECTION_RULE_TABLE}
        ORDER BY updated_ts DESC, id DESC
        LIMIT {int(limit)}
    """
    rules: List[Dict[str, Any]] = []
    alert_rows = get_ch_client().query(
        f"""
        SELECT rule_id, count() AS hits, max(ts_last) AS last_alert
        FROM siem.alerts_raw
        GROUP BY rule_id
        """
    ).result_rows
    alert_index = {int(rule_id): {"hits": int(hits), "last_alert": _fmt(last_alert)} for rule_id, hits, last_alert in alert_rows}
    for row in get_ch_client().query(query).named_results():
        verification_query = str(row["verification_query"] or "")
        match_hits_24h = _count_rule_matches(verification_query, window="24h") if verification_query else 0
        record = {
            "id": int(row["id"]),
            "title": row["title"],
            "sigma_id": row["sigma_id"],
            "status": row["status"],
            "level": str(row["level"]).lower(),
            "source_format": row["source_format"],
            "logsource_product": row["logsource_product"],
            "logsource_service": row["logsource_service"],
            "logsource_category": row["logsource_category"],
            "expr": row["expr"],
            "entity_field": row["entity_field"],
            "window_s": int(row["window_s"]),
            "threshold": int(row["threshold"]),
            "verification_query": verification_query,
            "tags": [part for part in str(row["tags"] or "").split(",") if part],
            "description": row["description"],
            "enabled": bool(row["enabled"]),
            "author": row["author"],
            "created_ts": _fmt(row["created_ts"]),
            "updated_ts": _fmt(row["updated_ts"]),
            "match_hits_24h": match_hits_24h,
            "alert_hits_total": alert_index.get(int(row["id"]), {}).get("hits", 0),
            "last_alert_ts": alert_index.get(int(row["id"]), {}).get("last_alert", ""),
            "events_link": f"/events?q={quote(verification_query)}" if verification_query else "/events",
        }
        rules.append(record)
    return rules


def test_detection_rule(rule_id: int) -> Dict[str, Any]:
    ensure_detection_support_tables()
    result = get_ch_client().query(
        f"""
        SELECT id, title, verification_query
        FROM {DETECTION_RULE_TABLE}
        WHERE id = {int(rule_id)}
        LIMIT 1
        """
    )
    if not result.result_rows:
        raise ValueError("Rule not found")
    _, title, verification_query = result.result_rows[0]
    hits = _count_rule_matches(str(verification_query or ""), window="24h")
    last_alert = _scalar(f"SELECT max(ts_last) FROM siem.alerts_raw WHERE rule_id = {int(rule_id)}")
    return {
        "rule_id": int(rule_id),
        "title": title,
        "verification_query": verification_query,
        "hits_24h": hits,
        "last_alert_ts": _fmt(last_alert),
        "events_link": f"/events?q={quote(str(verification_query or ''))}",
    }


def fetch_asset_categories() -> List[Dict[str, Any]]:
    ensure_detection_support_tables()
    ensure_active_list_support()
    return [
        {
            "name": "Devices",
            "count": int(_scalar("SELECT countDistinct(log_source) FROM siem.events WHERE ts >= now() - INTERVAL 24 HOUR")),
            "description": "Observed hosts and sources active during the last 24 hours.",
        },
        {
            "name": "Detection Rules",
            "count": int(_scalar(f"SELECT count() FROM {DETECTION_RULE_TABLE}")),
            "description": "Rules stored in the web-side catalog and synchronized to stream correlation.",
        },
        {
            "name": "Sigma Rules",
            "count": int(_scalar(f"SELECT count() FROM {DETECTION_RULE_TABLE} WHERE lower(source_format) = 'sigma'")),
            "description": "Sigma-oriented rules converted into the SIEM stream rule DSL.",
        },
        {
            "name": "Normalizers",
            "count": int(_scalar("SELECT count() FROM siem.normalizer_rules WHERE enabled = 1")),
            "description": "Enabled normalizer rules plus built-in Linux parsing logic.",
        },
        {
            "name": "Active Lists",
            "count": int(_scalar(f"SELECT count() FROM {ACTIVE_LIST_TABLE}")),
            "description": "Stateful watchlists for enrichment, allow/deny inventory and entity lookups.",
        },
        {
            "name": "Threat Feeds",
            "count": 0,
            "description": "Reserved category for TI/CyberTrace and external feed connectors.",
        },
    ]
