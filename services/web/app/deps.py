
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime
from functools import lru_cache
import re
from typing import Any, Dict, List

import clickhouse_connect

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
EVENT_VIEW_SQL = """
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
        lower(severity) AS severity,
        message,
        tags
    FROM siem.events
""".strip()
EVENT_VIEW_COLUMNS = [
    'ts',
    'event_id',
    'category',
    'subcategory',
    'src_ip',
    'dst_ip',
    'src_port',
    'dst_port',
    'device_vendor',
    'device_product',
    'log_source',
    'severity',
    'message',
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
        "src_ip, ' ', dst_ip, ' ', toString(src_port), ' ', toString(dst_port), ' ', "
        "device_vendor, ' ', device_product, ' ', log_source, ' ', severity, ' ', message, ' ', tags)"
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


def _resolve_select_query(raw_query: str, limit: int) -> str:
    query = _validate_read_only_sql(raw_query)
    if 'events_view' in query.lower():
        resolved = EVENT_VIEW_FROM_RE.sub(rf"\1 ({EVENT_VIEW_SQL}) AS events_view", query)
    else:
        resolved = EVENT_TABLE_FROM_RE.sub(rf"\1 ({EVENT_VIEW_SQL}) AS events_view", query)
    if ' from ' not in resolved.lower():
        raise ValueError('SELECT query must include a FROM clause')
    if resolved == query and 'events_view' not in query.lower() and 'siem.events' not in query.lower():
        raise ValueError("Read-only SELECT must query from events_view or siem.events")
    return _ensure_limit(resolved, limit)


def _build_events_sql(query_text: str, window: str, limit: int) -> str:
    limit = max(1, min(limit, EVENT_ROW_LIMIT_MAX))
    query_text = (query_text or '').strip()
    if not query_text:
        expression = '1'
    elif FULL_SQL_RE.match(query_text):
        return _resolve_select_query(query_text, limit)
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
        f"    src_ip,\n"
        f"    dst_ip,\n"
        f"    src_port,\n"
        f"    dst_port,\n"
        f"    device_vendor,\n"
        f"    device_product,\n"
        f"    log_source,\n"
        f"    severity,\n"
        f"    message,\n"
        f"    tags\n"
        f"FROM ({EVENT_VIEW_SQL}) AS events_view\n"
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


def execute_event_query(query_text: str, window: str = '24h', limit: int = EVENT_ROW_LIMIT_DEFAULT) -> Dict[str, Any]:
    sql = _build_events_sql(query_text=query_text, window=window, limit=limit)
    result = _rows_from_query(sql)
    rows = result['rows']
    return {
        'sql': sql,
        'columns': result['columns'],
        'rows': rows,
        'row_count': len(rows),
        'histogram': _bucket_rows(rows, bucket_minutes=15),
        'severity_stats': _severity_stats(rows),
        'source_stats': _source_stats(rows),
    }


def fetch_alerts_agg(limit: int = 200) -> List[Dict[str, Any]]:
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
            status
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
            lower(severity) AS severity,
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
    return {
        'clickhouse_ok': ch_ping(),
        'events_total': int(_scalar("SELECT count() FROM siem.events")),
        'alerts_raw_total': int(_scalar("SELECT count() FROM siem.alerts_raw")),
        'alerts_agg_total': int(_scalar("SELECT count() FROM siem.alerts_agg")),
        'normalizer_rules': int(_scalar("SELECT count() FROM siem.normalizer_rules WHERE enabled = 1")),
        'filter_rules': int(_scalar("SELECT count() FROM siem.filter_rules WHERE enabled = 1")),
        'stream_rules': int(_scalar("SELECT count() FROM siem.correlation_rules_stream WHERE enabled = 1")),
        'last_event_ts': _fmt(_scalar("SELECT max(ts) FROM siem.events")),
    }
