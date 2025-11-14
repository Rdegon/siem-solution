-- 02_schema_core.sql
-- Основные таблицы SIEM:
--   events_raw, events, alerts_raw, alerts_agg,
--   normalizer_rules, filter_rules,
--   correlation_rules_stream, correlation_rules_batch,
--   справочники (whitelist/blacklist).

CREATE DATABASE IF NOT EXISTS siem ENGINE = Atomic;

CREATE TABLE IF NOT EXISTS siem.events_raw
(
    ts              DateTime             CODEC(Delta, ZSTD),
    ingest_ts       DateTime             CODEC(Delta, ZSTD),
    source          LowCardinality(String),
    source_type     LowCardinality(String),
    facility        LowCardinality(String),
    severity        LowCardinality(String),
    host            String,
    message         String,
    raw_json        String,
    raw_id          String,
    recv_iface      LowCardinality(String),
    extra           Map(String, String)
)
ENGINE = MergeTree
PARTITION BY toDate(ts)
ORDER BY (ts, source, raw_id)
TTL ts + INTERVAL 7 DAY
SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS siem.events
(
    event_ts        DateTime             CODEC(Delta, ZSTD),
    ingest_ts       DateTime             CODEC(Delta, ZSTD),

    event_provider  LowCardinality(String),
    source_type     LowCardinality(String),        -- <── ДОБАВЛЕНО
    event_category  LowCardinality(String),
    event_type      LowCardinality(String),
    event_outcome   LowCardinality(String),

    src_ip          IPv6,
    src_port        UInt16,
    src_user        String,
    src_host        String,

    dst_ip          IPv6,
    dst_port        UInt16,
    dst_user        String,
    dst_host        String,

    protocol        LowCardinality(String),
    http_method     LowCardinality(String),
    http_url        String,
    http_status     UInt16,

    dns_qname       String,
    dns_qtype       LowCardinality(String),

    process_name    String,
    process_path    String,
    process_pid     UInt32,
    parent_name     String,
    parent_pid      UInt32,

    object          String,
    action          LowCardinality(String),

    tenant          LowCardinality(String),
    tags            Array(LowCardinality(String)),
    severity        LowCardinality(String),
    normalized      UInt8,

    raw_id          String,
    raw_source      LowCardinality(String),
    extra           Map(String, String)
)
ENGINE = MergeTree
PARTITION BY toDate(event_ts)
ORDER BY (event_ts, tenant, event_category, event_type)
TTL event_ts + INTERVAL 30 DAY
SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS siem.alerts_raw
(
    alert_id        UUID,
    rule_id         String,
    rule_name       String,
    severity        LowCardinality(String),

    ts_first        DateTime,
    ts_last         DateTime,
    window_s        UInt32,

    entity_key      String,
    hits            UInt32,

    src             LowCardinality(String),
    status          LowCardinality(String),

    context_json    String,
    created_at      DateTime DEFAULT now()
)
ENGINE = MergeTree
PARTITION BY toDate(ts_first)
ORDER BY (ts_first, rule_id, entity_key, alert_id)
TTL ts_first + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS siem.alerts_agg
(
    agg_id          UUID,
    rule_id         String,
    rule_name       String,
    severity_agg    LowCardinality(String),

    group_key_json  String,

    ts_first        DateTime,
    ts_last         DateTime,
    count_alerts    UInt32,
    unique_entities UInt32,

    samples         Array(UUID),
    status          LowCardinality(String),

    updated_at      DateTime
)
ENGINE = ReplacingMergeTree(updated_at)
PARTITION BY toDate(ts_first)
ORDER BY (rule_id, group_key_json, agg_id)
TTL ts_first + INTERVAL 180 DAY
SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS siem.normalizer_rules
(
    rule_id         String,
    name            String,
    description     String,
    priority        Int32,
    enabled         UInt8,

    source_type     LowCardinality(String),
    match_condition String,
    jmespath_expr   String,
    yaml_text       String,

    updated_at      DateTime
)
ENGINE = MergeTree
ORDER BY (source_type, priority, rule_id)
SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS siem.filter_rules
(
    rule_id         String,
    name            String,
    description     String,
    priority        Int32,
    enabled         UInt8,

    expr            String,
    action          LowCardinality(String),
    tags_to_add     Array(LowCardinality(String)),
    stop_on_match   UInt8,

    updated_at      DateTime
)
ENGINE = MergeTree
ORDER BY (priority, rule_id)
SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS siem.correlation_rules_stream
(
    rule_id         String,
    name            String,
    description     String,
    enabled         UInt8,

    rule_type       LowCardinality(String),
    window_s        UInt32,
    slide_s         UInt32,

    entity_fields   Array(String),
    condition_expr  String,
    params_json     String,

    severity        LowCardinality(String),
    updated_at      DateTime
)
ENGINE = MergeTree
ORDER BY (rule_id)
SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS siem.correlation_rules_batch
(
    rule_id         String,
    name            String,
    description     String,
    enabled         UInt8,

    interval_s      UInt32,
    lookback_s      UInt32,

    target_table    LowCardinality(String),
    sql_template    String,

    severity        LowCardinality(String),
    updated_at      DateTime
)
ENGINE = MergeTree
ORDER BY (rule_id)
SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS siem.dict_dns_whitelist
(
    domain String
)
ENGINE = Set;

CREATE TABLE IF NOT EXISTS siem.dict_ip_whitelist
(
    ip String
)
ENGINE = Set;

CREATE TABLE IF NOT EXISTS siem.dict_user_whitelist
(
    username String
)
ENGINE = Set;
