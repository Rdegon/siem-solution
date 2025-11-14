-- 03_mv_and_ttl.sql
--   - 1-минутная агрегация событий
--   - дедупликация алертов через ReplacingMergeTree + MV

CREATE DATABASE IF NOT EXISTS siem ENGINE = Atomic;

CREATE TABLE IF NOT EXISTS siem.events_min_agg
(
    bucket          DateTime,
    tenant          LowCardinality(String),
    event_category  LowCardinality(String),
    event_type      LowCardinality(String),
    source_type     LowCardinality(String),
    cnt_events      UInt64
)
ENGINE = SummingMergeTree
PARTITION BY toDate(bucket)
ORDER BY (bucket, tenant, event_category, event_type, source_type)
TTL bucket + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.events_min_agg_mv
TO siem.events_min_agg
AS
SELECT
    toStartOfMinute(event_ts)        AS bucket,
    tenant,
    event_category,
    event_type,
    source_type,
    count()                          AS cnt_events
FROM siem.events
GROUP BY
    bucket,
    tenant,
    event_category,
    event_type,
    source_type;

CREATE TABLE IF NOT EXISTS siem.alerts_unique
(
    ts_first        DateTime,
    ts_last         DateTime,

    rule_id         String,
    rule_name       String,
    severity        LowCardinality(String),

    entity_key      String,
    hits            UInt32,

    src             LowCardinality(String),
    status          LowCardinality(String),

    context_json    String,
    alert_id        UUID,
    created_at      DateTime
)
ENGINE = ReplacingMergeTree(created_at)
PARTITION BY toDate(ts_first)
ORDER BY (rule_id, entity_key, ts_first, ts_last, alert_id)
TTL ts_first + INTERVAL 180 DAY
SETTINGS index_granularity = 8192;

DROP VIEW IF EXISTS siem.alerts_unique_mv;

CREATE MATERIALIZED VIEW siem.alerts_unique_mv
TO siem.alerts_unique
AS
SELECT
    ts_first,
    ts_last,
    rule_id,
    rule_name,
    severity,
    entity_key,
    hits,
    src,
    status,
    context_json,
    alert_id,
    created_at
FROM siem.alerts_raw;
