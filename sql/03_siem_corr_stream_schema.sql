-- sql/03_siem_corr_stream_schema.sql
-- Схема для потоковых правил корреляции и таблицы алертов.

CREATE TABLE IF NOT EXISTS siem.correlation_rules_stream
(
    id              UInt32,
    name            String,
    description     String,
    enabled         UInt8,
    severity        LowCardinality(String), -- low/medium/high/critical
    pattern         LowCardinality(String), -- 'threshold' (пока базовый паттерн)
    window_s        UInt32,                 -- размер окна в секундах
    threshold       UInt32,                 -- N событий за окно
    expr            String,                 -- мини-DSL по полям события (как в filter_rules.expr)
    entity_field    String,                 -- поле сущности, например 'source.ip' или 'user.name'
    created_ts      DateTime DEFAULT now(),
    updated_ts      DateTime DEFAULT now()
)
ENGINE = MergeTree
ORDER BY (id);

CREATE TABLE IF NOT EXISTS siem.alerts_raw
(
    ts          DateTime,                   -- время создания алерта
    alert_id    UUID,                       -- уникальный ID алерта
    rule_id     UInt32,                     -- ID правила
    rule_name   String,
    severity    LowCardinality(String),     -- low/medium/high/critical
    ts_first    DateTime,                   -- время первого события в окне
    ts_last     DateTime,                   -- время последнего события в окне
    window_s    UInt32,                     -- размер окна правила
    entity_key  String,                     -- сущность (user@host, ip и т.д.)
    hits        UInt32,                     -- сколько событий попало в окно
    context_json String,                    -- JSON с примерами/аггр. данными
    source      LowCardinality(String),     -- 'stream' или 'batch'
    status      LowCardinality(String)      -- 'open', 'ack', 'closed'
)
ENGINE = MergeTree
PARTITION BY toDate(ts)
ORDER BY (ts, rule_id, entity_key)
TTL ts + INTERVAL 90 DAY DELETE;
