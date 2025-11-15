-- sql/05_alerts_agg_schema.sql
-- Таблица агрегированных алертов siem.alerts_agg
-- и базовая таблица правил агрегации siem.alert_agg_rules.

CREATE TABLE IF NOT EXISTS siem.alerts_agg
(
    ts              DateTime DEFAULT now(),              -- время пересчёта/обновления группы
    agg_id          UUID,                                -- уникальный ID агрегата
    rule_id         UInt32,
    rule_name       String,
    severity_agg    LowCardinality(String),              -- агрегированная важность (max по группе)
    ts_first        DateTime,                            -- MIN ts_first из siem.alerts_raw
    ts_last         DateTime,                            -- MAX ts_last из siem.alerts_raw
    count_alerts    UInt32,                              -- количество алертов в группе
    unique_entities UInt32,                              -- число уникальных entity_key (обычно 1)
    entity_key      String,                              -- сущность (ip, user и т.п.)
    group_key_json  String,                              -- JSON с ключом группировки
    samples_json    String,                              -- JSON-массив с примерами context_json (до 3 штук)
    status          LowCardinality(String)               -- 'open' если есть хотя бы один open, иначе 'closed'
)
ENGINE = ReplacingMergeTree()
PARTITION BY toDate(ts)
ORDER BY (rule_id, entity_key, ts_last, agg_id)
TTL ts_last + INTERVAL 90 DAY DELETE;


CREATE TABLE IF NOT EXISTS siem.alert_agg_rules
(
    id              UInt32,
    name            String,
    description     String,
    enabled         UInt8,
    rule_id         UInt32,              -- 0 = применять ко всем правилам
    group_by        Array(String),       -- список полей для группировки (пока не используем глубоко)
    suppress_for_s  UInt32,              -- резерв под suppression (пока не используется логикой)
    min_count       UInt32,              -- минимальное количество алертов для отображения
    escalate_on_cnt UInt32,              -- порог для эскалации (резерв)
    created_ts      DateTime DEFAULT now(),
    updated_ts      DateTime DEFAULT now()
)
ENGINE = MergeTree
ORDER BY id;
