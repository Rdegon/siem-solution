ALTER TABLE siem.events
    ADD COLUMN IF NOT EXISTS event_action String DEFAULT '',
    ADD COLUMN IF NOT EXISTS event_outcome String DEFAULT '',
    ADD COLUMN IF NOT EXISTS host_name String DEFAULT '',
    ADD COLUMN IF NOT EXISTS user_name String DEFAULT '',
    ADD COLUMN IF NOT EXISTS target_user String DEFAULT '',
    ADD COLUMN IF NOT EXISTS process_name String DEFAULT '',
    ADD COLUMN IF NOT EXISTS process_executable String DEFAULT '',
    ADD COLUMN IF NOT EXISTS process_command String DEFAULT '',
    ADD COLUMN IF NOT EXISTS normalized_json String DEFAULT '';

ALTER TABLE siem.alerts_raw
    ADD COLUMN IF NOT EXISTS assignee String DEFAULT '',
    ADD COLUMN IF NOT EXISTS updated_ts DateTime DEFAULT now();

ALTER TABLE siem.alerts_agg
    ADD COLUMN IF NOT EXISTS assignee String DEFAULT '',
    ADD COLUMN IF NOT EXISTS updated_ts DateTime DEFAULT now();

CREATE TABLE IF NOT EXISTS siem.active_list_items
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
ORDER BY (list_name, value);

ALTER TABLE siem.active_list_items
    ADD COLUMN IF NOT EXISTS list_kind LowCardinality(String) DEFAULT 'watch';

CREATE TABLE IF NOT EXISTS siem.events_cold
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
ORDER BY (ts, log_source, event_id);

CREATE TABLE IF NOT EXISTS siem.alert_history
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
ORDER BY (view, record_id, changed_ts);
