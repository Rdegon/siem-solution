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
    value String,
    value_type LowCardinality(String),
    label String,
    tags String,
    enabled UInt8,
    updated_ts DateTime DEFAULT now()
)
ENGINE = MergeTree
ORDER BY (list_name, value);
