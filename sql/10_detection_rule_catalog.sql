CREATE TABLE IF NOT EXISTS siem.detection_rule_catalog
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
ORDER BY (id);
