ALTER TABLE siem.events ADD COLUMN IF NOT EXISTS event_code String DEFAULT '';
ALTER TABLE siem.events ADD COLUMN IF NOT EXISTS asset_id String DEFAULT '';
ALTER TABLE siem.events ADD COLUMN IF NOT EXISTS asset_owner String DEFAULT '';
ALTER TABLE siem.events ADD COLUMN IF NOT EXISTS asset_criticality String DEFAULT '';
ALTER TABLE siem.events ADD COLUMN IF NOT EXISTS asset_environment String DEFAULT '';
ALTER TABLE siem.events ADD COLUMN IF NOT EXISTS asset_service String DEFAULT '';
ALTER TABLE siem.events ADD COLUMN IF NOT EXISTS ti_indicator String DEFAULT '';
ALTER TABLE siem.events ADD COLUMN IF NOT EXISTS ti_indicator_type String DEFAULT '';
ALTER TABLE siem.events ADD COLUMN IF NOT EXISTS ti_provider String DEFAULT '';
ALTER TABLE siem.events ADD COLUMN IF NOT EXISTS ti_severity String DEFAULT '';

ALTER TABLE siem.events_cold ADD COLUMN IF NOT EXISTS event_code String DEFAULT '';
ALTER TABLE siem.events_cold ADD COLUMN IF NOT EXISTS asset_id String DEFAULT '';
ALTER TABLE siem.events_cold ADD COLUMN IF NOT EXISTS asset_owner String DEFAULT '';
ALTER TABLE siem.events_cold ADD COLUMN IF NOT EXISTS asset_criticality String DEFAULT '';
ALTER TABLE siem.events_cold ADD COLUMN IF NOT EXISTS asset_environment String DEFAULT '';
ALTER TABLE siem.events_cold ADD COLUMN IF NOT EXISTS asset_service String DEFAULT '';
ALTER TABLE siem.events_cold ADD COLUMN IF NOT EXISTS ti_indicator String DEFAULT '';
ALTER TABLE siem.events_cold ADD COLUMN IF NOT EXISTS ti_indicator_type String DEFAULT '';
ALTER TABLE siem.events_cold ADD COLUMN IF NOT EXISTS ti_provider String DEFAULT '';
ALTER TABLE siem.events_cold ADD COLUMN IF NOT EXISTS ti_severity String DEFAULT '';

CREATE TABLE IF NOT EXISTS siem.cmdb_assets
(
    asset_id String,
    asset_type LowCardinality(String) DEFAULT 'server',
    hostname String DEFAULT '',
    ip String DEFAULT '',
    owner String DEFAULT '',
    criticality LowCardinality(String) DEFAULT 'medium',
    environment LowCardinality(String) DEFAULT 'prod',
    business_service String DEFAULT '',
    os_family LowCardinality(String) DEFAULT '',
    expected_ports String DEFAULT '',
    tags String DEFAULT '',
    notes String DEFAULT '',
    enabled UInt8 DEFAULT 1,
    updated_ts DateTime DEFAULT now()
)
ENGINE = MergeTree
ORDER BY (asset_id, hostname, ip);

CREATE TABLE IF NOT EXISTS siem.threat_intel_iocs
(
    indicator_type LowCardinality(String),
    indicator String,
    provider String DEFAULT '',
    severity LowCardinality(String) DEFAULT 'medium',
    confidence UInt8 DEFAULT 50,
    description String DEFAULT '',
    tags String DEFAULT '',
    enabled UInt8 DEFAULT 1,
    expires_ts Nullable(DateTime),
    updated_ts DateTime DEFAULT now()
)
ENGINE = MergeTree
ORDER BY (indicator_type, indicator, provider);
