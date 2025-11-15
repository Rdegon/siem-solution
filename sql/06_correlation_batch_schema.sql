-- sql/06_correlation_batch_schema.sql
-- Таблица batch-корреляций: SQL-шаблоны, выполняемые по расписанию.

DROP TABLE IF EXISTS siem.correlation_rules_batch;

CREATE TABLE siem.correlation_rules_batch
(
    id           UInt32,
    name         String,
    description  String,
    enabled      UInt8,
    severity     LowCardinality(String),
    window_s     UInt32,          -- окно в секундах, подставляется в шаблон
    sql_template String,          -- SQL-шаблон c плейсхолдером {WINDOW_S}
    created_ts   DateTime DEFAULT now(),
    updated_ts   DateTime DEFAULT now()
)
ENGINE = MergeTree
ORDER BY id;
