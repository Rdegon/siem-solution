-- sql/07_insert_test_batch_rule.sql
-- Тестовое batch-правило: мета-алерт по rule_id=1 в siem.alerts_raw.
-- Без агрегатов в WHERE: окно по обычному полю ts.

INSERT INTO siem.correlation_rules_batch
    (id, name, description, enabled, severity, window_s, sql_template)
VALUES
(
    2001,
    'batch_meta_test_threshold_http',
    'Meta batch rule over alerts_raw for rule_id=1',
    1,
    'low',
    300,
    'INSERT INTO siem.alerts_raw
(
    alert_id,
    rule_id,
    rule_name,
    severity,
    ts_first,
    ts_last,
    window_s,
    entity_key,
    hits,
    context_json,
    status,
    source
)
SELECT
    generateUUIDv4() AS alert_id,
    2001 AS rule_id,
    ''batch_meta_test_threshold_http'' AS rule_name,
    ''low'' AS severity,
    min(ts) AS ts_first,
    max(ts) AS ts_last,
    {WINDOW_S} AS window_s,
    ''meta:rule_1'' AS entity_key,
    count(*) AS hits,
    toJSONString(map(
        ''rule_id'', toString(2001),
        ''rule_name'', ''batch_meta_test_threshold_http'',
        ''description'', ''Meta batch rule over alerts_raw for rule_id=1'',
        ''child_rule_id'', toString(1)
    )) AS context_json,
    ''open'' AS status,
    ''batch'' AS source
FROM siem.alerts_raw
WHERE rule_id = 1
  AND ts >= now() - INTERVAL {WINDOW_S} SECOND
  AND ts <  now()
GROUP BY rule_id
HAVING count(*) >= 1;'
);
