-- sql/04_insert_test_stream_rule.sql
-- Тестовое потоковое правило:
-- rule 1: 5 http_json событий за 30 секунд по одному source.ip

INSERT INTO siem.correlation_rules_stream
    (id, name, description, enabled, severity, pattern, window_s, threshold, expr, entity_field)
VALUES
    (
      1,
      'test_threshold_http',
      '5 http_json events per 30s per source.ip',
      1,
      'medium',
      'threshold',
      30,
      5,
      'event.provider == ''http_json''',
      'source.ip'
    );
