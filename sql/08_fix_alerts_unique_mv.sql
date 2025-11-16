-- sql/08_fix_alerts_unique_mv.sql
-- Фикс материализованного представления siem.alerts_unique_mv.
-- Старая версия ссылалась на несуществующие колонки src и created_at в siem.alerts_raw.
-- Новая версия:
--   - читает поле source из siem.alerts_raw и алиасит его как src;
--   - создаёт поле created_at через now() на момент вставки в MV.

-- 1. На всякий случай удаляем старое MV (если есть)
DROP VIEW IF EXISTS siem.alerts_unique_mv;

-- 2. Создаём корректное MV в таблицу siem.alerts_unique
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
    source AS src,
    status,
    context_json,
    alert_id,
    now() AS created_at
FROM siem.alerts_raw;
