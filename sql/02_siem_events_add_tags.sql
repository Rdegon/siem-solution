-- sql/02_siem_events_add_tags.sql
-- Миграция схемы для таблицы siem.events:
--   - добавляет колонку tags, если её ещё нет.
--
-- Используемый тип:
--   tags LowCardinality(String) — теги события, например "test_http".

ALTER TABLE siem.events
    ADD COLUMN IF NOT EXISTS tags LowCardinality(String);
