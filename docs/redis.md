# Redis in SIEM

Назначение Redis:
- Шина событий (Redis Streams) между микросервисами.
- Временное хранение состояния потоковых корреляторов.

## Streams

Используемые ключи:

- `siem:raw`          — сырые события после ingest.
- `siem:normalized`   — нормализованные события (UEM).
- `siem:filtered`     — события после фильтрации (drop/tag/pass).
- `siem:alerts_stream` — алерты от потокового коррелятора.
- `siem:dead_letter`  — проблемные сообщения (опционально).

## Consumer groups

- `siem:raw`:
  - `normalizer`

- `siem:normalized`:
  - `filter`

- `siem:filtered`:
  - `writer`
  - `stream_corr`

- `siem:alerts_stream`:
  - `alert_agg`

Создание групп выполняется приложениями (микросервисами) при старте.
