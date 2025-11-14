# SIEM Ingest Service

FastAPI-приложение, обеспечивающее:
- HTTP/JSON ingest (`POST /ingest/json`) → Redis Stream `siem:raw`.
- TCP syslog ingest (порт SIEM_INGEST_SYSLOG_PORT) → `siem:raw`.
- Health-check (`GET /health`).

## Конфигурация (env)

Используемые переменные:
- SIEM_ENV (dev/prod/stage)
- SIEM_INSTANCE_NAME
- SIEM_LOG_LEVEL

- SIEM_REDIS_HOST
- SIEM_REDIS_PORT
- SIEM_REDIS_DB
- SIEM_REDIS_PASSWORD

- SIEM_INGEST_SYSLOG_HOST
- SIEM_INGEST_SYSLOG_PORT
- SIEM_INGEST_HTTP_HOST
- SIEM_INGEST_HTTP_PORT

В PROD значения задаются в /etc/siem/siem.env.
В DEV значения можно хранить в ./../.env, который подхватывается python-dotenv.
