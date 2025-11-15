"""
/home/siem/siem-solution/services/stream_corr/config.py

Настройки потокового коррелятора.

Используемые env-переменные:
  SIEM_ENV
  SIEM_INSTANCE_NAME

  SIEM_REDIS_HOST
  SIEM_REDIS_PORT
  SIEM_REDIS_DB
  SIEM_REDIS_PASSWORD

  SIEM_CH_HOST
  SIEM_CH_PORT
  SIEM_CH_DB
  SIEM_CH_USER
  SIEM_CH_PASSWORD
  SIEM_CH_TIMEOUT_SECS

  (опционально)
  SIEM_REDIS_STREAM_FILTERED       -- ключ стрима с событиями (по умолчанию siem:filtered)
  SIEM_STREAM_CORR_GROUP           -- имя consumer group (по умолчанию siem_stream_corr)
  SIEM_STREAM_CORR_CONSUMER        -- имя consumer (по умолчанию siem_stream_corr_1)
  SIEM_STREAM_CORR_BATCH_SIZE      -- размер батча (по умолчанию 200)
"""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass
class StreamCorrSettings:
    env: str
    instance_name: str

    redis_host: str
    redis_port: int
    redis_db: int
    redis_password: str | None

    ch_host: str
    ch_port: int
    ch_db: str
    ch_user: str
    ch_password: str
    ch_timeout_secs: int

    filtered_stream_key: str
    group_name: str
    consumer_name: str
    batch_size: int

    @classmethod
    def load(cls) -> "StreamCorrSettings":
        env = os.getenv("SIEM_ENV", "dev")
        instance_name = os.getenv("SIEM_INSTANCE_NAME", "dev-instance")

        redis_host = os.getenv("SIEM_REDIS_HOST", "127.0.0.1")
        redis_port = int(os.getenv("SIEM_REDIS_PORT", "6379"))
        redis_db = int(os.getenv("SIEM_REDIS_DB", "0"))
        redis_password = os.getenv("SIEM_REDIS_PASSWORD") or None

        ch_host = os.getenv("SIEM_CH_HOST", "127.0.0.1")
        ch_port = int(os.getenv("SIEM_CH_PORT", "9000"))
        ch_db = os.getenv("SIEM_CH_DB", "siem")
        ch_user = os.getenv("SIEM_CH_USER", "siem_admin")
        ch_password = os.getenv("SIEM_CH_PASSWORD", "")
        ch_timeout_secs = int(os.getenv("SIEM_CH_TIMEOUT_SECS", "10"))

        filtered_stream_key = os.getenv("SIEM_REDIS_STREAM_FILTERED", "siem:filtered")
        group_name = os.getenv("SIEM_STREAM_CORR_GROUP", "siem_stream_corr")
        consumer_name = os.getenv("SIEM_STREAM_CORR_CONSUMER", "siem_stream_corr_1")
        batch_size = int(os.getenv("SIEM_STREAM_CORR_BATCH_SIZE", "200"))

        return cls(
            env=env,
            instance_name=instance_name,
            redis_host=redis_host,
            redis_port=redis_port,
            redis_db=redis_db,
            redis_password=redis_password,
            ch_host=ch_host,
            ch_port=ch_port,
            ch_db=ch_db,
            ch_user=ch_user,
            ch_password=ch_password,
            ch_timeout_secs=ch_timeout_secs,
            filtered_stream_key=filtered_stream_key,
            group_name=group_name,
            consumer_name=consumer_name,
            batch_size=batch_size,
        )
