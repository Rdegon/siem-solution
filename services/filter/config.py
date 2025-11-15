"""
/home/siem/siem-solution/services/filter/config.py

Настройки фильтра:
  - Параметры Redis и ClickHouse
  - Ключи стримов: siem:normalized -> siem:filtered

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
"""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass
class FilterSettings:
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

    normalized_stream_key: str
    filtered_stream_key: str
    batch_size: int

    @classmethod
    def load(cls) -> "FilterSettings":
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

        normalized_stream_key = os.getenv("SIEM_REDIS_STREAM_NORMALIZED", "siem:normalized")
        filtered_stream_key = os.getenv("SIEM_REDIS_STREAM_FILTERED", "siem:filtered")
        batch_size = int(os.getenv("SIEM_FILTER_BATCH_SIZE", "100"))

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
            normalized_stream_key=normalized_stream_key,
            filtered_stream_key=filtered_stream_key,
            batch_size=batch_size,
        )
