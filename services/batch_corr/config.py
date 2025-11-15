"""
/home/siem/siem-solution/services/batch_corr/config.py

Настройки batch-корреллятора.

Используемые env-переменные:
  SIEM_ENV
  SIEM_INSTANCE_NAME

  SIEM_CH_HOST
  SIEM_CH_PORT
  SIEM_CH_DB
  SIEM_CH_USER
  SIEM_CH_PASSWORD
  SIEM_CH_TIMEOUT_SECS

  (опционально)
  SIEM_BATCH_CORR_INTERVAL_SEC   -- интервал выполнения правил, сек (по умолчанию 60)
"""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass
class BatchCorrSettings:
    env: str
    instance_name: str

    ch_host: str
    ch_port: int
    ch_db: str
    ch_user: str
    ch_password: str
    ch_timeout_secs: int

    interval_sec: int

    @classmethod
    def load(cls) -> "BatchCorrSettings":
        env = os.getenv("SIEM_ENV", "dev")
        instance_name = os.getenv("SIEM_INSTANCE_NAME", "dev-instance")

        ch_host = os.getenv("SIEM_CH_HOST", "127.0.0.1")
        ch_port = int(os.getenv("SIEM_CH_PORT", "9000"))
        ch_db = os.getenv("SIEM_CH_DB", "siem")
        ch_user = os.getenv("SIEM_CH_USER", "siem_admin")
        ch_password = os.getenv("SIEM_CH_PASSWORD", "")
        ch_timeout_secs = int(os.getenv("SIEM_CH_TIMEOUT_SECS", "10"))

        interval_sec = int(os.getenv("SIEM_BATCH_CORR_INTERVAL_SEC", "60"))

        return cls(
            env=env,
            instance_name=instance_name,
            ch_host=ch_host,
            ch_port=ch_port,
            ch_db=ch_db,
            ch_user=ch_user,
            ch_password=ch_password,
            ch_timeout_secs=ch_timeout_secs,
            interval_sec=interval_sec,
        )
