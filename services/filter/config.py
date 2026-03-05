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
    group_name: str
    consumer_name: str
    batch_size: int
    block_ms: int

    @classmethod
    def load(cls) -> 'FilterSettings':
        return cls(
            env=os.getenv('SIEM_ENV', 'dev'),
            instance_name=os.getenv('SIEM_INSTANCE_NAME', 'dev-instance'),
            redis_host=os.getenv('SIEM_REDIS_HOST', '127.0.0.1'),
            redis_port=int(os.getenv('SIEM_REDIS_PORT', '6379')),
            redis_db=int(os.getenv('SIEM_REDIS_DB', '0')),
            redis_password=os.getenv('SIEM_REDIS_PASSWORD') or None,
            ch_host=os.getenv('SIEM_CH_HOST', '127.0.0.1'),
            ch_port=int(os.getenv('SIEM_CH_PORT', '9000')),
            ch_db=os.getenv('SIEM_CH_DB', 'siem'),
            ch_user=os.getenv('SIEM_CH_USER', 'siem_admin'),
            ch_password=os.getenv('SIEM_CH_PASSWORD', ''),
            ch_timeout_secs=int(os.getenv('SIEM_CH_TIMEOUT_SECS', '10')),
            normalized_stream_key=os.getenv('SIEM_REDIS_STREAM_NORMALIZED', 'siem:normalized'),
            filtered_stream_key=os.getenv('SIEM_REDIS_STREAM_FILTERED', 'siem:filtered'),
            group_name=os.getenv('SIEM_FILTER_GROUP', 'filter'),
            consumer_name=os.getenv('SIEM_FILTER_CONSUMER', 'filter-1'),
            batch_size=int(os.getenv('SIEM_FILTER_BATCH_SIZE', '100')),
            block_ms=int(os.getenv('SIEM_FILTER_BLOCK_MS', '5000')),
        )
