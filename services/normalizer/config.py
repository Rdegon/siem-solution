from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Literal


def _maybe_load_dotenv() -> None:
    env = os.getenv('SIEM_ENV', 'dev')
    if env.lower() == 'prod':
        return
    try:
        from dotenv import load_dotenv
    except ImportError:
        return
    repo_root = Path(__file__).resolve().parents[2]
    env_file = repo_root / '.env'
    if env_file.exists():
        load_dotenv(env_file)


@dataclass
class NormalizerSettings:
    env: Literal['dev', 'prod', 'stage']
    log_level: str
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
    raw_stream_key: str = 'siem:raw'
    normalized_stream_key: str = 'siem:normalized'
    consumer_group: str = 'normalizer'
    consumer_name: str = 'normalizer-1'
    batch_size: int = 100
    block_ms: int = 5000

    @classmethod
    def load(cls) -> 'NormalizerSettings':
        _maybe_load_dotenv()
        env = os.getenv('SIEM_ENV', 'dev').lower()
        if env not in ('dev', 'prod', 'stage'):
            raise ValueError(f'Invalid SIEM_ENV={env!r}')
        return cls(
            env=env,  # type: ignore[arg-type]
            log_level=os.getenv('SIEM_LOG_LEVEL', 'INFO').upper(),
            instance_name=os.getenv('SIEM_INSTANCE_NAME', 'default'),
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
            raw_stream_key=os.getenv('SIEM_REDIS_STREAM_RAW', 'siem:raw'),
            normalized_stream_key=os.getenv('SIEM_REDIS_STREAM_NORMALIZED', 'siem:normalized'),
            consumer_group=os.getenv('SIEM_NORMALIZER_GROUP', 'normalizer'),
            consumer_name=os.getenv('SIEM_NORMALIZER_CONSUMER', 'normalizer-1'),
            batch_size=int(os.getenv('SIEM_NORMALIZER_BATCH_SIZE', '100')),
            block_ms=int(os.getenv('SIEM_NORMALIZER_BLOCK_MS', '5000')),
        )
