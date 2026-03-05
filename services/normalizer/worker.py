from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, List

from redis.asyncio import Redis
from redis.exceptions import ResponseError

from .config import NormalizerSettings
from .logging_conf import configure_logging
from .normalizer_core import NormalizerRule, apply_rules, load_rules

logger = logging.getLogger(__name__)


class NormalizerWorker:
    def __init__(self, settings: NormalizerSettings) -> None:
        self._settings = settings
        self._redis: Redis | None = None
        self._rules: List[NormalizerRule] = []

    async def init(self) -> None:
        self._redis = Redis(
            host=self._settings.redis_host,
            port=self._settings.redis_port,
            db=self._settings.redis_db,
            password=self._settings.redis_password,
            decode_responses=True,
        )
        self._rules = load_rules(self._settings)
        try:
            await self._redis.xgroup_create(
                name=self._settings.raw_stream_key,
                groupname=self._settings.consumer_group,
                id='0-0',
                mkstream=True,
            )
        except ResponseError as exc:
            if 'BUSYGROUP' not in str(exc):
                raise
        logger.info(
            'NormalizerWorker initialized',
            extra={'extra': {
                'raw_stream': self._settings.raw_stream_key,
                'normalized_stream': self._settings.normalized_stream_key,
                'batch_size': self._settings.batch_size,
                'rules_count': len(self._rules),
                'group': self._settings.consumer_group,
                'consumer': self._settings.consumer_name,
            }},
        )

    async def _reload_rules_periodically(self) -> None:
        while True:
            try:
                self._rules = load_rules(self._settings)
            except Exception as exc:  # noqa: BLE001
                logger.error('Failed to reload normalizer rules', extra={'extra': {'error': str(exc)}})
            await asyncio.sleep(30)

    async def run(self) -> None:
        assert self._redis is not None
        redis = self._redis
        asyncio.create_task(self._reload_rules_periodically())
        while True:
            try:
                resp = await redis.xreadgroup(
                    groupname=self._settings.consumer_group,
                    consumername=self._settings.consumer_name,
                    streams={self._settings.raw_stream_key: '>'},
                    count=self._settings.batch_size,
                    block=self._settings.block_ms,
                )
            except Exception as exc:  # noqa: BLE001
                logger.error('Redis XREADGROUP failed in normalizer', extra={'extra': {'error': str(exc)}})
                await asyncio.sleep(1)
                continue
            if not resp:
                continue

            read_count = 0
            normalized_count = 0
            ack_ids: List[str] = []
            for _stream_key, messages in resp:
                for msg_id, fields in messages:
                    read_count += 1
                    raw_event: Dict[str, Any] = dict(fields)
                    uem = apply_rules(self._rules, raw_event)
                    if uem is None:
                        ack_ids.append(msg_id)
                        continue
                    try:
                        await redis.xadd(
                            self._settings.normalized_stream_key,
                            {k: '' if v is None else str(v) for k, v in uem.items()},
                            maxlen=1_000_000,
                            approximate=True,
                        )
                        normalized_count += 1
                        ack_ids.append(msg_id)
                    except Exception as exc:  # noqa: BLE001
                        logger.error('Failed to push normalized event to Redis', extra={'extra': {'error': str(exc), 'msg_id': msg_id}})
            if ack_ids:
                await redis.xack(self._settings.raw_stream_key, self._settings.consumer_group, *ack_ids)
            if read_count > 0:
                logger.info('Normalizer batch processed', extra={'extra': {'raw_events_read': read_count, 'normalized_events': normalized_count, 'acked': len(ack_ids)}})


async def main() -> None:
    configure_logging()
    settings = NormalizerSettings.load()
    worker = NormalizerWorker(settings)
    await worker.init()
    await worker.run()


if __name__ == '__main__':
    asyncio.run(main())
