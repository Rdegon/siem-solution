from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, List, Optional

from redis.asyncio import Redis
from redis.exceptions import ResponseError

from .config import FilterSettings
from .filter_core import FilterRule, eval_expr, load_filter_rules
from .logging_conf import configure_logging

logger = logging.getLogger(__name__)


class FilterWorker:
    def __init__(self, settings: FilterSettings) -> None:
        self._settings = settings
        self._redis: Optional[Redis] = None
        self._rules: List[FilterRule] = []

    async def init(self) -> None:
        self._redis = Redis(
            host=self._settings.redis_host,
            port=self._settings.redis_port,
            db=self._settings.redis_db,
            password=self._settings.redis_password,
            decode_responses=True,
        )
        self._rules = load_filter_rules(self._settings)
        try:
            await self._redis.xgroup_create(
                name=self._settings.normalized_stream_key,
                groupname=self._settings.group_name,
                id='0-0',
                mkstream=True,
            )
        except ResponseError as exc:
            if 'BUSYGROUP' not in str(exc):
                raise
        logger.info(
            'FilterWorker initialized',
            extra={'extra': {
                'normalized_stream': self._settings.normalized_stream_key,
                'filtered_stream': self._settings.filtered_stream_key,
                'batch_size': self._settings.batch_size,
                'rules_count': len(self._rules),
                'group': self._settings.group_name,
                'consumer': self._settings.consumer_name,
            }},
        )

    async def _reload_rules_periodically(self) -> None:
        while True:
            try:
                self._rules = load_filter_rules(self._settings)
            except Exception as exc:  # noqa: BLE001
                logger.error('Failed to reload filter rules', extra={'extra': {'error': str(exc)}})
            await asyncio.sleep(30)

    async def run(self) -> None:
        assert self._redis is not None
        redis = self._redis
        asyncio.create_task(self._reload_rules_periodically())
        while True:
            try:
                resp = await redis.xreadgroup(
                    groupname=self._settings.group_name,
                    consumername=self._settings.consumer_name,
                    streams={self._settings.normalized_stream_key: '>'},
                    count=self._settings.batch_size,
                    block=self._settings.block_ms,
                )
            except Exception as exc:  # noqa: BLE001
                logger.error('Redis XREADGROUP failed in filter', extra={'extra': {'error': str(exc)}})
                await asyncio.sleep(1)
                continue
            if not resp:
                continue

            read_count = 0
            passed_count = 0
            dropped_count = 0
            tagged_count = 0
            ack_ids: List[str] = []
            for _stream_key, messages in resp:
                for msg_id, fields in messages:
                    read_count += 1
                    event = dict(fields)
                    decision, final_event = self.apply_rules(event)
                    if decision == 'drop':
                        dropped_count += 1
                        ack_ids.append(msg_id)
                        continue
                    if decision == 'tag':
                        tagged_count += 1
                    try:
                        await redis.xadd(
                            self._settings.filtered_stream_key,
                            {k: '' if v is None else str(v) for k, v in final_event.items()},
                            maxlen=1_000_000,
                            approximate=True,
                        )
                        passed_count += 1
                        ack_ids.append(msg_id)
                    except Exception as exc:  # noqa: BLE001
                        logger.error('Failed to push filtered event to Redis', extra={'extra': {'error': str(exc), 'msg_id': msg_id}})
            if ack_ids:
                await redis.xack(self._settings.normalized_stream_key, self._settings.group_name, *ack_ids)
            if read_count > 0:
                logger.info('Filter batch processed', extra={'extra': {'events_read': read_count, 'events_passed': passed_count, 'events_dropped': dropped_count, 'events_tagged': tagged_count, 'acked': len(ack_ids)}})

    def apply_rules(self, event: Dict[str, Any]) -> tuple[str, Dict[str, Any]]:
        result = dict(event)
        tags: List[str] = []
        for rule in self._rules:
            if not rule.expr_ast:
                continue
            try:
                matched = eval_expr(rule.expr_ast, event)
            except Exception as exc:  # noqa: BLE001
                logger.error('Error evaluating filter rule', extra={'extra': {'rule_id': rule.id, 'expr': rule.expr_text, 'error': str(exc)}})
                continue
            if not matched:
                continue
            if rule.action == 'drop':
                return 'drop', result
            if rule.action == 'tag':
                tags.extend(rule.tags)
                break
            if rule.action == 'pass':
                break
        if tags:
            existing = result.get('tags')
            result['tags'] = f"{existing},{','.join(tags)}" if existing else ','.join(tags)
            return 'tag', result
        return 'pass', result


async def main() -> None:
    configure_logging()
    settings = FilterSettings.load()
    worker = FilterWorker(settings)
    await worker.init()
    await worker.run()


if __name__ == '__main__':
    asyncio.run(main())
