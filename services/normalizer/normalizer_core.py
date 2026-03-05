from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import jmespath
from clickhouse_driver import Client

from .config import NormalizerSettings

logger = logging.getLogger(__name__)


@dataclass
class NormalizerRule:
    id: int
    priority: int
    source_type: str
    event_matcher_expr: str
    compiled_matcher: Optional[jmespath.parser.ParsedResult]
    compiled_mapping: Dict[str, jmespath.parser.ParsedResult]


def load_rules(settings: NormalizerSettings) -> List[NormalizerRule]:
    client = Client(
        host=settings.ch_host,
        port=settings.ch_port,
        user=settings.ch_user,
        password=settings.ch_password,
        database=settings.ch_db,
        send_receive_timeout=settings.ch_timeout_secs,
    )
    rows = client.execute(
        """
        SELECT id, priority, source_type, event_matcher, uem_mapping
        FROM siem.normalizer_rules
        WHERE enabled = 1
        ORDER BY priority ASC, id ASC
        """
    )
    rules: List[NormalizerRule] = []
    for rule_id, priority, source_type, event_matcher, uem_mapping_str in rows:
        try:
            mapping_dict = json.loads(uem_mapping_str)
            if not isinstance(mapping_dict, dict):
                raise ValueError('uem_mapping must be a JSON object')
        except Exception as exc:  # noqa: BLE001
            logger.error('Failed to parse uem_mapping JSON', extra={'extra': {'rule_id': rule_id, 'error': str(exc)}})
            continue

        compiled_matcher: Optional[jmespath.parser.ParsedResult] = None
        if event_matcher and str(event_matcher).strip():
            try:
                compiled_matcher = jmespath.compile(event_matcher)
            except Exception as exc:  # noqa: BLE001
                logger.error('Failed to compile normalizer matcher', extra={'extra': {'rule_id': rule_id, 'matcher': event_matcher, 'error': str(exc)}})
                continue

        compiled_mapping: Dict[str, jmespath.parser.ParsedResult] = {}
        for uem_field, expr in mapping_dict.items():
            try:
                compiled_mapping[uem_field] = jmespath.compile(expr)
            except Exception as exc:  # noqa: BLE001
                logger.error('Failed to compile JMESPath expression in uem_mapping', extra={'extra': {'rule_id': rule_id, 'uem_field': uem_field, 'expr': expr, 'error': str(exc)}})

        rules.append(
            NormalizerRule(
                id=rule_id,
                priority=priority,
                source_type=str(source_type or '').strip(),
                event_matcher_expr=event_matcher,
                compiled_matcher=compiled_matcher,
                compiled_mapping=compiled_mapping,
            )
        )

    logger.info('Loaded normalizer rules', extra={'extra': {'count': len(rules)}})
    return rules


def _source_type_matches(rule: NormalizerRule, raw_event: Dict[str, Any]) -> bool:
    source_type = str(raw_event.get('source_type', '') or '').strip()
    expected = rule.source_type.lower()
    if expected in {'', '*', 'generic', 'any'}:
        return True
    return source_type.lower() == expected


def _matcher_matches(rule: NormalizerRule, raw_event: Dict[str, Any]) -> bool:
    if rule.compiled_matcher is None:
        return True
    try:
        return bool(rule.compiled_matcher.search(raw_event))
    except Exception as exc:  # noqa: BLE001
        logger.error('Failed to evaluate normalizer matcher', extra={'extra': {'rule_id': rule.id, 'matcher': rule.event_matcher_expr, 'error': str(exc)}})
        return False


def _build_uem(rule: NormalizerRule, raw_event: Dict[str, Any]) -> Dict[str, Any]:
    uem: Dict[str, Any] = {str(k): v for k, v in raw_event.items() if '.' in str(k) or str(k) in {'message', 'severity', 'log_source', 'source_type', 'source'}}
    for uem_field, compiled_expr in rule.compiled_mapping.items():
        try:
            value = compiled_expr.search(raw_event)
        except Exception as exc:  # noqa: BLE001
            logger.error('Failed to apply JMESPath mapping', extra={'extra': {'rule_id': rule.id, 'uem_field': uem_field, 'error': str(exc)}})
            value = None
        uem[uem_field] = value

    if 'event.provider' not in uem or uem.get('event.provider') in (None, ''):
        uem['event.provider'] = raw_event.get('source_type', '') or ''
    if 'event.original' not in uem or uem.get('event.original') in (None, ''):
        uem['event.original'] = raw_event.get('message', '') or str(raw_event)
    if 'host.name' not in uem or uem.get('host.name') in (None, ''):
        uem['host.name'] = raw_event.get('source', '') or raw_event.get('log_source', '') or ''
    if 'log_source' not in uem or uem.get('log_source') in (None, ''):
        uem['log_source'] = raw_event.get('source', '') or raw_event.get('log_source', '') or ''
    return uem


def apply_rules(rules: List[NormalizerRule], raw_event: Dict[str, Any]) -> Dict[str, Any] | None:
    for rule in rules:
        if not _source_type_matches(rule, raw_event):
            continue
        if not _matcher_matches(rule, raw_event):
            continue
        return _build_uem(rule, raw_event)
    return None
