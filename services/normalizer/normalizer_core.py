"""
/home/siem/siem-solution/services/normalizer/normalizer_core.py

Назначение:
  - Загрузка правил нормализации из ClickHouse (таблица siem.normalizer_rules).
  - Применение правил к сырому событию:
      raw_event (dict) -> UEM-событие (dict) или None.

На данном этапе:
  - JMESPath используется для маппинга полей (uem_mapping).
  - Фильтрация по event_matcher отключена: применяется первое включённое правило
    к каждому событию. Это гарантирует поток в siem:normalized и siem.events.
  - Позже можно вернуть полноценную логику event_matcher (JMESPath-выражения).
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any, Dict, List

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
    compiled_mapping: Dict[str, jmespath.parser.ParsedResult]


def load_rules(settings: NormalizerSettings) -> List[NormalizerRule]:
    """Загружает правила нормализации из ClickHouse.

    Ожидаемая структура siem.normalizer_rules:
      - id            UInt32
      - enabled       UInt8
      - priority      UInt16
      - source_type   String / LowCardinality(String)
      - event_matcher String       -- пока игнорируем
      - uem_mapping   String (JSON-объект: { "uem.field": "jmespath_expr", ... })
    """
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
        SELECT
            id,
            priority,
            source_type,
            event_matcher,
            uem_mapping
        FROM siem.normalizer_rules
        WHERE enabled = 1
        ORDER BY priority ASC, id ASC
        """
    )

    rules: List[NormalizerRule] = []

    for row in rows:
        rule_id, priority, source_type, event_matcher, uem_mapping_str = row

        try:
            mapping_dict = json.loads(uem_mapping_str)
            if not isinstance(mapping_dict, dict):
                raise ValueError("uem_mapping must be a JSON object")
        except Exception as exc:  # noqa: BLE001
            logger.error(
                "Failed to parse uem_mapping JSON",
                extra={
                    "extra": {
                        "rule_id": rule_id,
                        "error": str(exc),
                    }
                },
            )
            continue

        compiled_mapping: Dict[str, jmespath.parser.ParsedResult] = {}
        for uem_field, expr in mapping_dict.items():
            try:
                compiled_mapping[uem_field] = jmespath.compile(expr)
            except Exception as exc:  # noqa: BLE001
                logger.error(
                    "Failed to compile JMESPath expression in uem_mapping",
                    extra={
                        "extra": {
                            "rule_id": rule_id,
                            "uem_field": uem_field,
                            "expr": expr,
                            "error": str(exc),
                        }
                    },
                )

        rules.append(
            NormalizerRule(
                id=rule_id,
                priority=priority,
                source_type=source_type,
                event_matcher_expr=event_matcher,
                compiled_mapping=compiled_mapping,
            )
        )

    logger.info(
        "Loaded normalizer rules",
        extra={"extra": {"count": len(rules)}},
    )

    return rules


def apply_rules(
    rules: List[NormalizerRule],
    raw_event: Dict[str, Any],
) -> Dict[str, Any] | None:
    """Применяет правила к сырому событию.

    Текущая упрощённая логика:
      - Берётся первое правило из списка `rules`.
      - На него всегда "считается", что событие подходит (matcher не используется).
      - По uem_mapping через JMESPath формируется UEM-словарь.
      - Если каких-то ключей нет, добавляем дефолты из raw_event:
          event.provider <- raw_event["source_type"] (если есть)
          event.original <- raw_event["message"] (если есть)

    Возвращает:
      - dict с UEM-полями, если удалось что-то собрать;
      - None, если правил нет вообще.
    """
    if not rules:
        return None

    rule = rules[0]

    uem: Dict[str, Any] = {}

    # Применяем JMESPath-мэппинг
    for uem_field, compiled_expr in rule.compiled_mapping.items():
        try:
            value = compiled_expr.search(raw_event)
        except Exception as exc:  # noqa: BLE001
            logger.error(
                "Failed to apply JMESPath mapping",
                extra={
                    "extra": {
                        "rule_id": rule.id,
                        "uem_field": uem_field,
                        "error": str(exc),
                    }
                },
            )
            value = None
        uem[uem_field] = value

    # Дефолты для ключевых полей
    if "event.provider" not in uem or uem.get("event.provider") in (None, ""):
        uem["event.provider"] = raw_event.get("source_type", "") or ""
    if "event.original" not in uem or uem.get("event.original") in (None, ""):
        # Если в raw_event есть поле message — используем его
        if "message" in raw_event:
            uem["event.original"] = raw_event.get("message", "") or ""
        else:
            # Фолбэк — строковое представление события
            uem["event.original"] = str(raw_event)

    # При желании можно добавить ещё дефолтов (category/type/source.ip и т.п.)

    return uem
