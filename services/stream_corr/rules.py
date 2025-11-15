"""
/home/siem/siem-solution/services/stream_corr/rules.py

Работа с потоковыми правилами корреляции:
  - Загрузка из siem.correlation_rules_stream
  - Парсинг expr через parse_expr (из services.filter.filter_core)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, List, Optional, Tuple

from clickhouse_driver import Client

from services.filter.filter_core import parse_expr, eval_expr
from .config import StreamCorrSettings

logger = logging.getLogger(__name__)


@dataclass
class StreamCorrRule:
    id: int
    name: str
    description: str
    enabled: bool
    severity: str
    pattern: str
    window_s: int
    threshold: int
    expr_text: str
    expr_ast: Optional[Tuple[Any, ...]]
    entity_field: str


def load_stream_rules(settings: StreamCorrSettings) -> List[StreamCorrRule]:
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
            name,
            description,
            enabled,
            severity,
            pattern,
            window_s,
            threshold,
            expr,
            entity_field
        FROM siem.correlation_rules_stream
        WHERE enabled = 1
        ORDER BY id
        """
    )

    rules: List[StreamCorrRule] = []
    for row in rows:
        (
            rule_id,
            name,
            description,
            enabled,
            severity,
            pattern,
            window_s,
            threshold,
            expr,
            entity_field,
        ) = row

        expr_ast: Optional[Tuple[Any, ...]] = None
        if expr:
            try:
                expr_ast = parse_expr(expr)
            except Exception as exc:  # noqa: BLE001
                logger.error(
                    "Failed to parse stream correlation expr",
                    extra={
                        "extra": {
                            "rule_id": rule_id,
                            "expr": expr,
                            "error": str(exc),
                        }
                    },
                )

        rules.append(
            StreamCorrRule(
                id=int(rule_id),
                name=name,
                description=description,
                enabled=bool(enabled),
                severity=str(severity),
                pattern=str(pattern),
                window_s=int(window_s),
                threshold=int(threshold),
                expr_text=expr,
                expr_ast=expr_ast,
                entity_field=entity_field,
            )
        )

    logger.info(
        "Loaded stream correlation rules",
        extra={"extra": {"count": len(rules)}},
    )

    return rules


def matches_rule(rule: StreamCorrRule, event: dict[str, Any]) -> bool:
    """Проверяем условие expr для события."""
    if rule.expr_ast is None:
        return False
    try:
        return bool(eval_expr(rule.expr_ast, event))
    except Exception as exc:  # noqa: BLE001
        logger.error(
            "Error evaluating stream correlation rule",
            extra={
                "extra": {
                    "rule_id": rule.id,
                    "expr": rule.expr_text,
                    "error": str(exc),
                }
            },
        )
        return False
