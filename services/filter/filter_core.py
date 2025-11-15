"""
/home/siem/siem-solution/services/filter/filter_core.py

Логика фильтра:
  - Загрузка правил из ClickHouse (siem.filter_rules).
  - Мини-DSL для expr:
      expr := cmp (('and' | 'or') cmp)*
      cmp  := field '==' string_literal | field '!=' string_literal

    Примеры:
      event.provider == 'http_json'
      event.provider == 'http_json' and event.category == 'test'

  - Действия:
      pass -> пропускаем событие
      drop -> отбрасываем
      tag  -> добавляем теги (строкой в поле 'tags') и пропускаем
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from clickhouse_driver import Client

from .config import FilterSettings

logger = logging.getLogger(__name__)


@dataclass
class FilterRule:
    id: int
    name: str
    description: str
    priority: int
    action: str
    tags: List[str]
    expr_text: str
    expr_ast: Optional[Tuple]  # внутреннее представление выражения


# ====== Загрузка правил из ClickHouse ======


def load_filter_rules(settings: FilterSettings) -> List[FilterRule]:
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
            priority,
            expr,
            action,
            tags
        FROM siem.filter_rules
        WHERE enabled = 1
        ORDER BY priority ASC, id ASC
        """
    )

    rules: List[FilterRule] = []
    for row in rows:
        rule_id, name, description, priority, expr, action, tags = row
        try:
            expr_ast = parse_expr(expr) if expr else None
        except Exception as exc:  # noqa: BLE001
            logger.error(
                "Failed to parse filter expr",
                extra={
                    "extra": {
                        "rule_id": rule_id,
                        "expr": expr,
                        "error": str(exc),
                    }
                },
            )
            expr_ast = None

        rules.append(
            FilterRule(
                id=rule_id,
                name=name,
                description=description,
                priority=priority,
                action=str(action),
                tags=list(tags),
                expr_text=expr,
                expr_ast=expr_ast,
            )
        )

    logger.info(
        "Loaded filter rules",
        extra={"extra": {"count": len(rules)}},
    )
    return rules


# ====== Мини-DSL парсер ======

Token = Tuple[str, str]  # (type, value)


def _tokenize(expr: str) -> List[Token]:
    """
    Разбивает expr на токены:
      - NAME: [a-zA-Z0-9_.]+
      - STRING: '...'
      - OP: ==, !=
      - AND, OR
    """

    tokens: List[Token] = []
    i = 0
    length = len(expr)

    while i < length:
        ch = expr[i]
        if ch.isspace():
            i += 1
            continue

        # Операторы ==, !=
        if expr.startswith("==", i):
            tokens.append(("OP", "=="))
            i += 2
            continue
        if expr.startswith("!=", i):
            tokens.append(("OP", "!="))
            i += 2
            continue

        # Строковый литерал в одиночных кавычках
        if ch == "'":
            j = i + 1
            buf = []
            while j < length and expr[j] != "'":
                buf.append(expr[j])
                j += 1
            if j >= length:
                raise ValueError("Unterminated string literal in filter expr")
            tokens.append(("STRING", "".join(buf)))
            i = j + 1
            continue

        # Имя / путь: буквы, цифры, _, .
        if re.match(r"[A-Za-z0-9_]", ch):
            j = i + 1
            while j < length and re.match(r"[A-Za-z0-9_.]", expr[j]):
                j += 1
            value = expr[i:j]
            if value == "and":
                tokens.append(("AND", value))
            elif value == "or":
                tokens.append(("OR", value))
            else:
                tokens.append(("NAME", value))
            i = j
            continue

        raise ValueError(f"Unexpected character in expr: {ch!r} at position {i}")

    return tokens


# AST представление:
#   ("cmp", field, op, value)
#   ("and", left, right)
#   ("or", left, right)


def parse_expr(expr: str) -> Tuple:
    tokens = _tokenize(expr)
    if not tokens:
        raise ValueError("Empty expr")

    pos = 0

    def parse_cmp() -> Tuple:
        nonlocal pos
        if pos + 3 > len(tokens):
            raise ValueError("Invalid comparison in expr")

        t_field, field = tokens[pos]
        t_op, op = tokens[pos + 1]
        t_val, val = tokens[pos + 2]

        if t_field != "NAME":
            raise ValueError("Expected field name in comparison")
        if t_op != "OP" or op not in ("==", "!="):
            raise ValueError("Expected == or != in comparison")
        if t_val != "STRING":
            raise ValueError("Expected string literal in comparison")

        pos += 3
        return ("cmp", field, op, val)

    def parse_expr_inner() -> Tuple:
        nonlocal pos
        left = parse_cmp()

        while pos < len(tokens):
            t, v = tokens[pos]
            if t == "AND":
                pos += 1
                right = parse_cmp()
                left = ("and", left, right)
            elif t == "OR":
                pos += 1
                right = parse_cmp()
                left = ("or", left, right)
            else:
                break
        return left

    ast = parse_expr_inner()
    if pos != len(tokens):
        raise ValueError("Unexpected tokens at end of expr")
    return ast


def _get_field_value(event: Dict[str, Any], field: str) -> str:
    """Поле берём как есть (ключ с точкой)."""
    value = event.get(field)
    if value is None:
        return ""
    return str(value)


def eval_expr(ast: Optional[Tuple], event: Dict[str, Any]) -> bool:
    """Оценивает AST для события."""
    if ast is None:
        return False

    node_type = ast[0]

    if node_type == "cmp":
        _, field, op, val = ast
        actual = _get_field_value(event, field)
        if op == "==":
            return actual == val
        if op == "!=":
            return actual != val
        return False

    if node_type == "and":
        _, left, right = ast
        return eval_expr(left, event) and eval_expr(right, event)

    if node_type == "or":
        _, left, right = ast
        return eval_expr(left, event) or eval_expr(right, event)

    raise ValueError(f"Unknown AST node type: {node_type}")
