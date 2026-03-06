from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import jmespath
from clickhouse_driver import Client

from .config import NormalizerSettings

logger = logging.getLogger(__name__)

SYSLOG_RE = re.compile(
    r"^(?:<(?P<pri>\d+)>)?(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<clock>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<program>[\w./-]+?)(?:\[(?P<pid>\d+)\])?:\s?(?P<body>.*)$"
)
KV_RE = re.compile(r'([A-Za-z0-9_.-]+)=(".*?"|\'.*?\'|[^ ]+)')
IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
SSHD_ACCEPT_RE = re.compile(
    r"Accepted (?P<method>\w+) for (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+) port (?P<port>\d+)",
    re.IGNORECASE,
)
SSHD_FAIL_RE = re.compile(
    r"Failed (?P<method>\w+) for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+) port (?P<port>\d+)",
    re.IGNORECASE,
)
SSHD_SESSION_RE = re.compile(
    r"pam_unix\(sshd:session\): session (?P<state>opened|closed) for user (?P<user>\S+)",
    re.IGNORECASE,
)
SUDO_COMMAND_RE = re.compile(
    r"^\s*(?P<user>\S+)\s*:\s*PWD=(?P<pwd>[^;]+)\s*;\s*USER=(?P<target>[^;]+)\s*;\s*COMMAND=(?P<command>.+)$"
)
SUDO_SESSION_RE = re.compile(
    r"pam_unix\(sudo:session\): session (?P<state>opened|closed) for user (?P<target>\S+)",
    re.IGNORECASE,
)
SYSLOG_LEVEL_MAP = {
    0: "critical",
    1: "critical",
    2: "high",
    3: "high",
    4: "medium",
    5: "low",
    6: "info",
    7: "low",
}


@dataclass
class NormalizerRule:
    id: int
    priority: int
    source_type: str
    event_matcher_expr: str
    compiled_matcher: Optional[jmespath.parser.ParsedResult]
    compiled_mapping: Dict[str, jmespath.parser.ParsedResult]


def _clean_value(value: Any) -> str:
    return str(value or "").replace("\x1d", " ").strip()


def _is_ipv4(value: str) -> bool:
    return bool(value and IPV4_RE.match(value))


def _strip_quotes(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def _decode_hex(value: str) -> str:
    raw = value.strip()
    if not raw or len(raw) % 2 != 0 or not re.fullmatch(r"[0-9A-Fa-f]+", raw):
        return raw
    try:
        decoded = bytes.fromhex(raw).decode("utf-8", errors="replace").replace("\x00", " ").strip()
    except Exception:
        return raw
    return decoded or raw


def _merge_non_empty(target: Dict[str, Any], updates: Dict[str, Any]) -> Dict[str, Any]:
    for key, value in updates.items():
        if value in (None, "", [], {}, "?"):
            continue
        target[key] = value
    return target


def _parse_key_values(text: str) -> Dict[str, str]:
    parsed: Dict[str, str] = {}
    for key, value in KV_RE.findall(text):
        parsed[key] = _strip_quotes(value)
    return parsed


def _derive_outcome(values: Dict[str, str]) -> str:
    for key in ("res", "success", "result"):
        raw = values.get(key, "")
        lowered = raw.lower()
        if lowered in {"success", "yes", "ok", "opened"}:
            return "success"
        if lowered in {"failed", "failure", "no", "denied", "closed"}:
            return "failure"
    return "unknown"


def _derive_severity(program: str, event_type: str, outcome: str, default_level: str) -> str:
    if program == "sshd" and outcome == "failure":
        return "medium"
    if program == "sudo" and event_type == "sudo_command":
        return "medium"
    if event_type == "audit_exec_as_root":
        return "high"
    if event_type in {"audit_user_login_failure", "audit_user_auth_failure"}:
        return "medium"
    return default_level or "info"


def _parse_auditd(body: str, base: Dict[str, Any]) -> Dict[str, Any]:
    values = _parse_key_values(body)
    inner_msg = values.get("msg", "")
    if "=" in inner_msg:
        _merge_non_empty(values, _parse_key_values(inner_msg))

    event_type_raw = values.get("type", "UNKNOWN").upper()
    outcome = _derive_outcome(values)
    acct = values.get("acct", "")
    addr = values.get("addr", "")
    exe = values.get("exe", "")
    command_hex = values.get("cmd", "")
    proctitle_hex = values.get("proctitle", "")
    audit_key = values.get("key", "")

    event_category = "audit"
    event_action = "audit"
    event_type = f"audit_{event_type_raw.lower()}"

    if event_type_raw in {"USER_AUTH", "USER_ACCT", "USER_LOGIN"}:
        event_category = "authentication"
        event_action = "authentication" if event_type_raw != "USER_LOGIN" else "login"
        if outcome in {"success", "failure"}:
            event_type = f"audit_{event_type_raw.lower()}_{outcome}"
    elif event_type_raw in {"USER_START", "USER_END", "CRED_ACQ", "CRED_DISP", "CRED_REFR"}:
        event_category = "session"
        event_action = "session"
        if outcome in {"success", "failure"}:
            event_type = f"audit_{event_type_raw.lower()}_{outcome}"
    elif event_type_raw == "USER_CMD":
        event_category = "privilege"
        event_action = "command"
        event_type = "audit_user_command"
    elif event_type_raw in {"EXECVE", "SYSCALL", "PROCTITLE", "PATH", "CWD"}:
        event_category = "process"
        event_action = "execute"
        if audit_key == "exec_as_root":
            event_category = "privilege"
            event_action = "execute_as_root"
            event_type = "audit_exec_as_root"
        else:
            event_type = f"audit_{event_type_raw.lower()}"

    result = {
        "event.provider": "linux.auditd",
        "event.category": event_category,
        "event.action": event_action,
        "event.type": event_type,
        "event.outcome": outcome,
        "audit.type": event_type_raw,
        "audit.id": values.get("msg", ""),
        "audit.key": audit_key,
        "user.name": acct,
        "user.audit.name": values.get("AUID", "") or values.get("auid", ""),
        "source.ip": addr if _is_ipv4(addr) else "",
        "process.executable": exe,
        "process.name": values.get("comm", "") or base.get("process.name", ""),
        "process.command_line": _decode_hex(command_hex) or _decode_hex(proctitle_hex),
        "host.name": values.get("hostname", "") or base.get("host.name", ""),
    }
    result["event.severity"] = _derive_severity("auditd", result["event.type"], outcome, str(base.get("log.level", "info")))
    return result


def _parse_sshd(body: str, base: Dict[str, Any]) -> Dict[str, Any]:
    accepted = SSHD_ACCEPT_RE.search(body)
    if accepted:
        return {
            "event.provider": "linux.sshd",
            "event.category": "authentication",
            "event.action": "authentication_success",
            "event.type": "ssh_login_success",
            "event.outcome": "success",
            "event.severity": "info",
            "user.name": accepted.group("user"),
            "source.ip": accepted.group("ip"),
            "source.port": accepted.group("port"),
            "network.transport": "tcp",
            "auth.method": accepted.group("method").lower(),
        }

    failed = SSHD_FAIL_RE.search(body)
    if failed:
        return {
            "event.provider": "linux.sshd",
            "event.category": "authentication",
            "event.action": "authentication_failed",
            "event.type": "ssh_login_failure",
            "event.outcome": "failure",
            "event.severity": "medium",
            "user.name": failed.group("user"),
            "source.ip": failed.group("ip"),
            "source.port": failed.group("port"),
            "network.transport": "tcp",
            "auth.method": failed.group("method").lower(),
        }

    session = SSHD_SESSION_RE.search(body)
    if session:
        state = session.group("state").lower()
        return {
            "event.provider": "linux.sshd",
            "event.category": "session",
            "event.action": f"session_{state}",
            "event.type": f"ssh_session_{state}",
            "event.outcome": "success",
            "event.severity": "info",
            "user.name": session.group("user"),
        }

    return {
        "event.provider": "linux.sshd",
        "event.category": "authentication",
        "event.type": "ssh_event",
        "event.action": "observe",
        "event.severity": str(base.get("log.level", "info") or "info"),
    }


def _parse_sudo(body: str, base: Dict[str, Any]) -> Dict[str, Any]:
    command = SUDO_COMMAND_RE.search(body)
    if command:
        target_user = command.group("target").strip()
        severity = "high" if target_user == "root" else "medium"
        return {
            "event.provider": "linux.sudo",
            "event.category": "privilege",
            "event.action": "command",
            "event.type": "sudo_command",
            "event.outcome": "success",
            "event.severity": severity,
            "user.name": command.group("user").strip(),
            "user.target.name": target_user,
            "process.command_line": command.group("command").strip(),
            "process.working_directory": command.group("pwd").strip(),
        }

    session = SUDO_SESSION_RE.search(body)
    if session:
        state = session.group("state").lower()
        return {
            "event.provider": "linux.sudo",
            "event.category": "session",
            "event.action": f"session_{state}",
            "event.type": f"sudo_session_{state}",
            "event.outcome": "success",
            "event.severity": "info",
            "user.target.name": session.group("target"),
        }

    return {
        "event.provider": "linux.sudo",
        "event.category": "privilege",
        "event.type": "sudo_event",
        "event.action": "observe",
        "event.severity": str(base.get("log.level", "info") or "info"),
    }


def _parse_linux_syslog(raw_event: Dict[str, Any]) -> Dict[str, Any]:
    message = _clean_value(raw_event.get("message"))
    source_ip = _clean_value(raw_event.get("source"))
    match = SYSLOG_RE.match(message)

    enriched: Dict[str, Any] = {
        "event.original": message,
        "log_source": source_ip,
        "source.ip": source_ip if _is_ipv4(source_ip) else "",
        "event.provider": "linux.syslog",
        "event.category": "syslog",
        "event.type": "syslog",
        "event.action": "observe",
        "event.severity": "info",
    }

    body = message
    program = ""
    if match:
        body = _clean_value(match.group("body"))
        program = _clean_value(match.group("program")).lower()
        pri = int(match.group("pri") or 13)
        severity_code = pri % 8
        level = SYSLOG_LEVEL_MAP.get(severity_code, "info")
        _merge_non_empty(
            enriched,
            {
                "log.level": level,
                "host.name": _clean_value(match.group("host")),
                "process.name": program,
                "process.pid": _clean_value(match.group("pid")),
                "event.provider": f"linux.{program}" if program else "linux.syslog",
            },
        )
        enriched["event.severity"] = level

    if program == "auditd" or " auditd:" in message.lower():
        return _merge_non_empty(enriched, _parse_auditd(body, enriched))
    if program == "sshd":
        return _merge_non_empty(enriched, _parse_sshd(body, enriched))
    if program == "sudo":
        return _merge_non_empty(enriched, _parse_sudo(body, enriched))

    return enriched


def _enrich_raw_event(raw_event: Dict[str, Any]) -> Dict[str, Any]:
    enriched = dict(raw_event)
    source_type = _clean_value(raw_event.get("source_type")).lower()
    if source_type == "syslog" or _clean_value(raw_event.get("message")).startswith("<"):
        _merge_non_empty(enriched, _parse_linux_syslog(raw_event))
    return enriched


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
                raise ValueError("uem_mapping must be a JSON object")
        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to parse uem_mapping JSON", extra={"extra": {"rule_id": rule_id, "error": str(exc)}})
            continue

        compiled_matcher: Optional[jmespath.parser.ParsedResult] = None
        if event_matcher and str(event_matcher).strip():
            try:
                compiled_matcher = jmespath.compile(event_matcher)
            except Exception as exc:  # noqa: BLE001
                logger.error("Failed to compile normalizer matcher", extra={"extra": {"rule_id": rule_id, "matcher": event_matcher, "error": str(exc)}})
                continue

        compiled_mapping: Dict[str, jmespath.parser.ParsedResult] = {}
        for uem_field, expr in mapping_dict.items():
            try:
                compiled_mapping[uem_field] = jmespath.compile(expr)
            except Exception as exc:  # noqa: BLE001
                logger.error("Failed to compile JMESPath expression in uem_mapping", extra={"extra": {"rule_id": rule_id, "uem_field": uem_field, "expr": expr, "error": str(exc)}})

        rules.append(
            NormalizerRule(
                id=rule_id,
                priority=priority,
                source_type=str(source_type or "").strip(),
                event_matcher_expr=event_matcher,
                compiled_matcher=compiled_matcher,
                compiled_mapping=compiled_mapping,
            )
        )

    logger.info("Loaded normalizer rules", extra={"extra": {"count": len(rules)}})
    return rules


def _source_type_matches(rule: NormalizerRule, raw_event: Dict[str, Any]) -> bool:
    source_type = str(raw_event.get("source_type", "") or "").strip()
    expected = rule.source_type.lower()
    if expected in {"", "*", "generic", "any"}:
        return True
    return source_type.lower() == expected


def _matcher_matches(rule: NormalizerRule, raw_event: Dict[str, Any]) -> bool:
    if rule.compiled_matcher is None:
        return True
    try:
        return bool(rule.compiled_matcher.search(raw_event))
    except Exception as exc:  # noqa: BLE001
        logger.error("Failed to evaluate normalizer matcher", extra={"extra": {"rule_id": rule.id, "matcher": rule.event_matcher_expr, "error": str(exc)}})
        return False


def _build_uem(rule: Optional[NormalizerRule], raw_event: Dict[str, Any]) -> Dict[str, Any]:
    uem: Dict[str, Any] = {}
    compiled_mapping = rule.compiled_mapping if rule else {}

    for uem_field, compiled_expr in compiled_mapping.items():
        try:
            value = compiled_expr.search(raw_event)
        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to apply JMESPath mapping", extra={"extra": {"rule_id": rule.id if rule else "builtin", "uem_field": uem_field, "error": str(exc)}})
            value = None
        if value not in (None, "", [], {}):
            uem[uem_field] = value

    for key, value in raw_event.items():
        if "." in str(key) or str(key) in {"message", "severity", "log_source", "source_type", "source"}:
            if value not in (None, "", [], {}):
                uem[str(key)] = value

    if "event.provider" not in uem or uem.get("event.provider") in (None, ""):
        uem["event.provider"] = raw_event.get("source_type", "") or ""
    if "event.original" not in uem or uem.get("event.original") in (None, ""):
        uem["event.original"] = raw_event.get("message", "") or str(raw_event)
    if "host.name" not in uem or uem.get("host.name") in (None, ""):
        uem["host.name"] = raw_event.get("source", "") or raw_event.get("log_source", "") or ""
    if "log_source" not in uem or uem.get("log_source") in (None, ""):
        uem["log_source"] = raw_event.get("source", "") or raw_event.get("log_source", "") or ""
    return uem


def apply_rules(rules: List[NormalizerRule], raw_event: Dict[str, Any]) -> Dict[str, Any] | None:
    enriched_event = _enrich_raw_event(raw_event)
    for rule in rules:
        if not _source_type_matches(rule, enriched_event):
            continue
        if not _matcher_matches(rule, enriched_event):
            continue
        return _build_uem(rule, enriched_event)

    if enriched_event.get("event.provider") or enriched_event.get("event.category"):
        return _build_uem(None, enriched_event)
    return None
